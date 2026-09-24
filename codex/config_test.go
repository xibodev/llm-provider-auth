package codex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEmptyEndpointsUseCanonicalOpenAIURLs(t *testing.T) {
	t.Parallel()
	// Consumers compile against these values, so pin them literally.
	for got, want := range map[string]string{
		UserCodeURL:      "https://auth.openai.com/api/accounts/deviceauth/usercode",
		DeviceTokenURL:   "https://auth.openai.com/api/accounts/deviceauth/token",
		OAuthTokenURL:    "https://auth.openai.com/oauth/token",
		RevokeURL:        "https://auth.openai.com/oauth/revoke",
		ResponsesBaseURL: "https://chatgpt.com/backend-api/codex",
		ModelsURL:        "https://chatgpt.com/backend-api/codex/models",
	} {
		if got != want {
			t.Errorf("constant=%q, want %q", got, want)
		}
	}

	// The transport answers in memory, so no request leaves the process.
	responses := map[string]string{
		UserCodeURL:    `{"device_auth_id":"device-1","user_code":"CODE-1"}`,
		DeviceTokenURL: `{"authorization_code":"fixture-code","code_verifier":"fixture-verifier"}`,
		OAuthTokenURL:  `{"access_token":"fixture-access","refresh_token":"fixture-refresh"}`,
		RevokeURL:      `{}`,
	}
	var mu sync.Mutex
	var requested []string
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		requested = append(requested, r.Method+" "+r.URL.String())
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(responses[r.URL.String()])), Request: r,
		}, nil
	})}
	config := Config{ClientID: "fixture-client", HTTPClient: client}
	ctx := context.Background()
	flow, err := config.StartDeviceFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status, _, err := config.PollAndExchange(ctx, flow); err != nil || status != "authorized" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	if _, err := config.Refresh(ctx, "fixture-refresh"); err != nil {
		t.Fatal(err)
	}
	if err := config.Revoke(ctx, "fixture-refresh", ""); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST " + UserCodeURL, "POST " + DeviceTokenURL, "POST " + OAuthTokenURL, "POST " + OAuthTokenURL, "POST " + RevokeURL}
	if !reflect.DeepEqual(requested, want) {
		t.Fatalf("requested=%v, want %v", requested, want)
	}
}

func TestEndpointFieldsFallBackIndependently(t *testing.T) {
	t.Parallel()
	got := Config{Endpoints: Endpoints{DeviceTokenURL: "https://device.example.test", RevokeURL: " "}}.endpoints()
	want := Endpoints{UserCodeURL: UserCodeURL, DeviceTokenURL: "https://device.example.test", OAuthTokenURL: OAuthTokenURL, RevokeURL: RevokeURL}
	if got != want {
		t.Fatalf("endpoints=%+v, want %+v", got, want)
	}
}

func TestBlankClientIDFailsBeforeAnyRequest(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	config := fixtureConfig(server, " ")
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"start": func() error { _, err := config.StartDeviceFlow(ctx); return err },
		"poll": func() error {
			status, _, err := config.PollAndExchange(ctx, DeviceFlow{DeviceAuthID: "device", UserCode: "code"})
			if status != "error" {
				t.Errorf("poll status=%q", status)
			}
			return err
		},
		"exchange": func() error { _, err := config.ExchangeAuthorizationCode(ctx, "code", "verifier"); return err },
		"refresh":  func() error { _, err := config.Refresh(ctx, "fixture-refresh"); return err },
		"revoke":   func() error { return config.Revoke(ctx, "fixture-refresh", "") },
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "client ID is required") {
			t.Errorf("%s error=%v", name, err)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests=%d, want none", got)
	}
	if err := config.Revoke(ctx, "", "fixture-access"); err != nil || requests.Load() != 1 {
		t.Fatalf("access-token revoke err=%v requests=%d: it sends no client ID", err, requests.Load())
	}
}

func TestPollAndExchangeUsesTheClientThatStartedTheFlow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, flowClient, configClient, want string }{
		{"flow client wins", "flow-client", "config-client", "flow-client"},
		{"config client fills a bare flow", "", "config-client", "config-client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var exchanged atomic.Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/device-token":
					body := map[string]string{}
					_ = json.NewDecoder(r.Body).Decode(&body)
					if len(body) != 2 {
						t.Errorf("device-token body=%+v: the poll sends no client ID", body)
					}
					_, _ = w.Write([]byte(`{"authorization_code":"fixture-code","code_verifier":"fixture-verifier"}`))
				case "/oauth-token":
					raw, _ := io.ReadAll(r.Body)
					form, _ := url.ParseQuery(string(raw))
					exchanged.Store(form.Get("client_id"))
					_, _ = w.Write([]byte(`{"access_token":"fixture-access"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			flow := DeviceFlow{DeviceAuthID: "device", UserCode: "code", ClientID: tc.flowClient}
			status, _, err := fixtureConfig(server, tc.configClient).PollAndExchange(context.Background(), flow)
			if err != nil || status != "authorized" || exchanged.Load() != tc.want {
				t.Fatalf("status=%q err=%v exchanged with %v, want %q", status, err, exchanged.Load(), tc.want)
			}
		})
	}
}

func TestCanceledContextStopsRequests(t *testing.T) {
	t.Parallel()
	for name, call := range map[string]func(context.Context, Config) error{
		"start": func(ctx context.Context, c Config) error { _, err := c.StartDeviceFlow(ctx); return err },
		"poll": func(ctx context.Context, c Config) error {
			status, _, err := c.PollAndExchange(ctx, DeviceFlow{DeviceAuthID: "device", UserCode: "code"})
			if status != "error" {
				return fmt.Errorf("status=%q, want error", status)
			}
			return err
		},
		"exchange": func(ctx context.Context, c Config) error {
			_, err := c.ExchangeAuthorizationCode(ctx, "code", "verifier")
			return err
		},
		"refresh": func(ctx context.Context, c Config) error { _, err := c.Refresh(ctx, "fixture-refresh"); return err },
		"revoke":  func(ctx context.Context, c Config) error { return c.Revoke(ctx, "fixture-refresh", "") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			arrived := make(chan struct{}, 1)
			release := make(chan struct{})
			// The server never answers on its own: only the canceled context
			// can end the call. release lets Close finish on a failure.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case arrived <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- call(ctx, fixtureConfig(server, "fixture-client")) }()
			select {
			case <-arrived:
			case <-time.After(10 * time.Second):
				t.Fatal("request never reached the server")
			}
			cancel()
			select {
			case err := <-result:
				authErr := &AuthError{}
				if !errors.As(err, &authErr) || authErr.Code != "transport" || authErr.StatusCode != 0 {
					t.Fatalf("error=%v authError=%+v, want a transport AuthError", err, authErr)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("canceling the context did not stop the request")
			}
		})
	}
}

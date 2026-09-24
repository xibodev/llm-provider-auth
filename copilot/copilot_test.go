package copilot

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func endpointsFor(server *httptest.Server) Endpoints {
	return Endpoints{
		DeviceCodeURL:   server.URL + "/device",
		AccessTokenURL:  server.URL + "/access",
		SessionTokenURL: server.URL + "/session",
	}
}

// sessionServer issues a distinct session token per exchange and counts the
// exchanges, so tests can tell a cache hit from a new exchange.
func sessionServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	exchanges := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"session-%d","expires_at":%d,"endpoints":{"api":"https://copilot.example.test/"}}`,
			n, time.Now().Add(time.Hour).Unix())
	}))
	t.Cleanup(server.Close)
	return server, exchanges
}

func TestBYOCSessionCachePathsAreIsolated(t *testing.T) {
	t.Parallel()
	config := Config{CacheDir: t.TempDir()}
	first := config.oauthSessionPath("oauth-token-one")
	second := config.oauthSessionPath("oauth-token-two")
	if first == second {
		t.Fatal("different OAuth credentials share a session cache path")
	}
	if filepath.Base(first) == sessionCacheFile || filepath.Base(second) == sessionCacheFile {
		t.Fatal("BYOC cache reused the global session filename")
	}
}

func TestSyntheticDeviceFlowPreservesSuccessAndSanitizesDenial(t *testing.T) {
	t.Parallel()
	secret := "llmgw_" + strings.Repeat("b", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device":
			_, _ = w.Write([]byte(`{"device_code":"device-secret","user_code":"ABCD-EFGH","verification_uri":"https://github.example.test/device","interval":7,"expires_in":600}`))
		case "/access":
			_, _ = fmt.Fprintf(w, `{"error":"Bearer evil owner@example.test api_key=%s %s"}`, secret, strings.Repeat("q", 700))
		}
	}))
	defer server.Close()
	client := New(Config{Endpoints: endpointsFor(server)})
	flow, err := client.StartDeviceFlow()
	if err != nil || flow.DeviceCode != "device-secret" || flow.UserCode != "ABCD-EFGH" || flow.VerificationURI != "https://github.example.test/device" || flow.Interval != 7 || flow.ExpiresIn != 600 {
		t.Fatalf("flow=%+v err=%v", flow, err)
	}
	result := client.PollDeviceFlowTokenOnce(flow.DeviceCode)
	if result.Status != "denied" || result.AccessToken != "" || len([]rune(result.Error)) > maxAuthDiagnosticChars || strings.Contains(result.Error, secret) || strings.Contains(result.Error, "evil") || strings.Contains(result.Error, "owner@example.test") {
		t.Fatalf("unsafe denial result: %+v", result)
	}
}

func TestSyntheticDevicePollPreservesSemanticStatusesAndToken(t *testing.T) {
	t.Parallel()
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch polls.Add(1) {
		case 1:
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
		case 2:
			_, _ = w.Write([]byte(`{"error":"slow_down"}`))
		default:
			_, _ = w.Write([]byte(`{"access_token":"synthetic-internal-token"}`))
		}
	}))
	defer server.Close()
	client := New(Config{Endpoints: Endpoints{AccessTokenURL: server.URL}})

	for _, want := range []string{"pending", "slow_down", "authorized"} {
		result := client.PollDeviceFlowTokenOnce("synthetic-device")
		if result.Status != want {
			t.Fatalf("poll %d status=%q want=%q", polls.Load(), result.Status, want)
		}
		if want == "authorized" && result.AccessToken != "synthetic-internal-token" {
			t.Fatalf("authorized token=%q", result.AccessToken)
		}
	}
}

func TestSyntheticSessionStatusIsInspectable(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	_, err := Config{Endpoints: endpointsFor(server)}.exchangeOAuthForSession("synthetic-oauth")
	authErr := &AuthError{}
	if !errors.As(err, &authErr) || authErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("error=%v authError=%+v", err, authErr)
	}
}

func TestSyntheticTransportDiagnosticsAreSanitized(t *testing.T) {
	t.Parallel()
	config := Config{Endpoints: Endpoints{
		SessionTokenURL: "http://127.0.0.1:1/session?access_token=query-secret&owner=owner@example.test",
	}}
	_, err := config.exchangeOAuthForSession("synthetic-oauth")
	authErr := &AuthError{}
	if err == nil || !errors.As(err, &authErr) || !authErr.Transport || strings.Contains(err.Error(), "query-secret") || strings.Contains(err.Error(), "owner@example.test") || len([]rune(err.Error())) > maxAuthDiagnosticChars {
		t.Fatalf("unsafe transport error: %v", err)
	}
}

func TestConfiguredTokenPrecedesCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	Config{CacheDir: dir}.persistOAuthToken("cached-token")

	token, err := New(Config{CacheDir: dir, OAuthToken: " configured-token "}).ResolveOAuthToken()
	if err != nil || token != "configured-token" {
		t.Fatalf("configured token=%q err=%v", token, err)
	}
	token, err = New(Config{CacheDir: dir}).ResolveOAuthToken()
	if err != nil || token != "cached-token" {
		t.Fatalf("cached token=%q err=%v", token, err)
	}
}

func TestMissingTokenAndDisabledProxyAreTypedErrors(t *testing.T) {
	t.Parallel()
	client := New(Config{CacheDir: t.TempDir()})
	if _, err := client.ResolveOAuthToken(); !errors.Is(err, ErrNoOAuthToken) {
		t.Fatalf("ResolveOAuthToken error=%v, want ErrNoOAuthToken", err)
	}
	if _, err := client.GetSession(false); !errors.Is(err, ErrNoOAuthToken) {
		t.Fatalf("GetSession error=%v, want ErrNoOAuthToken", err)
	}
	if err := client.AssertProxyAllowed(); !errors.Is(err, ErrProxyDisabled) {
		t.Fatalf("AssertProxyAllowed error=%v, want ErrProxyDisabled", err)
	}
	if err := New(Config{AllowProxy: true}).AssertProxyAllowed(); err != nil {
		t.Fatalf("enabled proxy refused: %v", err)
	}
}

func TestRejectedOAuthTokenIsTyped(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := New(Config{Endpoints: endpointsFor(server)}).GetSessionForOAuth("synthetic-oauth", false)
	authErr := &AuthError{}
	if !errors.Is(err, ErrOAuthTokenRejected) || !errors.As(err, &authErr) || authErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error=%v authError=%+v", err, authErr)
	}
}

// TestLibraryIgnoresEnvironment pins that the package reads no environment:
// the variables it once honoured change nothing.
func TestLibraryIgnoresEnvironment(t *testing.T) {
	// Sequential on purpose: t.Setenv is not allowed in parallel tests.
	environmentCache := t.TempDir()
	Config{CacheDir: environmentCache}.persistOAuthToken("environment-cached-token")
	t.Setenv("LLMGW_GITHUB_COPILOT_CACHE_DIR", environmentCache)
	t.Setenv("GITHUB_COPILOT_OAUTH_TOKEN", "environment-token")
	t.Setenv("LLMGW_GITHUB_COPILOT_OAUTH_TOKEN", "environment-token")
	t.Setenv("LLMGW_EXPERIMENTAL_COPILOT_PROVIDER", "1")

	client := New(Config{})
	if token, err := client.ResolveOAuthToken(); !errors.Is(err, ErrNoOAuthToken) {
		t.Fatalf("token=%q err=%v: an environment variable supplied a token", token, err)
	}
	if err := client.AssertProxyAllowed(); !errors.Is(err, ErrProxyDisabled) {
		t.Fatalf("error=%v: an environment variable enabled the proxy", err)
	}
	if dir := client.AuthStatus()["cache_dir"]; dir != "" {
		t.Fatalf("cache_dir=%v: an environment variable chose the cache", dir)
	}
}

func TestSessionCacheIsOwnedByConfiguration(t *testing.T) {
	t.Parallel()
	server, exchanges := sessionServer(t)
	first := New(Config{CacheDir: t.TempDir(), Endpoints: endpointsFor(server)})
	second := New(Config{CacheDir: t.TempDir(), Endpoints: endpointsFor(server)})

	initial, err := first.GetSessionForOAuth("shared-oauth", false)
	if err != nil {
		t.Fatal(err)
	}
	if initial.ChatBaseURL != "https://copilot.example.test" {
		t.Fatalf("chat base=%q", initial.ChatBaseURL)
	}
	cached, err := first.GetSessionForOAuth("shared-oauth", false)
	if err != nil || cached.Token != initial.Token || exchanges.Load() != 1 {
		t.Fatalf("cached=%+v err=%v exchanges=%d: want a cache hit", cached, err, exchanges.Load())
	}
	if _, err := second.GetSessionForOAuth("shared-oauth", false); err != nil || exchanges.Load() != 2 {
		t.Fatalf("err=%v exchanges=%d: another cache directory must not share sessions", err, exchanges.Load())
	}
	forced, err := first.GetSessionForOAuth("shared-oauth", true)
	if err != nil || forced.Token == initial.Token || exchanges.Load() != 3 {
		t.Fatalf("forced=%+v err=%v exchanges=%d: want a new exchange", forced, err, exchanges.Load())
	}
}

func TestEmptyCacheDirTouchesNoDisk(t *testing.T) {
	t.Parallel()
	server, exchanges := sessionServer(t)
	client := New(Config{OAuthToken: "configured-token", Endpoints: endpointsFor(server)})
	for i := 0; i < 2; i++ {
		if _, err := client.GetSession(false); err != nil {
			t.Fatal(err)
		}
	}
	if got := exchanges.Load(); got != 2 {
		t.Fatalf("exchanges=%d, want 2: nothing may be cached without a cache directory", got)
	}
	if matches, _ := filepath.Glob("github_copilot_*.json"); len(matches) != 0 {
		t.Fatalf("cache files written to the working directory: %v", matches)
	}
	if removed := client.ClearCachedCredentials(); removed["oauth"] || removed["session"] {
		t.Fatalf("removed=%v without a cache directory", removed)
	}
	if result := client.PollDeviceFlowOnce("device"); result["status"] != "error" || exchanges.Load() != 2 {
		t.Fatalf("result=%v exchanges=%d: an unstorable device poll must not run", result, exchanges.Load())
	}
}

func TestPollDeviceFlowOncePersistsIntoCacheDir(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"device-oauth-token"}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	client := New(Config{CacheDir: dir, Endpoints: endpointsFor(server)})

	result := client.PollDeviceFlowOnce("device")
	if result["status"] != "authorized" || len(result) != 1 {
		t.Fatalf("result=%v: want a secret-free authorized envelope", result)
	}
	if token, err := client.ResolveOAuthToken(); err != nil || token != "device-oauth-token" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	status := client.AuthStatus()
	if status["active_source"] != "cache" || status["cache_present"] != true || status["cache_dir"] != dir {
		t.Fatalf("status=%v", status)
	}
	if removed := client.ClearCachedCredentials(); !removed["oauth"] {
		t.Fatalf("removed=%v", removed)
	}
	if _, err := client.ResolveOAuthToken(); !errors.Is(err, ErrNoOAuthToken) {
		t.Fatalf("error=%v after clearing the cache", err)
	}
}

func TestDynamicClientReadsSettingsPerOperation(t *testing.T) {
	t.Parallel()
	var allow atomic.Bool
	client := NewDynamic(func() Config { return Config{AllowProxy: allow.Load()} })
	if err := client.AssertProxyAllowed(); !errors.Is(err, ErrProxyDisabled) {
		t.Fatalf("error=%v, want ErrProxyDisabled", err)
	}
	allow.Store(true)
	if err := client.AssertProxyAllowed(); err != nil {
		t.Fatalf("updated settings ignored: %v", err)
	}
	if err := NewDynamic(nil).AssertProxyAllowed(); !errors.Is(err, ErrProxyDisabled) {
		t.Fatalf("nil settings error=%v, want the zero Config", err)
	}
}

func TestEditorIdentityDefaultsAndOverrides(t *testing.T) {
	t.Parallel()
	var headers atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers.Store(r.Header.Clone())
		_, _ = fmt.Fprintf(w, `{"token":"session","expires_at":%d}`, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()

	for _, tc := range []struct {
		config        Config
		editor, agent string
	}{
		{Config{}, DefaultEditorVersion, "GithubCopilot/" + DefaultEditorPluginVersion},
		{Config{EditorVersion: "vscode/9.9.9", EditorPluginVersion: "product/2.0"}, "vscode/9.9.9", "GithubCopilot/product/2.0"},
	} {
		tc.config.Endpoints = endpointsFor(server)
		if _, err := New(tc.config).GetSessionForOAuth("synthetic-oauth", true); err != nil {
			t.Fatal(err)
		}
		got, _ := headers.Load().(http.Header)
		if got.Get("Editor-Version") != tc.editor || got.Get("User-Agent") != tc.agent || got.Get("Authorization") != "token synthetic-oauth" {
			t.Fatalf("headers=%v, want editor %q and agent %q", got, tc.editor, tc.agent)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConfiguredHTTPClientPerformsRequests(t *testing.T) {
	t.Parallel()
	var used atomic.Bool
	client := New(Config{HTTPClient: &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		used.Store(true)
		body := fmt.Sprintf(`{"token":"session","expires_at":%d}`, time.Now().Add(time.Hour).Unix())
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	})}})
	session, err := client.GetSessionForOAuth("synthetic-oauth", true)
	if err != nil || session.Token != "session" || !used.Load() {
		t.Fatalf("session=%+v err=%v used=%v", session, err, used.Load())
	}
}

func TestConcurrentPollsOfOneDeviceCodeSerialize(t *testing.T) {
	t.Parallel()
	var inFlight, peak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := inFlight.Add(1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
	}))
	defer server.Close()
	client := New(Config{Endpoints: Endpoints{AccessTokenURL: server.URL}})

	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			client.PollDeviceFlowTokenOnce("same-device")
		}()
	}
	group.Wait()
	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent polls=%d, want 1", got)
	}
}

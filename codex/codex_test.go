package codex

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// fixtureConfig points every OAuth endpoint at one test server, so each test
// owns its configuration and tests run in parallel.
func fixtureConfig(server *httptest.Server, clientID string) Config {
	return Config{
		ClientID: clientID,
		Endpoints: Endpoints{
			UserCodeURL:    server.URL + "/usercode",
			DeviceTokenURL: server.URL + "/device-token",
			OAuthTokenURL:  server.URL + "/oauth-token",
			RevokeURL:      server.URL + "/oauth-revoke",
		},
		HTTPClient: server.Client(),
	}
}

func TestOfficialDeviceFlowUsesJSONPollsPendingAndExchangesPollReturnedPKCE(t *testing.T) {
	t.Parallel()
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/usercode":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("usercode request=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
			}
			body := map[string]string{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["client_id"] != "fixture-client" || len(body) != 1 {
				t.Fatalf("usercode body=%+v", body)
			}
			_, _ = w.Write([]byte(`{"device_auth_id":"device-1","usercode":"CODE-123","interval":"3","expires_in":60}`))
		case "/device-token":
			body := map[string]string{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["device_auth_id"] != "device-1" || body["user_code"] != "CODE-123" || len(body) != 2 {
				t.Fatalf("device-token body=%+v", body)
			}
			poll := polls.Add(1)
			if poll == 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if poll == 2 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"authorization_code":"authorization-code","code_challenge":"server-challenge","code_verifier":"server-verifier"}`))
		case "/oauth-token":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Fatalf("exchange request=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
			}
			raw := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(raw)
			form, _ := url.ParseQuery(string(raw))
			if form.Get("grant_type") != "authorization_code" || form.Get("client_id") != "fixture-client" || form.Get("code") != "authorization-code" || form.Get("code_verifier") != "server-verifier" || form.Get("redirect_uri") != DeviceAuthRedirectURI || len(form) != 5 {
				t.Fatalf("device PKCE exchange form=%v", form)
			}
			_, _ = w.Write([]byte(`{"access_token":"fixture-access","refresh_token":"fixture-refresh","id_token":"fixture-id","expires_in":120,"account_id":"account-1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	config := fixtureConfig(server, "fixture-client")

	flow, err := config.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if flow.DeviceAuthID != "device-1" || flow.UserCode != "CODE-123" || flow.VerificationURI != DeviceVerificationURL || flow.Interval != 3 {
		t.Fatalf("flow=%+v", flow)
	}
	for _, want := range []string{"pending", "pending", "authorized"} {
		status, tokens, err := config.PollAndExchange(context.Background(), flow)
		if err != nil || status != want {
			t.Fatalf("poll=%s tokens=%+v err=%v want=%s", status, tokens, err, want)
		}
		if want == "authorized" && (tokens.AccessToken != "fixture-access" || tokens.RefreshToken != "fixture-refresh" || tokens.AccountID != "account-1") {
			t.Fatalf("tokens=%+v", tokens)
		}
	}
}

func TestSyntheticDeviceDenialCodeIsSanitizedAndInspectable(t *testing.T) {
	t.Parallel()
	secret := "llmgw_" + strings.Repeat("c", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"Bearer malicious owner@example.test api_key=%s %s"}`, secret, strings.Repeat("x", 700))
	}))
	defer server.Close()
	config := fixtureConfig(server, "synthetic-client")
	status, _, err := config.PollAndExchange(context.Background(), DeviceFlow{DeviceAuthID: "device", UserCode: "code"})
	authErr := &AuthError{}
	if status != "denied" || !errors.As(err, &authErr) || authErr.StatusCode != http.StatusBadRequest || len([]rune(authErr.Code)) > maxAuthDiagnosticChars || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "malicious") || strings.Contains(err.Error(), "owner@example.test") {
		t.Fatalf("status=%q error=%v authError=%+v", status, err, authErr)
	}
}

func TestSyntheticRefreshDescriptionIsSanitizedAndCodePreserved(t *testing.T) {
	t.Parallel()
	secret := "llmgw_" + strings.Repeat("d", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"Bearer malicious owner@example.test api_key=%s %s"}`, secret, strings.Repeat("y", 700))
	}))
	defer server.Close()
	_, err := fixtureConfig(server, "synthetic-client").Refresh(context.Background(), "synthetic-refresh")
	refreshErr := &RefreshError{}
	if !errors.As(err, &refreshErr) || refreshErr.StatusCode != http.StatusUnauthorized || refreshErr.Code != "invalid_grant" || len([]rune(refreshErr.Description)) > maxAuthDiagnosticChars || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "malicious") || strings.Contains(err.Error(), "owner@example.test") {
		t.Fatalf("error=%v refreshError=%+v", err, refreshErr)
	}
}

func TestTypedErrorFinalMessagesAreSanitizedAndBounded(t *testing.T) {
	t.Parallel()
	secret := "llmgw_" + strings.Repeat("f", 32)
	code := strings.Repeat("c", maxAuthDiagnosticChars-len(secret)) + secret
	description := strings.Repeat("d", maxAuthDiagnosticChars-len("owner@example.test")) + "owner@example.test"
	for name, err := range map[string]error{
		"auth":    &AuthError{Operation: "OAuth token", StatusCode: http.StatusBadGateway, Code: code, Description: description},
		"refresh": &RefreshError{StatusCode: http.StatusUnauthorized, Code: code, Description: description},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			message := err.Error()
			if len([]rune(message)) > maxAuthDiagnosticChars || strings.Contains(message, secret) || strings.Contains(message, "owner@example.test") {
				t.Fatalf("unsafe or unbounded final error: %q", message)
			}
		})
	}
}

func TestSyntheticTransportQueryIsSanitized(t *testing.T) {
	t.Parallel()
	config := Config{
		ClientID:   "synthetic-client",
		Endpoints:  Endpoints{RevokeURL: "http://127.0.0.1:1/revoke?access_token=query-secret&owner=owner@example.test"},
		HTTPClient: &http.Client{},
	}
	err := config.Revoke(context.Background(), "synthetic-refresh", "")
	authErr := &AuthError{}
	if err == nil || !errors.As(err, &authErr) || authErr.StatusCode != 0 || authErr.Code != "transport" || strings.Contains(err.Error(), "query-secret") || strings.Contains(err.Error(), "owner@example.test") || len([]rune(err.Error())) > maxAuthDiagnosticChars {
		t.Fatalf("unsafe transport error: %v", err)
	}
}

func TestRefreshReturnsTypedInvalidReusedAndExpiredErrors(t *testing.T) {
	t.Parallel()
	cases := []string{"invalid_grant", "refresh_token_reused", "expired_token"}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
					t.Fatalf("refresh request=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
				}
				body := map[string]string{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["client_id"] != "fixture-client" || body["grant_type"] != "refresh_token" || body["refresh_token"] != "fixture-refresh" || len(body) != 3 {
					t.Fatalf("refresh body=%+v", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"fixture failure"}`))
			}))
			defer server.Close()
			_, err := fixtureConfig(server, "fixture-client").Refresh(context.Background(), "fixture-refresh")
			refreshError := &RefreshError{}
			if err == nil || !asRefreshError(err, refreshError) || refreshError.StatusCode != http.StatusBadRequest || refreshError.Code != code {
				t.Fatalf("refresh err=%v status=%d code=%q", err, refreshError.StatusCode, refreshError.Code)
			}
		})
	}
}

func TestRefreshDerivesExpiryFromAccessTokenJWT(t *testing.T) {
	t.Parallel()
	accessToken := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1900000000}`)) + ".signature"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + accessToken + `","refresh_token":"new-refresh"}`))
	}))
	defer server.Close()

	tokens, err := fixtureConfig(server, "fixture-client").Refresh(context.Background(), "fixture-refresh")
	if err != nil || tokens.ExpiresAt != 1900000000 {
		t.Fatalf("tokens=%+v err=%v", tokens, err)
	}
}

func TestRefreshAndRevokeUseOfficialJSONAndIDTokenClaims(t *testing.T) {
	t.Parallel()
	idToken := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"email":"fixture@example.test","https://api.openai.com/auth":{"chatgpt_account_id":"workspace-42"}}`)) + ".signature"
	var revocations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			body := map[string]string{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if r.Header.Get("Content-Type") != "application/json" || body["client_id"] != "fixture-client" || body["grant_type"] != "refresh_token" || body["refresh_token"] != "fixture-refresh" || len(body) != 3 {
				t.Fatalf("refresh body=%+v", body)
			}
			_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","id_token":"` + idToken + `"}`))
		case "/oauth/revoke":
			revocation := revocations.Add(1)
			body := map[string]string{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if r.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("revoke content-type=%q", r.Header.Get("Content-Type"))
			}
			if revocation == 1 && (body["token"] != "fixture-refresh" || body["token_type_hint"] != "refresh_token" || body["client_id"] != "fixture-client" || len(body) != 3) {
				t.Fatalf("refresh revoke body=%+v", body)
			}
			if revocation == 2 && (body["token"] != "fixture-access" || body["token_type_hint"] != "access_token" || body["client_id"] != "" || len(body) != 2) {
				t.Fatalf("access revoke body=%+v", body)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	config := Config{
		ClientID:   "fixture-client",
		Endpoints:  Endpoints{OAuthTokenURL: server.URL + "/oauth/token", RevokeURL: server.URL + "/oauth/revoke"},
		HTTPClient: server.Client(),
	}

	tokens, err := config.Refresh(context.Background(), "fixture-refresh")
	if err != nil || tokens.AccessToken != "new-access" || tokens.AccountID != "workspace-42" || tokens.AccountLabel != "fixture@example.test" {
		t.Fatalf("tokens=%+v err=%v", tokens, err)
	}
	if err := config.Revoke(context.Background(), "fixture-refresh", "fixture-access"); err != nil {
		t.Fatal(err)
	}
	if err := config.Revoke(context.Background(), "", "fixture-access"); err != nil {
		t.Fatal(err)
	}
	if got := revocations.Load(); got != 2 {
		t.Fatalf("revocations=%d", got)
	}
}

func asRefreshError(err error, target *RefreshError) bool {
	value, ok := err.(*RefreshError)
	if !ok {
		return false
	}
	*target = *value
	return true
}

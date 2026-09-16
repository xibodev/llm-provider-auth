package copilot

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestBYOCSessionCachePathsAreIsolated(t *testing.T) {
	t.Setenv("LLMGW_GITHUB_COPILOT_CACHE_DIR", t.TempDir())
	first := sessionCachePathForOAuth("oauth-token-one")
	second := sessionCachePathForOAuth("oauth-token-two")
	if first == second {
		t.Fatal("different OAuth credentials share a session cache path")
	}
	if filepath.Base(first) == sessionCacheFile || filepath.Base(second) == sessionCacheFile {
		t.Fatal("BYOC cache reused the global session filename")
	}
}

func withCopilotEndpoints(t *testing.T, server *httptest.Server) {
	t.Helper()
	oldDevice, oldAccess, oldSession := DeviceCodeURL, AccessTokenURL, SessionTokenURL
	DeviceCodeURL, AccessTokenURL, SessionTokenURL = server.URL+"/device", server.URL+"/access", server.URL+"/session"
	t.Cleanup(func() { DeviceCodeURL, AccessTokenURL, SessionTokenURL = oldDevice, oldAccess, oldSession })
}

func TestSyntheticDeviceFlowPreservesSuccessAndSanitizesDenial(t *testing.T) {
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
	withCopilotEndpoints(t, server)
	flow, err := StartDeviceFlow()
	if err != nil || flow.DeviceCode != "device-secret" || flow.UserCode != "ABCD-EFGH" || flow.VerificationURI != "https://github.example.test/device" || flow.Interval != 7 || flow.ExpiresIn != 600 {
		t.Fatalf("flow=%+v err=%v", flow, err)
	}
	result := PollDeviceFlowTokenOnce(flow.DeviceCode)
	if result.Status != "denied" || result.AccessToken != "" || len([]rune(result.Error)) > maxAuthDiagnosticChars || strings.Contains(result.Error, secret) || strings.Contains(result.Error, "evil") || strings.Contains(result.Error, "owner@example.test") {
		t.Fatalf("unsafe denial result: %+v", result)
	}
}

func TestSyntheticDevicePollPreservesSemanticStatusesAndToken(t *testing.T) {
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		polls++
		switch polls {
		case 1:
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
		case 2:
			_, _ = w.Write([]byte(`{"error":"slow_down"}`))
		default:
			_, _ = w.Write([]byte(`{"access_token":"synthetic-internal-token"}`))
		}
	}))
	defer server.Close()
	old := AccessTokenURL
	AccessTokenURL = server.URL
	t.Cleanup(func() { AccessTokenURL = old })

	for _, want := range []string{"pending", "slow_down", "authorized"} {
		result := PollDeviceFlowTokenOnce("synthetic-device")
		if result.Status != want {
			t.Fatalf("poll %d status=%q want=%q", polls, result.Status, want)
		}
		if want == "authorized" && result.AccessToken != "synthetic-internal-token" {
			t.Fatalf("authorized token=%q", result.AccessToken)
		}
	}
}

func TestSyntheticSessionStatusIsInspectable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	withCopilotEndpoints(t, server)
	_, err := exchangeOAuthForSession("synthetic-oauth")
	authErr := &AuthError{}
	if !errors.As(err, &authErr) || authErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("error=%v authError=%+v", err, authErr)
	}
}

func TestSyntheticTransportDiagnosticsAreSanitized(t *testing.T) {
	oldURL := SessionTokenURL
	SessionTokenURL = "http://127.0.0.1:1/session?access_token=query-secret&owner=owner@example.test"
	t.Cleanup(func() { SessionTokenURL = oldURL })
	_, err := exchangeOAuthForSession("synthetic-oauth")
	authErr := &AuthError{}
	if err == nil || !errors.As(err, &authErr) || !authErr.Transport || strings.Contains(err.Error(), "query-secret") || strings.Contains(err.Error(), "owner@example.test") || len([]rune(err.Error())) > maxAuthDiagnosticChars {
		t.Fatalf("unsafe transport error: %v", err)
	}
}

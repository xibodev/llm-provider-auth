package gcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestKey generates a throwaway RSA key. No real credential is used in these
// tests; every fixture below is synthesised in-process.
func newTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func testKeyJSON(t *testing.T, tokenURI string) (string, *rsa.PrivateKey) {
	t.Helper()
	key, pemText := newTestKey(t)
	doc := map[string]string{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "key-1",
		"private_key":    pemText,
		"client_email":   "svc@test-project.iam.gserviceaccount.com",
		"token_uri":      tokenURI,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(raw), key
}

// verifyRS256 checks the assertion signature the way Google's endpoint would.
func verifyRS256(signingInput, signature string, pub *rsa.PublicKey) error {
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], raw)
}

func TestParseAcceptsServiceAccountKey(t *testing.T) {
	raw, _ := testKeyJSON(t, "")
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cred.ProjectID() != "test-project" {
		t.Fatalf("project = %q, want test-project", cred.ProjectID())
	}
	meta := cred.Metadata()
	if meta.ClientEmail != "svc@test-project.iam.gserviceaccount.com" {
		t.Fatalf("client email = %q", meta.ClientEmail)
	}
	if meta.PrivateKeyID != "key-1" {
		t.Fatalf("key id = %q", meta.PrivateKeyID)
	}
	// An absent token_uri must fall back to Google's endpoint.
	if cred.tokenURI != defaultTokenURI {
		t.Fatalf("tokenURI = %q, want the default", cred.tokenURI)
	}
}

func TestParseRejectsNonServiceAccountShapes(t *testing.T) {
	cases := map[string]string{
		"authorized user": `{"type":"authorized_user","client_id":"x"}`,
		"missing type":    `{"project_id":"p"}`,
		"not json":        `nonsense`,
		"bad pem":         `{"type":"service_account","project_id":"p","client_email":"a@b","private_key":"not-a-pem"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("expected an error for %s", name)
			}
		})
	}
}

func TestParseReportsEveryMissingField(t *testing.T) {
	_, pemText := newTestKey(t)
	raw := fmt.Sprintf(`{"type":"service_account","private_key":%q}`, pemText)
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "client_email") {
		t.Fatalf("error should name client_email, got: %v", err)
	}
	if !strings.Contains(err.Error(), "project_id") {
		t.Fatalf("error should name project_id, got: %v", err)
	}
}

// TestParseErrorsNeverLeakKeyMaterial guards the invariant that key bytes must
// never reach a log line or an API error.
func TestParseErrorsNeverLeakKeyMaterial(t *testing.T) {
	_, pemText := newTestKey(t)
	raw := fmt.Sprintf(`{"type":"authorized_user","private_key":%q}`, pemText)
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("error message leaked the PEM header")
	}
	if strings.Contains(err.Error(), pemText[40:80]) {
		t.Fatal("error message leaked private key bytes")
	}
}

// tokenServer stands in for oauth2.googleapis.com and captures the assertion.
func tokenServer(t *testing.T, status int) (*httptest.Server, *string) {
	t.Helper()
	captured := new(string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*captured = r.Form.Get("assertion")
		if got := r.Form.Get("grant_type"); got != jwtGrantType {
			t.Errorf("grant_type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.test-token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(server.Close)
	return server, captured
}

func TestAccessTokenMintsAVerifiableAssertion(t *testing.T) {
	ResetCache()
	server, captured := tokenServer(t, http.StatusOK)
	raw, key := testKeyJSON(t, server.URL)
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	token, err := AccessToken(cred, CloudPlatformScope)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "ya29.test-token" {
		t.Fatalf("token = %q", token)
	}

	parts := strings.Split(*captured, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d segments, want 3", len(parts))
	}
	if err := verifyRS256(strings.Join(parts[:2], "."), parts[2], &key.PublicKey); err != nil {
		t.Fatalf("assertion signature did not verify: %v", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims["iss"] != "svc@test-project.iam.gserviceaccount.com" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["scope"] != CloudPlatformScope {
		t.Fatalf("scope = %v", claims["scope"])
	}
	if claims["aud"] != server.URL {
		t.Fatalf("aud = %v", claims["aud"])
	}
	if claims["exp"].(float64) <= claims["iat"].(float64) {
		t.Fatal("exp must be after iat")
	}
}

func TestAccessTokenCachesUntilCloseToExpiry(t *testing.T) {
	ResetCache()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"access_token":"ya29.test-token","expires_in":3600}`))
	}))
	defer server.Close()
	raw, _ := testKeyJSON(t, server.URL)
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	base := time.Now()
	now = func() time.Time { return base }
	defer func() { now = time.Now }()

	for i := 0; i < 3; i++ {
		if _, err := AccessToken(cred, CloudPlatformScope); err != nil {
			t.Fatalf("AccessToken: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("minted %d times, want 1 (later calls should hit the cache)", calls)
	}

	// Inside the refresh window the token must be re-minted, not served.
	now = func() time.Time { return base.Add(3600*time.Second - 30*time.Second) }
	if _, err := AccessToken(cred, CloudPlatformScope); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if calls != 2 {
		t.Fatalf("minted %d times, want 2 (early refresh)", calls)
	}
}

func TestAccessTokenSurfacesExchangeFailure(t *testing.T) {
	ResetCache()
	server, _ := tokenServer(t, http.StatusBadRequest)
	raw, _ := testKeyJSON(t, server.URL)
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := AccessToken(cred, CloudPlatformScope); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "Invalid JWT Signature") {
		t.Fatalf("error should carry Google's reason, got: %v", err)
	}
}

func TestAccessTokenSanitizesSyntheticEndpointDiagnostics(t *testing.T) {
	ResetCache()
	secret := "llmgw_" + strings.Repeat("a", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"Bearer malicious-bearer owner@example.test api_key=%s %s"}`, secret, strings.Repeat("z", 700))
	}))
	defer server.Close()
	raw, _ := testKeyJSON(t, server.URL)
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, err = AccessToken(cred, CloudPlatformScope)
	tokenErr := &TokenError{}
	if !errors.As(err, &tokenErr) || tokenErr.StatusCode != http.StatusUnauthorized || tokenErr.Code != "invalid_grant" {
		t.Fatalf("error=%v tokenError=%+v", err, tokenErr)
	}
	if len([]rune(tokenErr.Description)) > maxAuthDiagnosticChars || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "malicious-bearer") || strings.Contains(err.Error(), "owner@example.test") {
		t.Fatalf("unsafe or unbounded error: %q", err)
	}
}

type syntheticRoundTripper func(*http.Request) (*http.Response, error)

func (f syntheticRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAccessTokenSanitizesSyntheticTransportURL(t *testing.T) {
	ResetCache()
	oldClient := httpClient
	httpClient = &http.Client{Transport: syntheticRoundTripper(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial %s?access_token=query-secret for owner@example.test", r.URL)
	})}
	t.Cleanup(func() { httpClient = oldClient })
	raw, _ := testKeyJSON(t, "https://tokens.example.test/exchange")
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, err = AccessToken(cred, CloudPlatformScope)
	tokenErr := &TokenError{}
	if !errors.As(err, &tokenErr) || tokenErr.Code != "transport" || strings.Contains(err.Error(), "query-secret") || strings.Contains(err.Error(), "owner@example.test") {
		t.Fatalf("unsafe transport error: %v", err)
	}
}

func TestTokenErrorFinalMessageIsSanitizedAndBounded(t *testing.T) {
	secret := "llmgw_" + strings.Repeat("e", 32)
	err := &TokenError{
		StatusCode:  http.StatusBadGateway,
		Code:        strings.Repeat("c", maxAuthDiagnosticChars-len(secret)) + secret,
		Description: strings.Repeat("d", maxAuthDiagnosticChars-len("owner@example.test")) + "owner@example.test",
	}
	message := err.Error()
	if len([]rune(message)) > maxAuthDiagnosticChars || strings.Contains(message, secret) || strings.Contains(message, "owner@example.test") {
		t.Fatalf("unsafe or unbounded final error: %q", message)
	}
}

func TestScopesAreCachedSeparately(t *testing.T) {
	ResetCache()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"access_token":"ya29.test-token","expires_in":3600}`))
	}))
	defer server.Close()
	raw, _ := testKeyJSON(t, server.URL)
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if _, err := AccessToken(cred, CloudPlatformScope); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if _, err := AccessToken(cred, "https://www.googleapis.com/auth/devstorage.read_only"); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if calls != 2 {
		t.Fatalf("minted %d times, want 2 (one per scope)", calls)
	}
}

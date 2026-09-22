package antigravity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/xibodev/llm-provider-auth/browseroauth"
)

const fixtureRedirectURI = "http://127.0.0.1:51121/oauth-callback"

func TestAuthorizationURLUsesCanonicalGoogleFlow(t *testing.T) {
	config := Config{ClientID: "fixture-client", ClientSecret: "fixture-secret", ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost, RedirectURI: fixtureRedirectURI}
	authorization, err := config.AuthorizationURL()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(authorization.CodeVerifier))
	query := parsed.Query()
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != AuthorizeURL {
		t.Fatalf("authorization endpoint=%q", parsed.String())
	}
	if query.Get("client_id") != "fixture-client" || query.Get("redirect_uri") != fixtureRedirectURI || query.Get("response_type") != "code" || query.Get("access_type") != "offline" || query.Get("prompt") != "consent" {
		t.Fatalf("authorization query=%v", query)
	}
	if query.Get("scope") != strings.Join(Scopes(), " ") || query.Get("state") != authorization.State || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("OAuth security query=%v authorization=%+v", query, authorization)
	}
}

func TestScopesReturnsCanonicalIndependentCopies(t *testing.T) {
	want := []string{OpenIDScope, CloudPlatformScope, UserinfoEmailScope, UserinfoProfileScope, CloudCodeLogScope, ExperimentsScope}
	first := Scopes()
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("scopes=%v", first)
	}
	first[0] = "changed"
	if reflect.DeepEqual(Scopes(), first) {
		t.Fatal("Scopes returned shared mutable storage")
	}
}

func TestAuthorizationURLAcceptsCallerOwnedCustomRedirectScheme(t *testing.T) {
	config := Config{ClientID: "fixture-client", ClientSecret: "fixture-secret", ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost, RedirectURI: "fixture-app:/oauth/callback"}
	authorization, err := config.AuthorizationURL()
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorization.URL)
	if parsed.Query().Get("redirect_uri") != "fixture-app:/oauth/callback" {
		t.Fatalf("authorization URL=%q", authorization.URL)
	}
}

func TestExchangeUsesCallerConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != "fixture-client" || r.Form.Get("client_secret") != "fixture-secret" || r.Form.Get("code") != "fixture-code" || r.Form.Get("code_verifier") != "fixture-verifier" || r.Form.Get("redirect_uri") != fixtureRedirectURI {
			t.Fatalf("exchange form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"fixture-access","refresh_token":"fixture-refresh","expires_in":3600}`))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	tokens, err := config.Exchange(context.Background(), "fixture-code", "fixture-verifier")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "fixture-access" || tokens.RefreshToken != "fixture-refresh" || tokens.ExpiresIn != 3600 || tokens.ExpiresAt.IsZero() {
		t.Fatalf("tokens=%+v", tokens)
	}
}

func TestCompleteAuthorizationValidatesStateBeforeExchange(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{"access_token":"fixture-access"}`))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	authorization := Authorization{State: "expected-state", CodeVerifier: "fixture-verifier"}
	if _, err := config.CompleteAuthorization(context.Background(), authorization, "wrong-state", "fixture-code"); err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("state error=%v", err)
	}
	if requests != 0 {
		t.Fatalf("token endpoint called before state validation: requests=%d", requests)
	}
	if _, err := config.CompleteAuthorization(context.Background(), authorization, "expected-state", "fixture-code"); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestRefreshPreservesOmittedRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "existing-refresh" || r.Form.Get("client_secret") != "fixture-secret" {
			t.Fatalf("refresh form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"new-access","expires_in":60}`))
	}))
	defer server.Close()
	tokens, err := fixtureConfig(server).Refresh(context.Background(), "existing-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "new-access" || tokens.RefreshToken != "existing-refresh" {
		t.Fatalf("tokens=%+v", tokens)
	}
}

func TestPublicClientExchangeAndRefreshOmitSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Has("client_secret") {
			t.Fatalf("public token form=%v", r.Form)
		}
		if r.Form.Get("grant_type") == "authorization_code" && r.Form.Get("code_verifier") != "fixture-verifier" {
			t.Fatalf("public exchange form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"fixture-access"}`))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	config.ClientAuthMode = browseroauth.ClientAuthModePublicPKCE
	config.ClientSecret = "must-not-be-sent"
	if _, err := config.Exchange(context.Background(), "fixture-code", "fixture-verifier"); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Refresh(context.Background(), "fixture-refresh"); err != nil {
		t.Fatal(err)
	}
}

func TestConfidentialClientRequiresSecret(t *testing.T) {
	config := Config{
		ClientID:       "fixture-client",
		ClientAuthMode: ClientAuthModeClientSecretPost,
		RedirectURI:    fixtureRedirectURI,
	}
	if _, err := config.AuthorizationURL(); err == nil || !strings.Contains(err.Error(), "client secret") {
		t.Fatalf("missing secret error=%v", err)
	}
}

func TestDiscoverAccountReturnsTypedMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/load" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer fixture-access" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		var request struct {
			Metadata struct {
				IDEType string `json:"ideType"`
			} `json:"metadata"`
		}
		if err := jsonNewDecoder(r).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Metadata.IDEType != "ANTIGRAVITY" {
			t.Fatalf("request=%+v", request)
		}
		_, _ = w.Write([]byte(`{"cloudaicompanionProject":" project-1 ","currentTier":{"id":"free-tier","name":"Free","userDefinedCloudaicompanionProject":false,"privacyNotice":{"showNotice":true,"noticeText":"notice"}},"paidTier":{"id":"paid-tier"},"allowedTiers":[{"id":"free-tier"}],"ineligibleTiers":[{"tierId":"other-tier","tierName":"Other","reasonCode":"VALIDATION_REQUIRED","reasonMessage":"not eligible","validationErrorMessage":"validate first","validationUrl":"https://example.test/validate","validationUrlLinkText":"Validate","validationLearnMoreUrl":"https://example.test/learn","validationLearnMoreLinkText":"Learn more"}]}`))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	config.Endpoints.LoadCodeAssistURL = server.URL + "/load"
	account, err := config.DiscoverAccount(context.Background(), "fixture-access")
	if err != nil {
		t.Fatal(err)
	}
	if account.ProjectID != "project-1" || account.CurrentTier == nil || account.CurrentTier.ID != "free-tier" || account.PaidTier == nil || account.PaidTier.ID != "paid-tier" || len(account.AllowedTiers) != 1 || len(account.IneligibleTiers) != 1 {
		t.Fatalf("account=%+v", account)
	}
	if account.CurrentTier.PrivacyNotice == nil || !account.CurrentTier.PrivacyNotice.ShowNotice || account.IneligibleTiers[0].ReasonCode != IneligibilityValidationRequired || account.IneligibleTiers[0].ValidationErrorMessage != "validate first" || account.IneligibleTiers[0].ValidationURLLinkText != "Validate" || account.IneligibleTiers[0].ValidationLearnMoreURL == "" {
		t.Fatalf("decision metadata=%+v", account)
	}
}

func TestDiscoverAccountDoesNotInventProject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"currentTier":{"id":"free-tier"}}`))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	config.Endpoints.LoadCodeAssistURL = server.URL
	account, err := config.DiscoverAccount(context.Background(), "fixture-access")
	if err != nil {
		t.Fatal(err)
	}
	if account.ProjectID != "" {
		t.Fatalf("fallback project=%q", account.ProjectID)
	}
}

func TestDiscoverAccountReloadsIncompleteProjectMetadataWithoutFallback(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var request struct {
			ProjectID string `json:"cloudaicompanionProject"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		switch requests {
		case 1:
			if request.ProjectID != "" {
				t.Fatalf("initial project=%q", request.ProjectID)
			}
			_, _ = w.Write([]byte(`{"cloudaicompanionProject":"initial-project","currentTier":{"id":"free-tier"}}`))
		case 2:
			if request.ProjectID != "initial-project" {
				t.Fatalf("reload project=%q", request.ProjectID)
			}
			_, _ = w.Write([]byte(`{"cloudaicompanionProject":"replacement-project","paidTier":{"id":"paid-tier"}}`))
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()
	config := fixtureConfig(server)
	config.Endpoints.LoadCodeAssistURL = server.URL
	account, err := config.DiscoverAccount(context.Background(), "fixture-access")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || account.ProjectID != "initial-project" || account.CurrentTier == nil || account.CurrentTier.ID != "free-tier" || account.PaidTier == nil || account.PaidTier.ID != "paid-tier" {
		t.Fatalf("requests=%d account=%+v", requests, account)
	}
}

func TestOperationsValidateOnlyTheirConfiguration(t *testing.T) {
	authorization, err := (Config{ClientID: "id", ClientAuthMode: browseroauth.ClientAuthModePublicPKCE, RedirectURI: fixtureRedirectURI, Endpoints: Endpoints{TokenURL: "relative"}}).AuthorizationURL()
	if err != nil || authorization.URL == "" {
		t.Fatalf("authorization=%+v error=%v", authorization, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"access"}`))
	}))
	defer server.Close()
	if _, err := (Config{ClientID: "id", ClientSecret: "secret", ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost, Endpoints: Endpoints{TokenURL: server.URL}, HTTPClient: server.Client()}).Refresh(context.Background(), "refresh"); err != nil {
		t.Fatalf("refresh required unrelated configuration: %v", err)
	}
	if _, err := (Config{Endpoints: Endpoints{LoadCodeAssistURL: server.URL}, HTTPClient: server.Client()}).DiscoverAccount(context.Background(), "access"); err != nil {
		t.Fatalf("discovery required OAuth configuration: %v", err)
	}
}

func TestAuthorizationValidationRejectsMissingCallerConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{name: "client ID", config: Config{ClientSecret: "secret", ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost, RedirectURI: fixtureRedirectURI}, want: "client ID"},
		{name: "redirect URI", config: Config{ClientID: "id", ClientSecret: "secret", ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost, RedirectURI: "relative"}, want: "redirect URI"},
		{name: "authorize endpoint", config: Config{ClientID: "id", ClientSecret: "secret", ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost, RedirectURI: fixtureRedirectURI, Endpoints: Endpoints{AuthorizeURL: "://bad"}}, want: "authorize URL"},
		{name: "client auth mode", config: Config{ClientID: "id", RedirectURI: fixtureRedirectURI}, want: "client auth mode"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.config.AuthorizationURL()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestDiscoverAccountRejectsMissingTokenAndMalformedEndpoint(t *testing.T) {
	config := Config{
		ClientID:       "fixture-client",
		ClientSecret:   "fixture-secret",
		ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost,
		RedirectURI:    fixtureRedirectURI,
		Endpoints:      Endpoints{LoadCodeAssistURL: "relative"},
	}
	if _, err := config.DiscoverAccount(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "access token") {
		t.Fatalf("missing token error=%v", err)
	}
	if _, err := config.DiscoverAccount(context.Background(), "fixture-access"); err == nil || !strings.Contains(err.Error(), "loadCodeAssist URL") {
		t.Fatalf("endpoint error=%v", err)
	}
}

func TestDiscoverAccountRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid JSON", body: `{`},
		{name: "null", body: `null`},
		{name: "wrong field type", body: `{"cloudaicompanionProject":42}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(test.body)) }))
			defer server.Close()
			config := fixtureConfig(server)
			config.Endpoints.LoadCodeAssistURL = server.URL
			_, err := config.DiscoverAccount(context.Background(), "fixture-access")
			apiErr := &APIError{}
			if !errors.As(err, &apiErr) || apiErr.Code != "invalid_response" {
				t.Fatalf("error=%v typed=%+v", err, apiErr)
			}
		})
	}
}

func TestDiscoverAccountErrorsExposeOnlyControlledStatusAndCode(t *testing.T) {
	secret := "sk-" + strings.Repeat("s", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"error":{"status":"PERMISSION_DENIED","message":"Bearer malicious owner@example.test api_key=%s %s"}}`, secret, strings.Repeat("x", 700))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	config.Endpoints.LoadCodeAssistURL = server.URL
	_, err := config.DiscoverAccount(context.Background(), "fixture-access")
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden || apiErr.Code != "PERMISSION_DENIED" || err.Error() != "Antigravity account discovery failed (HTTP 403): PERMISSION_DENIED" || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "owner@example.test") || strings.Contains(err.Error(), "malicious") {
		t.Fatalf("unsafe error=%v typed=%+v", err, apiErr)
	}
}

func TestDiscoverAccountBoundsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", int(maxResponseBytes)+1)))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	config.Endpoints.LoadCodeAssistURL = server.URL
	_, err := config.DiscoverAccount(context.Background(), "fixture-access")
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid_response" {
		t.Fatalf("error=%v typed=%+v", err, apiErr)
	}
}

func TestDiscoverAccountRejectsUncontrolledUpstreamCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"status":"secret owner@example.test","message":"private detail"}}`))
	}))
	defer server.Close()
	config := fixtureConfig(server)
	config.Endpoints.LoadCodeAssistURL = server.URL
	_, err := config.DiscoverAccount(context.Background(), "fixture-access")
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) || apiErr.Code != "http_502" || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsafe error=%v typed=%+v", err, apiErr)
	}
}

func TestTokenEndpointErrorsRemainTypedAndRedacted(t *testing.T) {
	secret := "sk-" + strings.Repeat("z", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"api_key=%s owner@example.test"}`, secret)
	}))
	defer server.Close()
	_, err := fixtureConfig(server).Refresh(context.Background(), "fixture-refresh")
	endpointErr := &browseroauth.EndpointError{}
	if !errors.As(err, &endpointErr) || endpointErr.Code != "invalid_grant" || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "owner@example.test") {
		t.Fatalf("unsafe error=%v typed=%+v", err, endpointErr)
	}
}

func fixtureConfig(server *httptest.Server) Config {
	return Config{
		ClientID:       "fixture-client",
		ClientSecret:   "fixture-secret",
		ClientAuthMode: browseroauth.ClientAuthModeClientSecretPost,
		RedirectURI:    fixtureRedirectURI,
		Endpoints: Endpoints{
			AuthorizeURL:      server.URL + "/authorize",
			TokenURL:          server.URL + "/token",
			LoadCodeAssistURL: server.URL + "/load",
		},
		HTTPClient: server.Client(),
	}
}

func jsonNewDecoder(r *http.Request) *json.Decoder {
	return json.NewDecoder(r.Body)
}

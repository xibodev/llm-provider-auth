package gcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xibodev/llm-provider-auth/internal/sanitize"
)

const maxAuthDiagnosticChars = 512

// TokenError retains safe machine-inspectable token endpoint facts.
type TokenError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	message := "service account token exchange failed"
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.StatusCode)
	}
	if e.Code != "" {
		message += ": " + e.Code
	}
	if e.Description != "" && e.Description != e.Code {
		message += ": " + e.Description
	}
	return sanitize.SanitizeTextLimit(message, maxAuthDiagnosticChars)
}

func tokenError(status int, code, description string) *TokenError {
	return &TokenError{
		StatusCode:  status,
		Code:        sanitize.SanitizeTextLimit(strings.TrimSpace(code), maxAuthDiagnosticChars),
		Description: sanitize.SanitizeTextLimit(strings.TrimSpace(description), maxAuthDiagnosticChars),
	}
}

// defaultExchangeTimeout bounds a token exchange when TokenCache.HTTPClient is
// nil.
const defaultExchangeTimeout = 30 * time.Second

// TokenCache mints access tokens for service-account credentials and caches
// them per credential and scope until shortly before they expire.
//
// Each TokenCache owns its tokens, HTTP client and clock, so separate caches
// share nothing. Tokens are short lived and re-mintable, so they are held in
// memory only: a restart costs one extra exchange, while persisting them would
// put bearer tokens on disk.
//
// The zero value is ready to use and a TokenCache is safe for concurrent use.
// Set its fields before first use, and do not copy it afterwards.
type TokenCache struct {
	// HTTPClient performs the token exchange. Nil uses a client that times out
	// after 30 seconds.
	HTTPClient *http.Client
	// Now returns the current time. Nil uses time.Now.
	Now func() time.Time

	mu      sync.Mutex
	entries map[string]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

func (t *TokenCache) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *TokenCache) client() *http.Client {
	if t.HTTPClient != nil {
		return t.HTTPClient
	}
	return &http.Client{Timeout: defaultExchangeTimeout}
}

// fingerprint identifies a credential and scope without retaining anything
// secret: the key id and client email are metadata, and hashing keeps the cache
// key opaque if it is ever printed.
func fingerprint(c *Credential, scope string) string {
	sum := sha256.Sum256([]byte(c.clientEmail + "|" + c.privateKeyID + "|" + scope))
	return hex.EncodeToString(sum[:8])
}

// AccessToken returns a cached token for the credential and scope, minting a
// new one when none is cached or the cached one is close to expiry. An empty
// scope means CloudPlatformScope.
func (t *TokenCache) AccessToken(c *Credential, scope string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("service account credential is not configured")
	}
	if strings.TrimSpace(scope) == "" {
		scope = CloudPlatformScope
	}
	key := fingerprint(c, scope)

	t.mu.Lock()
	entry, ok := t.entries[key]
	t.mu.Unlock()
	if ok && t.now().Add(refreshBeforeExpiry).Before(entry.expiresAt) {
		return entry.token, nil
	}

	token, expiresAt, err := t.exchange(c, scope)
	if err != nil {
		return "", err
	}
	t.mu.Lock()
	if t.entries == nil {
		t.entries = map[string]cachedToken{}
	}
	t.entries[key] = cachedToken{token: token, expiresAt: expiresAt}
	t.mu.Unlock()
	return token, nil
}

// Reset drops every cached token, for example after a credential is revoked or
// replaced.
func (t *TokenCache) Reset() {
	t.mu.Lock()
	t.entries = nil
	t.mu.Unlock()
}

// signAssertion builds the RS256 JWT that Google exchanges for a token.
func signAssertion(c *Credential, scope string, issued time.Time) (string, error) {
	issued = issued.UTC()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if c.privateKeyID != "" {
		header["kid"] = c.privateKeyID
	}
	claims := map[string]any{
		"iss":   c.clientEmail,
		"scope": scope,
		"aud":   c.tokenURI,
		"iat":   issued.Unix(),
		"exp":   issued.Add(assertionTTL).Unix(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("service account key: signing failed")
	}
	return signingInput + "." + enc.EncodeToString(signature), nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// exchange trades the signed assertion for an access token.
func (t *TokenCache) exchange(c *Credential, scope string) (string, time.Time, error) {
	assertion, err := signAssertion(c, scope, t.now())
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{"grant_type": {jwtGrantType}, "assertion": {assertion}}
	request, err := http.NewRequest(
		http.MethodPost, c.tokenURI, strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", time.Time{}, tokenError(0, "request", err.Error())
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := t.client().Do(request)
	if err != nil {
		return "", time.Time{}, tokenError(0, "transport", err.Error())
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))

	var parsed tokenResponse
	_ = json.Unmarshal(raw, &parsed)
	if response.StatusCode != http.StatusOK {
		detail := parsed.ErrorDesc
		if strings.TrimSpace(detail) == "" {
			detail = "no error detail returned"
		}
		return "", time.Time{}, tokenError(response.StatusCode, parsed.Error, detail)
	}
	if strings.TrimSpace(parsed.AccessToken) == "" {
		return "", time.Time{}, tokenError(response.StatusCode, "invalid_response", "response returned no access_token")
	}
	lifetime := parsed.ExpiresIn
	if lifetime <= 0 {
		lifetime = int64(assertionTTL / time.Second)
	}
	return parsed.AccessToken, t.now().Add(time.Duration(lifetime) * time.Second), nil
}

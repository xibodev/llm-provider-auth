// Package copilot resolves GitHub OAuth tokens for GitHub Copilot, runs the
// GitHub device flow, and exchanges OAuth tokens for Copilot session tokens.
//
// The package reads no environment variables and keeps no process-wide state.
// The caller supplies a Config, and each Client owns what it caches, so a
// product that honours environment variables maps them onto Config itself.
package copilot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xibodev/llm-provider-auth/internal/sanitize"
)

const (
	ClientID = "Iv1.b507a08c87ecfe98"

	// Canonical GitHub endpoints. Config.Endpoints replaces them for tests and
	// compatible deployments.
	DeviceCodeURL   = "https://github.com/login/device/code"
	AccessTokenURL  = "https://github.com/login/oauth/access_token"
	SessionTokenURL = "https://api.github.com/copilot_internal/v2/token"

	// DefaultEditorVersion and DefaultEditorPluginVersion identify the client
	// during the session-token exchange unless Config overrides them.
	DefaultEditorVersion       = "vscode/1.96.2"
	DefaultEditorPluginVersion = "copilot-auth/1.0"

	// DefaultTimeout bounds each request when Config.HTTPClient is nil.
	DefaultTimeout = 60 * time.Second

	defaultChatBase        = "https://api.githubcopilot.com"
	oauthCacheFile         = "github_copilot_oauth.json"
	sessionCacheFile       = "github_copilot_session.json"
	refreshBeforeExpirySec = 60
	maxAuthDiagnosticChars = 512

	TOSWarning = "GitHub Copilot is licensed for code suggestions in editors. Using it as a " +
		"general gateway provider is a personal-use grey area, not a sanctioned public API — " +
		"keep it on your own loopback gateway, do not expose it as a shared/hosted relay, and " +
		"expect the upstream endpoint/headers to change without notice."
)

// Error kinds matched with errors.Is. AuthError messages state only what went
// wrong; a product matches the kind to add guidance that names its own
// settings and sign-in surfaces.
var (
	// ErrProxyDisabled reports that Config.AllowProxy is false.
	ErrProxyDisabled = errors.New("copilot: provider use is not enabled")
	// ErrNoOAuthToken reports that no configured source produced an OAuth token.
	ErrNoOAuthToken = errors.New("copilot: no OAuth token available")
	// ErrOAuthTokenRejected reports that GitHub refused the OAuth token during
	// the session-token exchange: it is invalid or lacks Copilot access.
	ErrOAuthTokenRejected = errors.New("copilot: OAuth token rejected")
)

// AuthError reports a Copilot authentication failure. Msg is sanitized and safe
// to show.
type AuthError struct {
	Msg        string
	StatusCode int
	Transport  bool
	// Err is ErrProxyDisabled, ErrNoOAuthToken, ErrOAuthTokenRejected, or nil.
	Err error
}

func (e *AuthError) Error() string { return e.Msg }

// Unwrap exposes the error kind to errors.Is.
func (e *AuthError) Unwrap() error { return e.Err }

func newAuthError(status int, message string) *AuthError {
	return &AuthError{Msg: sanitize.SanitizeTextLimit(message, maxAuthDiagnosticChars), StatusCode: status}
}

// Session is a resolved Copilot session token + its chat endpoint.
type Session struct {
	Token       string
	ChatBaseURL string
	ExpiresAt   int64
}

// Endpoints allows tests and compatible deployments to replace GitHub URLs.
// Empty fields use the canonical GitHub endpoints.
type Endpoints struct {
	DeviceCodeURL   string
	AccessTokenURL  string
	SessionTokenURL string
}

// Config contains caller-owned Copilot configuration. Values are never
// discovered implicitly.
type Config struct {
	// CacheDir holds the persisted OAuth token and session tokens. Empty
	// disables the disk cache: nothing is read from or written to disk, so
	// every session request performs an exchange.
	CacheDir string
	// OAuthToken is an operator-supplied GitHub OAuth token. It takes
	// precedence over the cached token and the gh CLI.
	OAuthToken string
	// UseGhCLI lets `gh auth token` supply the OAuth token when neither
	// OAuthToken nor the cache does.
	UseGhCLI bool
	// AllowProxy is the product's explicit opt-in to Copilot use; see
	// TOSWarning. AssertProxyAllowed fails without it.
	AllowProxy bool
	Endpoints  Endpoints
	// HTTPClient performs every request. Nil uses a client that times out
	// after DefaultTimeout.
	HTTPClient *http.Client
	// EditorVersion and EditorPluginVersion identify the client during the
	// session-token exchange. Empty fields use the package defaults.
	EditorVersion       string
	EditorPluginVersion string
}

// Client performs Copilot authentication with caller-owned configuration. It is
// safe for concurrent use. Share one Client per configuration, because it
// serializes concurrent polls of one device code as GitHub requires.
type Client struct {
	settings func() Config
	polls    sync.Map // device code -> *sync.Mutex
}

// New returns a Client with fixed configuration.
func New(config Config) *Client {
	return &Client{settings: func() Config { return config }}
}

// NewDynamic returns a Client that reads its configuration at the start of
// every operation, for products whose settings change at runtime. One
// operation always works from one snapshot.
func NewDynamic(settings func() Config) *Client {
	if settings == nil {
		settings = func() Config { return Config{} }
	}
	return &Client{settings: settings}
}

func (c Config) endpoints() Endpoints {
	result := c.Endpoints
	if strings.TrimSpace(result.DeviceCodeURL) == "" {
		result.DeviceCodeURL = DeviceCodeURL
	}
	if strings.TrimSpace(result.AccessTokenURL) == "" {
		result.AccessTokenURL = AccessTokenURL
	}
	if strings.TrimSpace(result.SessionTokenURL) == "" {
		result.SessionTokenURL = SessionTokenURL
	}
	return result
}

func (c Config) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: DefaultTimeout}
}

// ---- cache paths -------------------------------------------------------- //

// cachePath returns the path of name inside CacheDir, or "" when the disk cache
// is disabled. Every reader and writer treats "" as "no cache" so a missing
// directory can never resolve against the working directory.
func (c Config) cachePath(name string) string {
	if c.CacheDir == "" {
		return ""
	}
	return filepath.Join(c.CacheDir, name)
}

// oauthSessionPath keys a BYOC session cache by a non-reversible fingerprint of
// its OAuth token, so different users never share a session file.
func (c Config) oauthSessionPath(token string) string {
	return c.cachePath("github_copilot_session_" + fingerprint(token) + ".json")
}

func fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

func readJSON(path string) map[string]any {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var data map[string]any
	if json.Unmarshal(b, &data) != nil {
		return nil
	}
	return data
}

func writeJSONSecret(path string, payload map[string]any) {
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	b, _ := json.Marshal(payload)
	_ = os.WriteFile(path, b, 0o600)
}

// ---- OAuth token resolution --------------------------------------------- //

func (c Config) configuredOAuthToken() string {
	return strings.TrimSpace(c.OAuthToken)
}

func (c Config) cachedOAuthToken() string {
	data := readJSON(c.cachePath(oauthCacheFile))
	if data == nil {
		return ""
	}
	t, _ := data["access_token"].(string)
	return strings.TrimSpace(t)
}

func (c Config) ghCLIToken() string {
	if !c.UseGhCLI {
		return ""
	}
	gh, err := exec.LookPath("gh")
	if err != nil {
		return ""
	}
	cmd := exec.Command(gh, "auth", "token")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (c Config) resolveOAuthToken() (string, error) {
	for _, source := range []func() string{c.configuredOAuthToken, c.cachedOAuthToken, c.ghCLIToken} {
		if t := source(); t != "" {
			return t, nil
		}
	}
	return "", &AuthError{Msg: "no GitHub Copilot OAuth token available.", Err: ErrNoOAuthToken}
}

// AssertProxyAllowed returns an AuthError matching ErrProxyDisabled unless the
// product enabled Copilot use with Config.AllowProxy.
func (c *Client) AssertProxyAllowed() error {
	if c.settings().AllowProxy {
		return nil
	}
	return &AuthError{
		Msg: "github_copilot provider is disabled by default (personal-use grey area).",
		Err: ErrProxyDisabled,
	}
}

// ResolveOAuthToken returns the first OAuth token from Config.OAuthToken, the
// disk cache, and the gh CLI, in that order. Without one it returns an
// AuthError matching ErrNoOAuthToken.
func (c *Client) ResolveOAuthToken() (string, error) {
	return c.settings().resolveOAuthToken()
}

// ---- session token ------------------------------------------------------ //

func (c Config) copilotHeaders() map[string]string {
	editorVersion := c.EditorVersion
	if editorVersion == "" {
		editorVersion = DefaultEditorVersion
	}
	pluginVersion := c.EditorPluginVersion
	if pluginVersion == "" {
		pluginVersion = DefaultEditorPluginVersion
	}
	return map[string]string{
		"Accept":                "application/json",
		"Editor-Version":        editorVersion,
		"Editor-Plugin-Version": pluginVersion,
		"User-Agent":            "GithubCopilot/" + pluginVersion,
	}
}

func (c Config) exchangeOAuthForSession(oauthToken string) (*Session, error) {
	req, err := http.NewRequest("GET", c.endpoints().SessionTokenURL, nil)
	if err != nil {
		return nil, newAuthError(0, "Copilot session-token request is invalid: "+err.Error())
	}
	for k, v := range c.copilotHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "token "+oauthToken)
	resp, err := c.client().Do(req)
	if err != nil {
		authErr := newAuthError(0, "Copilot session-token transport error: "+err.Error())
		authErr.Transport = true
		return nil, authErr
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		authErr := newAuthError(resp.StatusCode, "Copilot session-token exchange returned 401: the OAuth token "+
			"is invalid or lacks Copilot access.")
		authErr.Err = ErrOAuthTokenRejected
		return nil, authErr
	}
	if resp.StatusCode >= 400 {
		return nil, newAuthError(resp.StatusCode, fmt.Sprintf("Copilot session-token exchange failed (%d)", resp.StatusCode))
	}
	var payload map[string]any
	if json.NewDecoder(resp.Body).Decode(&payload) != nil {
		return nil, &AuthError{Msg: "Copilot session-token response was not JSON"}
	}
	token, _ := payload["token"].(string)
	token = strings.TrimSpace(token)
	expiresAt := int64(numOf(payload["expires_at"]))
	if token == "" || expiresAt == 0 {
		return nil, &AuthError{Msg: "Copilot session-token response missing token/expires_at"}
	}
	chatBase := defaultChatBase
	if endpoints, ok := payload["endpoints"].(map[string]any); ok {
		if api, ok := endpoints["api"].(string); ok && api != "" {
			chatBase = api
		}
	}
	return &Session{Token: token, ChatBaseURL: strings.TrimRight(chatBase, "/"), ExpiresAt: expiresAt}, nil
}

func numOf(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}

func cachedSessionAt(path, oauthToken string) *Session {
	data := readJSON(path)
	if data == nil || data["fingerprint"] != fingerprint(oauthToken) {
		return nil
	}
	expiresAt := int64(numOf(data["expires_at"]))
	if expiresAt-time.Now().Unix() < refreshBeforeExpirySec {
		return nil
	}
	token, _ := data["token"].(string)
	if strings.TrimSpace(token) == "" {
		return nil
	}
	chatBase, _ := data["chat_base_url"].(string)
	if chatBase == "" {
		chatBase = defaultChatBase
	}
	return &Session{Token: token, ChatBaseURL: strings.TrimRight(chatBase, "/"), ExpiresAt: expiresAt}
}

func storeSessionAt(path, oauthToken string, s *Session) {
	writeJSONSecret(path, map[string]any{
		"fingerprint": fingerprint(oauthToken), "token": s.Token,
		"chat_base_url": s.ChatBaseURL, "expires_at": s.ExpiresAt,
	})
}

func (c Config) session(path, oauthToken string, forceRefresh bool) (*Session, error) {
	if !forceRefresh {
		if cached := cachedSessionAt(path, oauthToken); cached != nil {
			return cached, nil
		}
	}
	session, err := c.exchangeOAuthForSession(oauthToken)
	if err != nil {
		return nil, err
	}
	storeSessionAt(path, oauthToken, session)
	return session, nil
}

// GetSession returns a fresh-enough Copilot session token for the resolved
// OAuth token, refreshing on demand.
func (c *Client) GetSession(forceRefresh bool) (*Session, error) {
	config := c.settings()
	oauthToken, err := config.resolveOAuthToken()
	if err != nil {
		return nil, err
	}
	return config.session(config.cachePath(sessionCacheFile), oauthToken, forceRefresh)
}

// GetSessionForOAuth resolves an isolated Copilot session for one BYOC OAuth
// credential. Its cache file is keyed by a non-reversible token fingerprint, so
// multiple users never overwrite or reuse each other's session token.
func (c *Client) GetSessionForOAuth(oauthToken string, forceRefresh bool) (*Session, error) {
	oauthToken = strings.TrimSpace(oauthToken)
	if oauthToken == "" {
		return nil, &AuthError{Msg: "Copilot OAuth token is empty"}
	}
	config := c.settings()
	return config.session(config.oauthSessionPath(oauthToken), oauthToken, forceRefresh)
}

// ---- device-code flow --------------------------------------------------- //

// DeviceCode is a started device-code login.
type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

func (c *Client) StartDeviceFlow() (*DeviceCode, error) {
	config := c.settings()
	form := url.Values{"client_id": {ClientID}, "scope": {"read:user"}}
	req, err := http.NewRequest("POST", config.endpoints().DeviceCodeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, newAuthError(0, "device-code request is invalid: "+err.Error())
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := config.client().Do(req)
	if err != nil {
		return nil, newAuthError(0, "device-code request failed: "+err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, newAuthError(resp.StatusCode, fmt.Sprintf("device-code request returned %d", resp.StatusCode))
	}
	var payload map[string]any
	if json.NewDecoder(resp.Body).Decode(&payload) != nil {
		return nil, &AuthError{Msg: "device-code response was not JSON"}
	}
	dc := &DeviceCode{
		DeviceCode:      strOf(payload["device_code"]),
		UserCode:        strOf(payload["user_code"]),
		VerificationURI: strOf(payload["verification_uri"]),
		Interval:        int(numOf(payload["interval"])),
		ExpiresIn:       int(numOf(payload["expires_in"])),
	}
	if dc.VerificationURI == "" {
		dc.VerificationURI = "https://github.com/login/device"
	}
	if dc.Interval == 0 {
		dc.Interval = 5
	}
	if dc.ExpiresIn == 0 {
		dc.ExpiresIn = 900
	}
	return dc, nil
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

type DevicePollResult struct {
	Status      string
	Error       string
	AccessToken string
}

// lockDevicePoll serializes concurrent polls for one device code. This preserves
// provider-required sequential polling while allowing a browser to resume later.
func (c *Client) lockDevicePoll(deviceCode string) func() {
	key := strings.TrimSpace(deviceCode)
	value, _ := c.polls.LoadOrStore(key, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

// PollDeviceFlowTokenOnce performs one non-blocking device-flow poll and returns
// the OAuth token to the caller without persisting or exposing it in JSON.
func (c *Client) PollDeviceFlowTokenOnce(deviceCode string) DevicePollResult {
	return c.pollDeviceFlow(c.settings(), deviceCode)
}

func (c *Client) pollDeviceFlow(config Config, deviceCode string) DevicePollResult {
	unlock := c.lockDevicePoll(deviceCode)
	defer unlock()
	form := url.Values{
		"client_id":   {ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	req, err := http.NewRequest("POST", config.endpoints().AccessTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return DevicePollResult{Status: "error", Error: sanitize.SanitizeTextLimit("invalid request: "+err.Error(), maxAuthDiagnosticChars)}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := config.client().Do(req)
	if err != nil {
		return DevicePollResult{Status: "error", Error: sanitize.SanitizeTextLimit("transport error: "+err.Error(), maxAuthDiagnosticChars)}
	}
	defer resp.Body.Close()
	var payload map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	if payload == nil {
		payload = map[string]any{}
	}
	token := strings.TrimSpace(strOf(payload["access_token"]))
	if token != "" {
		return DevicePollResult{Status: "authorized", AccessToken: token}
	}
	e := strings.TrimSpace(strOf(payload["error"]))
	switch e {
	case "authorization_pending":
		return DevicePollResult{Status: "pending"}
	case "slow_down":
		return DevicePollResult{Status: "slow_down"}
	}
	if e == "" {
		e = "unknown error"
	}
	return DevicePollResult{Status: "denied", Error: sanitize.SanitizeTextLimit(e, maxAuthDiagnosticChars)}
}

// PollDeviceFlowOnce is the legacy single-operator flow. It persists the token
// to the Copilot cache and returns a secret-free status envelope. It refuses to
// poll without a CacheDir, because an authorized token it cannot store would be
// lost and the one-time device code spent.
func (c *Client) PollDeviceFlowOnce(deviceCode string) map[string]any {
	config := c.settings()
	if config.CacheDir == "" {
		return map[string]any{"status": "error", "error": "Copilot cache directory is not configured"}
	}
	result := c.pollDeviceFlow(config, deviceCode)
	if result.Status == "authorized" {
		config.persistOAuthToken(result.AccessToken)
	}
	out := map[string]any{"status": result.Status}
	if result.Error != "" {
		out["error"] = result.Error
	}
	return out
}

func (c Config) persistOAuthToken(token string) {
	writeJSONSecret(c.cachePath(oauthCacheFile), map[string]any{
		"access_token": token, "stored_at": time.Now().Unix(),
	})
}

// ClearCachedCredentials removes cached OAuth + session tokens.
func (c *Client) ClearCachedCredentials() map[string]bool {
	config := c.settings()
	removed := map[string]bool{}
	for label, name := range map[string]string{"oauth": oauthCacheFile, "session": sessionCacheFile} {
		path := config.cachePath(name)
		removed[label] = path != "" && os.Remove(path) == nil
	}
	return removed
}

// AuthStatus is a diagnostic snapshot for an admin surface. The "env"
// active_source and env_present keys describe Config.OAuthToken; they keep the
// names existing status consumers already read.
func (c *Client) AuthStatus() map[string]any {
	config := c.settings()
	configured := config.configuredOAuthToken()
	cache := config.cachedOAuthToken()
	gh := config.ghCLIToken()
	var active any
	switch {
	case configured != "":
		active = "env"
	case cache != "":
		active = "cache"
	case gh != "":
		active = "gh-cli"
	}
	return map[string]any{
		"active_source":  active,
		"env_present":    configured != "",
		"cache_present":  cache != "",
		"gh_cli_present": gh != "",
		"use_gh_cli":     config.UseGhCLI,
		"cache_dir":      config.CacheDir,
	}
}

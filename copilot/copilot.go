package copilot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// Endpoint variables keep device and session flows testable against local mocked endpoints.
// Production defaults remain the official GitHub endpoints.
var (
	DeviceCodeURL   = "https://github.com/login/device/code"
	AccessTokenURL  = "https://github.com/login/oauth/access_token"
	SessionTokenURL = "https://api.github.com/copilot_internal/v2/token"
	devicePollLocks sync.Map
)

var (
	CacheDir            = ""
	OAuthToken          = ""
	UseGhCLI            = true
	EditorVersion       = "vscode/1.96.2"
	EditorPluginVersion = "copilot-auth/1.0"
	TimeoutSeconds      = 60.0
	AllowProxy          = true
)

// AuthError is raised when no usable Copilot OAuth token can be resolved.
type AuthError struct {
	Msg        string
	StatusCode int
	Transport  bool
}

func (e *AuthError) Error() string { return e.Msg }

func newAuthError(status int, message string) *AuthError {
	return &AuthError{Msg: sanitize.SanitizeTextLimit(message, maxAuthDiagnosticChars), StatusCode: status}
}

// Session is a resolved Copilot session token + its chat endpoint.
type Session struct {
	Token       string
	ChatBaseURL string
	ExpiresAt   int64
}

func httpClient() *http.Client {
	timeout := TimeoutSeconds
	if timeout <= 0 {
		timeout = 60
	}
	return &http.Client{Timeout: time.Duration(timeout * float64(time.Second))}
}

// ---- cache paths -------------------------------------------------------- //

func cacheDir() string {
	if CacheDir != "" {
		return CacheDir
	}
	if o := strings.TrimSpace(os.Getenv("LLMGW_GITHUB_COPILOT_CACHE_DIR")); o != "" {
		return o
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".copilot-auth", "cache")
}

func ensureCacheDir() string {
	d := cacheDir()
	_ = os.MkdirAll(d, 0o755)
	return d
}

func oauthCachePath() string   { return filepath.Join(cacheDir(), oauthCacheFile) }
func sessionCachePath() string { return filepath.Join(cacheDir(), sessionCacheFile) }
func sessionCachePathForOAuth(token string) string {
	return filepath.Join(cacheDir(), "github_copilot_session_"+fingerprint(token)+".json")
}

func fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

func readJSON(path string) map[string]any {
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
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	b, _ := json.Marshal(payload)
	_ = os.WriteFile(path, b, 0o600)
}

// ---- OAuth token resolution --------------------------------------------- //

func fromEnv() string {
	if OAuthToken != "" {
		return OAuthToken
	}
	if t := strings.TrimSpace(os.Getenv("GITHUB_COPILOT_OAUTH_TOKEN")); t != "" {
		return t
	}
	return strings.TrimSpace(os.Getenv("LLMGW_GITHUB_COPILOT_OAUTH_TOKEN"))
}

func fromCache() string {
	data := readJSON(oauthCachePath())
	if data == nil {
		return ""
	}
	t, _ := data["access_token"].(string)
	return strings.TrimSpace(t)
}

func fromGhCLI() string {
	if !UseGhCLI {
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

// AssertProxyAllowed raises AuthError unless the copilot proxy is enabled.
func AssertProxyAllowed() error {
	enabled := AllowProxy
	if !enabled {
		v := strings.ToLower(strings.TrimSpace(os.Getenv("LLMGW_EXPERIMENTAL_COPILOT_PROVIDER")))
		enabled = v == "1" || v == "true" || v == "yes" || v == "on"
	}
	if !enabled {
		return &AuthError{Msg: "github_copilot provider is disabled by default (personal-use grey " +
			"area). Enable it for your own loopback gateway with allow_copilot_proxy: true or " +
			"LLMGW_EXPERIMENTAL_COPILOT_PROVIDER=1."}
	}
	return nil
}

// ResolveOAuthToken finds a usable GitHub OAuth token or returns AuthError.
func ResolveOAuthToken() (string, error) {
	for _, src := range []func() string{fromEnv, fromCache, fromGhCLI} {
		if t := src(); t != "" {
			return t, nil
		}
	}
	return "", &AuthError{Msg: "no GitHub Copilot OAuth token available. Sign in via the /admin " +
		"panel, set LLMGW_GITHUB_COPILOT_OAUTH_TOKEN, or `gh auth refresh -s copilot` then `gh auth token`."}
}

// ---- session token ------------------------------------------------------ //

func copilotHeaders() map[string]string {
	return map[string]string{
		"Accept":                "application/json",
		"Editor-Version":        EditorVersion,
		"Editor-Plugin-Version": EditorPluginVersion,
		"User-Agent":            "GithubCopilot/" + EditorPluginVersion,
	}
}

func exchangeOAuthForSession(oauthToken string) (*Session, error) {
	req, _ := http.NewRequest("GET", SessionTokenURL, nil)
	for k, v := range copilotHeaders() {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "token "+oauthToken)
	resp, err := httpClient().Do(req)
	if err != nil {
		authErr := newAuthError(0, "Copilot session-token transport error: "+err.Error())
		authErr.Transport = true
		return nil, authErr
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, newAuthError(resp.StatusCode, "Copilot session-token exchange returned 401: the OAuth token "+
			"is invalid or lacks Copilot access. Sign in via the /admin panel.")
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
	ensureCacheDir()
	writeJSONSecret(path, map[string]any{
		"fingerprint": fingerprint(oauthToken), "token": s.Token,
		"chat_base_url": s.ChatBaseURL, "expires_at": s.ExpiresAt,
	})
}

// GetSession returns a fresh-enough Copilot session token, refreshing on demand.
func GetSession(forceRefresh bool) (*Session, error) {
	oauthToken, err := ResolveOAuthToken()
	if err != nil {
		return nil, err
	}
	if !forceRefresh {
		if c := cachedSessionAt(sessionCachePath(), oauthToken); c != nil {
			return c, nil
		}
	}
	s, err := exchangeOAuthForSession(oauthToken)
	if err != nil {
		return nil, err
	}
	storeSessionAt(sessionCachePath(), oauthToken, s)
	return s, nil
}

// GetSessionForOAuth resolves an isolated Copilot session for one BYOC OAuth
// credential. Its cache file is keyed by a non-reversible token fingerprint, so
// multiple users never overwrite or reuse each other's session token.
func GetSessionForOAuth(oauthToken string, forceRefresh bool) (*Session, error) {
	oauthToken = strings.TrimSpace(oauthToken)
	if oauthToken == "" {
		return nil, &AuthError{Msg: "Copilot OAuth token is empty"}
	}
	path := sessionCachePathForOAuth(oauthToken)
	if !forceRefresh {
		if cached := cachedSessionAt(path, oauthToken); cached != nil {
			return cached, nil
		}
	}
	session, err := exchangeOAuthForSession(oauthToken)
	if err != nil {
		return nil, err
	}
	storeSessionAt(path, oauthToken, session)
	return session, nil
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

func StartDeviceFlow() (*DeviceCode, error) {
	form := url.Values{"client_id": {ClientID}, "scope": {"read:user"}}
	req, _ := http.NewRequest("POST", DeviceCodeURL, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient().Do(req)
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
func lockDevicePoll(deviceCode string) func() {
	key := strings.TrimSpace(deviceCode)
	value, _ := devicePollLocks.LoadOrStore(key, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

// PollDeviceFlowTokenOnce performs one non-blocking device-flow poll and returns
// the OAuth token to the caller without persisting or exposing it in JSON.
func PollDeviceFlowTokenOnce(deviceCode string) DevicePollResult {
	unlock := lockDevicePoll(deviceCode)
	defer unlock()
	form := url.Values{
		"client_id":   {ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	req, _ := http.NewRequest("POST", AccessTokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient().Do(req)
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
// to the global Copilot cache and returns a secret-free status envelope.
func PollDeviceFlowOnce(deviceCode string) map[string]any {
	result := PollDeviceFlowTokenOnce(deviceCode)
	if result.Status == "authorized" {
		persistOAuthToken(result.AccessToken)
	}
	out := map[string]any{"status": result.Status}
	if result.Error != "" {
		out["error"] = result.Error
	}
	return out
}

func persistOAuthToken(token string) {
	ensureCacheDir()
	writeJSONSecret(oauthCachePath(), map[string]any{
		"access_token": token, "stored_at": time.Now().Unix(),
	})
}

// ClearCachedCredentials removes cached OAuth + session tokens.
func ClearCachedCredentials() map[string]bool {
	removed := map[string]bool{}
	for label, path := range map[string]string{"oauth": oauthCachePath(), "session": sessionCachePath()} {
		removed[label] = os.Remove(path) == nil
	}
	return removed
}

// AuthStatus is a diagnostic snapshot for the /admin panel.
func AuthStatus() map[string]any {
	env := fromEnv()
	cache := fromCache()
	gh := fromGhCLI()
	var active any
	switch {
	case env != "":
		active = "env"
	case cache != "":
		active = "cache"
	case gh != "":
		active = "gh-cli"
	}
	return map[string]any{
		"active_source":  active,
		"env_present":    env != "",
		"cache_present":  cache != "",
		"gh_cli_present": gh != "",
		"use_gh_cli":     UseGhCLI,
		"cache_dir":      cacheDir(),
	}
}

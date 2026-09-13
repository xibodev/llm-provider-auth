package codex

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xibodev/llm-provider-auth/internal/sanitize"
)

const maxAuthDiagnosticChars = 512

var (
	UserCodeURL      = "https://auth.openai.com/api/accounts/deviceauth/usercode"
	DeviceTokenURL   = "https://auth.openai.com/api/accounts/deviceauth/token"
	OAuthTokenURL    = "https://auth.openai.com/oauth/token"
	RevokeURL        = "https://auth.openai.com/oauth/revoke"
	ResponsesBaseURL = "https://chatgpt.com/backend-api/codex"
	ModelsURL        = "https://chatgpt.com/backend-api/codex/models"
	ClientVersion    = "llm-gateway/0.4"
	HTTPClient       = func() *http.Client { return &http.Client{Timeout: 20 * time.Second} }
)

const (
	DeviceVerificationURL = "https://auth.openai.com/codex/device"
	DeviceAuthRedirectURI = "https://auth.openai.com/deviceauth/callback"
)

type DeviceFlow struct {
	DeviceAuthID    string
	UserCode        string
	VerificationURI string
	Interval        int
	ExpiresIn       int
	ClientID        string
}

type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresAt    int64
	AccountID    string
	AccountLabel string
}

type RefreshError struct {
	StatusCode  int
	Code        string
	Description string
}

type AuthError struct {
	Operation   string
	StatusCode  int
	Code        string
	Description string
}

func (e *AuthError) Error() string {
	message := "Codex " + e.Operation + " failed"
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

func authError(operation string, status int, code, description string) *AuthError {
	return &AuthError{
		Operation: operation, StatusCode: status,
		Code:        sanitize.SanitizeTextLimit(strings.TrimSpace(code), maxAuthDiagnosticChars),
		Description: sanitize.SanitizeTextLimit(strings.TrimSpace(description), maxAuthDiagnosticChars),
	}
}

func (e *RefreshError) Error() string {
	message := "Codex refresh failed"
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.StatusCode)
	}
	if e.Code != "" {
		message += ": " + e.Code
	}
	if e.Description != "" {
		message += ": " + e.Description
	}
	return sanitize.SanitizeTextLimit(message, maxAuthDiagnosticChars)
}

func StartDeviceFlow(clientID string) (DeviceFlow, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return DeviceFlow{}, fmt.Errorf("OpenAI Codex client ID is required")
	}
	body, _ := json.Marshal(map[string]string{"client_id": clientID})
	request, _ := http.NewRequest(http.MethodPost, UserCodeURL, bytes.NewReader(body))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := HTTPClient().Do(request)
	if err != nil {
		return DeviceFlow{}, authError("device authorization", 0, "transport", err.Error())
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		return DeviceFlow{}, authError("device authorization", response.StatusCode, "", "")
	}
	payload := map[string]any{}
	if json.Unmarshal(raw, &payload) != nil {
		return DeviceFlow{}, fmt.Errorf("Codex device authorization response was not JSON")
	}
	flow := DeviceFlow{
		DeviceAuthID:    firstString(payload, "device_auth_id", "device_code"),
		UserCode:        firstString(payload, "user_code", "usercode"),
		VerificationURI: firstString(payload, "verification_uri", "verification_url", "verification_uri_complete"),
		Interval:        int(number(payload["interval"])), ExpiresIn: int(number(payload["expires_in"])),
		ClientID: clientID,
	}
	if flow.VerificationURI == "" {
		flow.VerificationURI = DeviceVerificationURL
	}
	if flow.Interval <= 0 {
		flow.Interval = 5
	}
	if flow.ExpiresIn <= 0 {
		flow.ExpiresIn = 900
	}
	if flow.DeviceAuthID == "" || flow.UserCode == "" {
		return DeviceFlow{}, fmt.Errorf("Codex device authorization response was incomplete")
	}
	return flow, nil
}

func PollAndExchange(flow DeviceFlow) (string, TokenSet, error) {
	body, _ := json.Marshal(map[string]string{"device_auth_id": flow.DeviceAuthID, "user_code": flow.UserCode})
	request, _ := http.NewRequest(http.MethodPost, DeviceTokenURL, bytes.NewReader(body))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := HTTPClient().Do(request)
	if err != nil {
		return "error", TokenSet{}, authError("device token", 0, "transport", err.Error())
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound {
		return "pending", TokenSet{}, nil
	}
	payload := map[string]any{}
	_ = json.Unmarshal(raw, &payload)
	if response.StatusCode >= 400 {
		code := strings.ToLower(firstString(payload, "error", "code"))
		switch code {
		case "authorization_pending", "pending":
			return "pending", TokenSet{}, nil
		case "slow_down":
			return "slow_down", TokenSet{}, nil
		case "expired_token", "expired", "device_code_expired":
			return "expired", TokenSet{}, nil
		default:
			if code == "" {
				code = fmt.Sprintf("http_%d", response.StatusCode)
			}
			return "denied", TokenSet{}, authError("device authorization", response.StatusCode, code, "")
		}
	}
	authorizationCode := firstString(payload, "authorization_code", "code")
	if authorizationCode == "" {
		return "pending", TokenSet{}, nil
	}
	verifier := firstString(payload, "code_verifier")
	if verifier == "" {
		return "error", TokenSet{}, fmt.Errorf("Codex device token response did not include code_verifier")
	}
	tokens, err := ExchangeAuthorizationCode(flow.ClientID, authorizationCode, verifier)
	if err != nil {
		return "error", TokenSet{}, err
	}
	return "authorized", tokens, nil
}

func ExchangeAuthorizationCode(clientID, authorizationCode, verifier string) (TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authorizationCode},
		"code_verifier": {verifier},
		"redirect_uri":  {DeviceAuthRedirectURI},
	}
	return tokenRequest(strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", false)
}

func Refresh(clientID, refreshToken string) (TokenSet, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return TokenSet{}, &RefreshError{Code: "missing_refresh_token"}
	}
	body, _ := json.Marshal(map[string]string{
		"client_id":     clientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})
	return tokenRequest(bytes.NewReader(body), "application/json", true)
}

func Revoke(clientID, refreshToken, accessToken string) error {
	token := strings.TrimSpace(refreshToken)
	tokenTypeHint := "refresh_token"
	if token == "" {
		token = strings.TrimSpace(accessToken)
		tokenTypeHint = "access_token"
	}
	if token == "" {
		return nil
	}
	payload := map[string]string{"token": token, "token_type_hint": tokenTypeHint}
	if tokenTypeHint == "refresh_token" {
		payload["client_id"] = clientID
	}
	body, _ := json.Marshal(payload)
	request, _ := http.NewRequest(http.MethodPost, RevokeURL, bytes.NewReader(body))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := HTTPClient().Do(request)
	if err != nil {
		return authError("revoke", 0, "transport", err.Error())
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return authError("revoke", response.StatusCode, "", "")
	}
	return nil
}

func tokenRequest(body io.Reader, contentType string, isRefresh bool) (TokenSet, error) {
	request, _ := http.NewRequest(http.MethodPost, OAuthTokenURL, body)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", contentType)
	response, err := HTTPClient().Do(request)
	if err != nil {
		return TokenSet{}, authError("OAuth token", 0, "transport", err.Error())
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	payload := map[string]any{}
	_ = json.Unmarshal(raw, &payload)
	if response.StatusCode >= 400 {
		code := firstString(payload, "error", "code")
		description := firstString(payload, "error_description", "message")
		if code == "" {
			code = fmt.Sprintf("http_%d", response.StatusCode)
		}
		if isRefresh {
			return TokenSet{}, &RefreshError{
				StatusCode:  response.StatusCode,
				Code:        sanitize.SanitizeTextLimit(code, maxAuthDiagnosticChars),
				Description: sanitize.SanitizeTextLimit(description, maxAuthDiagnosticChars),
			}
		}
		return TokenSet{}, authError("OAuth token exchange", response.StatusCode, code, description)
	}
	access := firstString(payload, "access_token")
	if access == "" {
		return TokenSet{}, fmt.Errorf("Codex OAuth token response did not include access_token")
	}
	idToken := firstString(payload, "id_token")
	accountID := firstString(payload, "account_id", "chatgpt_account_id", "workspace_id")
	accountLabel := firstString(payload, "account_label", "workspace_name", "email")
	claimedAccountID, claimedAccountLabel := idTokenIdentity(idToken)
	if accountID == "" {
		accountID = claimedAccountID
	}
	if accountLabel == "" {
		accountLabel = claimedAccountLabel
	}
	expiresIn := int64(number(payload["expires_in"]))
	expiresAt := int64(number(payload["expires_at"]))
	if expiresAt == 0 && expiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second).Unix()
	}
	if expiresAt == 0 {
		expiresAt = accessTokenExpiry(access)
	}
	return TokenSet{
		AccessToken: access, RefreshToken: firstString(payload, "refresh_token"), IDToken: idToken,
		TokenType: firstString(payload, "token_type"), ExpiresAt: expiresAt,
		AccountID: accountID, AccountLabel: accountLabel,
	}, nil
}

func accessTokenExpiry(accessToken string) int64 {
	parts := strings.Split(strings.TrimSpace(accessToken), ".")
	if len(parts) != 3 || parts[1] == "" {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return 0
	}
	claims := struct {
		ExpiresAt int64 `json:"exp"`
	}{}
	if json.Unmarshal(payload, &claims) != nil || claims.ExpiresAt <= 0 {
		return 0
	}
	return claims.ExpiresAt
}

type openAIIDTokenClaims struct {
	Email     string `json:"email"`
	AccountID string `json:"chatgpt_account_id"`
	Profile   struct {
		Email string `json:"email"`
	} `json:"https://api.openai.com/profile"`
	Auth struct {
		AccountID string `json:"chatgpt_account_id"`
	} `json:"https://api.openai.com/auth"`
}

func idTokenIdentity(idToken string) (string, string) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 || parts[1] == "" {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return "", ""
	}
	claims := openAIIDTokenClaims{}
	if json.Unmarshal(payload, &claims) != nil {
		return "", ""
	}
	accountID := strings.TrimSpace(claims.Auth.AccountID)
	if accountID == "" {
		accountID = strings.TrimSpace(claims.AccountID)
	}
	label := strings.TrimSpace(claims.Email)
	if label == "" {
		label = strings.TrimSpace(claims.Profile.Email)
	}
	return accountID, label
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func number(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed
	}
	return 0
}

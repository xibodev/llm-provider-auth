// Package antigravity provides storage-neutral OAuth and Cloud Code Assist
// account discovery primitives for Google Antigravity integrations.
package antigravity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xibodev/llm-provider-auth/browseroauth"
)

const (
	AuthorizeURL         = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenURL             = "https://oauth2.googleapis.com/token"
	LoadCodeAssistURL    = "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
	OpenIDScope          = "openid"
	CloudPlatformScope   = "https://www.googleapis.com/auth/cloud-platform"
	UserinfoEmailScope   = "https://www.googleapis.com/auth/userinfo.email"
	UserinfoProfileScope = "https://www.googleapis.com/auth/userinfo.profile"
	CloudCodeLogScope    = "https://www.googleapis.com/auth/cclog"
	ExperimentsScope     = "https://www.googleapis.com/auth/experimentsandconfigs"
	defaultTimeout       = 20 * time.Second
	maxResponseBytes     = int64(1 << 20)
)

// Endpoints allows tests and compatible deployments to replace provider URLs.
// Empty fields use the canonical Google endpoints.
type Endpoints struct {
	AuthorizeURL      string
	TokenURL          string
	LoadCodeAssistURL string
}

// ClientAuthMode identifies how the Antigravity OAuth client authenticates.
type ClientAuthMode = browseroauth.ClientAuthMode

const (
	ClientAuthModePublicPKCE       = browseroauth.ClientAuthModePublicPKCE
	ClientAuthModeClientSecretPost = browseroauth.ClientAuthModeClientSecretPost
)

// Config contains caller-owned OAuth application configuration. Each operation
// validates only the fields it uses; values are never discovered implicitly.
type Config struct {
	ClientID       string
	ClientSecret   string
	ClientAuthMode ClientAuthMode
	RedirectURI    string
	Endpoints      Endpoints
	HTTPClient     *http.Client
}

// TokenEnvelope is the browseroauth token result returned by Exchange and
// Refresh. The caller owns its storage and lifecycle.
type TokenEnvelope = browseroauth.TokenEnvelope

// Authorization contains the URL, state, and PKCE verifier for one login.
type Authorization = browseroauth.Authorization

// TierID identifies a Cloud Code Assist account tier.
type TierID string

// IneligibilityReason identifies why Google will not offer a tier.
type IneligibilityReason string

const (
	IneligibilityUnknown             IneligibilityReason = "UNKNOWN"
	IneligibilityDasherUser          IneligibilityReason = "DASHER_USER"
	IneligibilityAccount             IneligibilityReason = "INELIGIBLE_ACCOUNT"
	IneligibilityNonUserAccount      IneligibilityReason = "NON_USER_ACCOUNT"
	IneligibilityRestrictedAge       IneligibilityReason = "RESTRICTED_AGE"
	IneligibilityRestrictedNetwork   IneligibilityReason = "RESTRICTED_NETWORK"
	IneligibilityUnknownLocation     IneligibilityReason = "UNKNOWN_LOCATION"
	IneligibilityUnsupportedLocation IneligibilityReason = "UNSUPPORTED_LOCATION"
	IneligibilityValidationRequired  IneligibilityReason = "VALIDATION_REQUIRED"
)

// PrivacyNotice describes a tier's privacy-notice requirement.
type PrivacyNotice struct {
	ShowNotice bool   `json:"showNotice,omitempty"`
	NoticeText string `json:"noticeText,omitempty"`
}

// Tier describes a Cloud Code Assist account tier.
type Tier struct {
	ID                                 TierID         `json:"id,omitempty"`
	Name                               string         `json:"name,omitempty"`
	Description                        string         `json:"description,omitempty"`
	UserDefinedCloudAICompanionProject *bool          `json:"userDefinedCloudaicompanionProject,omitempty"`
	IsDefault                          bool           `json:"isDefault,omitempty"`
	PrivacyNotice                      *PrivacyNotice `json:"privacyNotice,omitempty"`
	HasAcceptedTOS                     bool           `json:"hasAcceptedTos,omitempty"`
	HasOnboardedPreviously             bool           `json:"hasOnboardedPreviously,omitempty"`
}

// IneligibleTier describes a tier that Cloud Code Assist will not offer.
type IneligibleTier struct {
	ReasonCode                  IneligibilityReason `json:"reasonCode,omitempty"`
	ReasonMessage               string              `json:"reasonMessage,omitempty"`
	TierID                      TierID              `json:"tierId,omitempty"`
	TierName                    string              `json:"tierName,omitempty"`
	ValidationErrorMessage      string              `json:"validationErrorMessage,omitempty"`
	ValidationURL               string              `json:"validationUrl,omitempty"`
	ValidationURLLinkText       string              `json:"validationUrlLinkText,omitempty"`
	ValidationLearnMoreURL      string              `json:"validationLearnMoreUrl,omitempty"`
	ValidationLearnMoreLinkText string              `json:"validationLearnMoreLinkText,omitempty"`
}

// AccountMetadata is the typed loadCodeAssist account and project result.
// ProjectID is empty when Google does not return a project; no fallback is used.
type AccountMetadata struct {
	ProjectID       string           `json:"cloudaicompanionProject,omitempty"`
	CurrentTier     *Tier            `json:"currentTier,omitempty"`
	PaidTier        *Tier            `json:"paidTier,omitempty"`
	AllowedTiers    []Tier           `json:"allowedTiers,omitempty"`
	IneligibleTiers []IneligibleTier `json:"ineligibleTiers,omitempty"`
}

// APIError exposes safe, machine-inspectable loadCodeAssist failure facts.
type APIError struct {
	StatusCode int
	Code       string
	cause      error
}

func (e *APIError) Error() string {
	message := "Antigravity account discovery failed"
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.StatusCode)
	}
	if e.Code != "" {
		message += ": " + e.Code
	}
	return message
}

// Unwrap exposes local request, transport, and decoding failures without
// incorporating their potentially sensitive text into the public message.
func (e *APIError) Unwrap() error {
	return e.cause
}

// Scopes returns a new copy of the canonical Antigravity OAuth scope list.
func Scopes() []string {
	return []string{
		OpenIDScope,
		CloudPlatformScope,
		UserinfoEmailScope,
		UserinfoProfileScope,
		CloudCodeLogScope,
		ExperimentsScope,
	}
}

// AuthorizationURL creates the Google authorization URL with PKCE, offline
// access, and forced consent so Google can issue a refresh token.
func (c Config) AuthorizationURL() (Authorization, error) {
	if strings.TrimSpace(c.ClientID) == "" {
		return Authorization{}, fmt.Errorf("Antigravity OAuth client ID is required")
	}
	endpoints := c.endpoints()
	if _, err := absoluteURL("authorize URL", endpoints.AuthorizeURL); err != nil {
		return Authorization{}, err
	}
	if _, err := redirectURL(c.RedirectURI); err != nil {
		return Authorization{}, err
	}
	oauth := browseroauth.Config{
		AuthorizeURL:   endpoints.AuthorizeURL,
		ClientID:       strings.TrimSpace(c.ClientID),
		ClientSecret:   c.ClientSecret,
		ClientAuthMode: c.ClientAuthMode,
		Scopes:         Scopes(),
		ExtraAuthParams: url.Values{
			"access_type": {"offline"},
			"prompt":      {"consent"},
		},
	}
	return oauth.AuthorizationURL(strings.TrimSpace(c.RedirectURI))
}

// Exchange trades a Google authorization code for tokens.
func (c Config) Exchange(ctx context.Context, code, codeVerifier string) (TokenEnvelope, error) {
	if _, err := redirectURL(c.RedirectURI); err != nil {
		return TokenEnvelope{}, err
	}
	oauth, err := c.oauthConfig()
	if err != nil {
		return TokenEnvelope{}, err
	}
	return oauth.Exchange(ctx, code, codeVerifier, strings.TrimSpace(c.RedirectURI))
}

// CompleteAuthorization validates the callback state before exchanging its
// authorization code. The caller still owns the browser and callback handling.
func (c Config) CompleteAuthorization(ctx context.Context, authorization Authorization, callbackState, code string) (TokenEnvelope, error) {
	if err := browseroauth.ValidateState(authorization.State, callbackState); err != nil {
		return TokenEnvelope{}, err
	}
	return c.Exchange(ctx, code, authorization.CodeVerifier)
}

// Refresh exchanges a refresh token. If Google omits a replacement refresh
// token, the supplied token is retained in the returned envelope.
func (c Config) Refresh(ctx context.Context, refreshToken string) (TokenEnvelope, error) {
	oauth, err := c.oauthConfig()
	if err != nil {
		return TokenEnvelope{}, err
	}
	return oauth.Refresh(ctx, refreshToken)
}

// DiscoverAccount resolves typed Cloud Code Assist metadata and the managed
// project returned by loadCodeAssist. It does not provision or invent projects.
func (c Config) DiscoverAccount(ctx context.Context, accessToken string) (AccountMetadata, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return AccountMetadata{}, fmt.Errorf("Antigravity access token is required")
	}
	account, paidTierPresent, err := c.loadCodeAssist(ctx, accessToken, "")
	if err != nil {
		return AccountMetadata{}, err
	}
	if account.ProjectID != "" && !paidTierPresent {
		additional, _, loadErr := c.loadCodeAssist(ctx, accessToken, account.ProjectID)
		err = loadErr
		if err != nil {
			return AccountMetadata{}, err
		}
		account = mergeAccountMetadata(account, additional)
	}
	return account, nil
}

func (c Config) loadCodeAssist(ctx context.Context, accessToken, projectID string) (AccountMetadata, bool, error) {
	endpoint, err := absoluteURL("loadCodeAssist URL", c.endpoints().LoadCodeAssistURL)
	if err != nil {
		return AccountMetadata{}, false, err
	}
	requestPayload := struct {
		ProjectID string `json:"cloudaicompanionProject,omitempty"`
		Metadata  struct {
			IDEType string `json:"ideType"`
		} `json:"metadata"`
	}{ProjectID: projectID}
	requestPayload.Metadata.IDEType = "ANTIGRAVITY"
	body, err := json.Marshal(requestPayload)
	if err != nil {
		return AccountMetadata{}, false, apiError(0, "request", err)
	}
	requestContext, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return AccountMetadata{}, false, apiError(0, "request", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client().Do(request)
	if err != nil {
		return AccountMetadata{}, false, apiError(0, "transport", err)
	}
	defer response.Body.Close()
	raw, err := readBounded(response.Body)
	if err != nil {
		return AccountMetadata{}, false, apiError(response.StatusCode, "invalid_response", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var payload struct {
			Error struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &payload) != nil {
			return AccountMetadata{}, false, apiError(response.StatusCode, fmt.Sprintf("http_%d", response.StatusCode), nil)
		}
		code := strings.TrimSpace(payload.Error.Status)
		if code == "" {
			code = fmt.Sprintf("http_%d", response.StatusCode)
		}
		return AccountMetadata{}, false, apiError(response.StatusCode, controlledCode(code, response.StatusCode), nil)
	}
	var payload *struct {
		ProjectID       string           `json:"cloudaicompanionProject,omitempty"`
		CurrentTier     *Tier            `json:"currentTier,omitempty"`
		PaidTier        *Tier            `json:"paidTier,omitempty"`
		AllowedTiers    []Tier           `json:"allowedTiers,omitempty"`
		IneligibleTiers []IneligibleTier `json:"ineligibleTiers,omitempty"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || payload == nil {
		return AccountMetadata{}, false, apiError(response.StatusCode, "invalid_response", err)
	}
	account := AccountMetadata{
		ProjectID:       strings.TrimSpace(payload.ProjectID),
		CurrentTier:     payload.CurrentTier,
		PaidTier:        payload.PaidTier,
		AllowedTiers:    payload.AllowedTiers,
		IneligibleTiers: payload.IneligibleTiers,
	}
	return account, payload.PaidTier != nil, nil
}

func (c Config) oauthConfig() (browseroauth.Config, error) {
	if strings.TrimSpace(c.ClientID) == "" {
		return browseroauth.Config{}, fmt.Errorf("Antigravity OAuth client ID is required")
	}
	endpoints := c.endpoints()
	if _, err := absoluteURL("token URL", endpoints.TokenURL); err != nil {
		return browseroauth.Config{}, err
	}
	return browseroauth.Config{
		AuthorizeURL:   endpoints.AuthorizeURL,
		TokenURL:       endpoints.TokenURL,
		ClientID:       strings.TrimSpace(c.ClientID),
		ClientSecret:   c.ClientSecret,
		ClientAuthMode: c.ClientAuthMode,
		Scopes:         Scopes(),
		ExtraAuthParams: url.Values{
			"access_type": {"offline"},
			"prompt":      {"consent"},
		},
		HTTPClient: c.HTTPClient,
	}, nil
}

func (c Config) endpoints() Endpoints {
	result := c.Endpoints
	if strings.TrimSpace(result.AuthorizeURL) == "" {
		result.AuthorizeURL = AuthorizeURL
	}
	if strings.TrimSpace(result.TokenURL) == "" {
		result.TokenURL = TokenURL
	}
	if strings.TrimSpace(result.LoadCodeAssistURL) == "" {
		result.LoadCodeAssistURL = LoadCodeAssistURL
	}
	return result
}

func (c Config) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: defaultTimeout}
}

func absoluteURL(name, raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, fmt.Errorf("Antigravity %s must be an absolute URL", name)
	}
	return parsed, nil
}

func redirectURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() {
		return nil, fmt.Errorf("Antigravity redirect URI must be absolute")
	}
	return parsed, nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("loadCodeAssist response exceeded %d bytes", maxResponseBytes)
	}
	return raw, nil
}

func apiError(status int, code string, cause error) *APIError {
	return &APIError{
		StatusCode: status,
		Code:       code,
		cause:      cause,
	}
}

func controlledCode(code string, status int) string {
	code = strings.TrimSpace(code)
	switch code {
	case "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "UNAUTHENTICATED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS":
		return code
	}
	return fmt.Sprintf("http_%d", status)
}

func mergeAccountMetadata(first, second AccountMetadata) AccountMetadata {
	if first.ProjectID != "" {
		second.ProjectID = first.ProjectID
	}
	if second.CurrentTier == nil {
		second.CurrentTier = first.CurrentTier
	}
	if second.PaidTier == nil {
		second.PaidTier = first.PaidTier
	}
	if second.AllowedTiers == nil {
		second.AllowedTiers = first.AllowedTiers
	}
	if second.IneligibleTiers == nil {
		second.IneligibleTiers = first.IneligibleTiers
	}
	return second
}

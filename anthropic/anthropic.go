// Package anthropic validates Anthropic setup tokens and applies the correct
// request authentication headers without discovering or persisting credentials.
package anthropic

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

const (
	SetupTokenPrefix = "sk-ant-oat01-"
	OAuthBeta        = "oauth-2025-04-20"
	minTokenLength   = 80
)

// CredentialKind describes the Anthropic authentication scheme selected for a
// caller-supplied credential.
type CredentialKind string

const (
	CredentialAPIKey     CredentialKind = "api_key"
	CredentialSetupToken CredentialKind = "setup_token"
)

// ValidateSetupToken enforces the stable setup-token prefix and conservative
// character/length constraints without attempting token discovery.
func ValidateSetupToken(token string) error {
	if token != strings.TrimSpace(token) {
		return fmt.Errorf("Anthropic setup token must not contain surrounding whitespace")
	}
	if !strings.HasPrefix(token, SetupTokenPrefix) {
		return fmt.Errorf("Anthropic setup token must start with %q", SetupTokenPrefix)
	}
	if len(token) < minTokenLength {
		return fmt.Errorf("Anthropic setup token is too short")
	}
	suffix := strings.TrimPrefix(token, SetupTokenPrefix)
	for _, char := range suffix {
		if char > unicode.MaxASCII || !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-') {
			return fmt.Errorf("Anthropic setup token contains invalid characters")
		}
	}
	return nil
}

// Kind validates and classifies a caller-supplied Anthropic credential.
func Kind(credential string) (CredentialKind, error) {
	trimmed := strings.TrimSpace(credential)
	if trimmed == "" {
		return "", fmt.Errorf("Anthropic credential is required")
	}
	if strings.HasPrefix(trimmed, "sk-ant-oat") {
		if err := ValidateSetupToken(credential); err != nil {
			return "", err
		}
		return CredentialSetupToken, nil
	}
	return CredentialAPIKey, nil
}

// HeaderSource applies Anthropic authentication for one caller-supplied
// credential. Setup tokens use OAuth bearer authentication and the required
// beta marker; all other non-empty credentials use x-api-key.
type HeaderSource struct {
	credential string
	kind       CredentialKind
}

// NewHeaderSource validates a credential and returns its reusable header source.
func NewHeaderSource(credential string) (HeaderSource, error) {
	kind, err := Kind(credential)
	if err != nil {
		return HeaderSource{}, err
	}
	credential = strings.TrimSpace(credential)
	return HeaderSource{credential: credential, kind: kind}, nil
}

// Kind reports which request authentication scheme the source applies.
func (s HeaderSource) Kind() CredentialKind { return s.kind }

// Apply implements auth.HeaderSource.
func (s HeaderSource) Apply(_ context.Context, request *http.Request) error {
	if request == nil {
		return fmt.Errorf("Anthropic request is required")
	}
	if s.credential == "" {
		return fmt.Errorf("Anthropic credential is required")
	}
	request.Header.Del("Authorization")
	request.Header.Del("x-api-key")
	if s.kind == CredentialSetupToken {
		request.Header.Set("Authorization", "Bearer "+s.credential)
		addHeaderValue(request.Header, "anthropic-beta", OAuthBeta)
		return nil
	}
	request.Header.Set("x-api-key", s.credential)
	removeHeaderValue(request.Header, "anthropic-beta", OAuthBeta)
	return nil
}

func addHeaderValue(header http.Header, name, wanted string) {
	for _, line := range header.Values(name) {
		for value := range strings.SplitSeq(line, ",") {
			if strings.TrimSpace(value) == wanted {
				return
			}
		}
	}
	header.Add(name, wanted)
}

func removeHeaderValue(header http.Header, name, unwanted string) {
	var kept []string
	for _, line := range header.Values(name) {
		for value := range strings.SplitSeq(line, ",") {
			value = strings.TrimSpace(value)
			if value != "" && value != unwanted {
				kept = append(kept, value)
			}
		}
	}
	header.Del(name)
	for _, value := range kept {
		header.Add(name, value)
	}
}

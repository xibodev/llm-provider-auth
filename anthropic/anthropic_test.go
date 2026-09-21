package anthropic

import (
	"context"
	"net/http"
	"strings"
	"testing"

	auth "github.com/xibodev/llm-provider-auth"
)

func TestValidateSetupToken(t *testing.T) {
	valid := SetupTokenPrefix + strings.Repeat("aB0_-", 4)
	if err := ValidateSetupToken(valid); err != nil {
		t.Fatalf("valid setup token rejected: %v", err)
	}
	for name, token := range map[string]string{
		"wrong prefix": "sk-ant-api01-" + strings.Repeat("a", 40),
		"short":        SetupTokenPrefix + "short",
		"whitespace":   " " + valid,
		"invalid char": SetupTokenPrefix + strings.Repeat("a", 20) + ".",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSetupToken(token); err == nil {
				t.Fatalf("invalid setup token accepted: %q", token)
			}
		})
	}
}

func TestHeaderSourceUsesSetupTokenBearerAndOAuthBeta(t *testing.T) {
	token := SetupTokenPrefix + strings.Repeat("a", 32)
	source, err := NewHeaderSource(token)
	if err != nil {
		t.Fatal(err)
	}
	var interfaceCheck auth.HeaderSource = source
	request, _ := http.NewRequest(http.MethodPost, "https://api.example.test/messages", nil)
	request.Header.Set("x-api-key", "stale-api-key")
	request.Header.Add("anthropic-beta", "other-feature")
	request.Header.Add("anthropic-beta", OAuthBeta)
	if err := interfaceCheck.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if source.Kind() != CredentialSetupToken || request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("x-api-key") != "" || countHeaderValue(request.Header, "anthropic-beta", OAuthBeta) != 1 || countHeaderValue(request.Header, "anthropic-beta", "other-feature") != 1 {
		t.Fatalf("kind=%q headers=%v", source.Kind(), request.Header)
	}
}

func TestHeaderSourceUsesAPIKeyAndRemovesOAuthBeta(t *testing.T) {
	source, err := NewHeaderSource("fixture-api-key")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://api.example.test/messages", nil)
	request.Header.Set("Authorization", "Bearer stale-token")
	request.Header.Add("anthropic-beta", "other-feature,"+OAuthBeta)
	if err := source.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if source.Kind() != CredentialAPIKey || request.Header.Get("x-api-key") != "fixture-api-key" || request.Header.Get("Authorization") != "" || countHeaderValue(request.Header, "anthropic-beta", OAuthBeta) != 0 || countHeaderValue(request.Header, "anthropic-beta", "other-feature") != 1 {
		t.Fatalf("kind=%q headers=%v", source.Kind(), request.Header)
	}
}

func TestMalformedSetupTokenIsNotTreatedAsAPIKey(t *testing.T) {
	for _, token := range []string{SetupTokenPrefix + "short", " " + SetupTokenPrefix + strings.Repeat("a", 32)} {
		if _, err := NewHeaderSource(token); err == nil {
			t.Fatalf("malformed setup token was accepted as an API key: %q", token)
		}
	}
}

func countHeaderValue(header http.Header, name, wanted string) int {
	count := 0
	for _, line := range header.Values(name) {
		for value := range strings.SplitSeq(line, ",") {
			if strings.TrimSpace(value) == wanted {
				count++
			}
		}
	}
	return count
}

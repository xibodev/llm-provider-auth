package codex

import (
	"fmt"
	"testing"

	"github.com/xibodev/llm-provider-auth/tokenstore"
)

func TestRefreshErrorTerminalClassification(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]bool{
		"invalid_grant": true, "refresh_token_reused": true, "expired_token": true,
		"server_error": false, "missing_refresh_token": false, "": false,
	} {
		err := fmt.Errorf("refresh: %w", &RefreshError{StatusCode: 400, Code: code})
		if got := tokenstore.IsTerminal(err); got != want {
			t.Errorf("code %q: terminal=%v, want %v", code, got, want)
		}
	}
	var missing *RefreshError
	if missing.Terminal() {
		t.Error("nil RefreshError reported terminal")
	}
}

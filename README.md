# llm-provider-auth

Modular Go credential resolvers, OAuth flows, and session token brokers for LLM providers.

## Modules & Drivers

Each driver is an independent subpackage with zero unnecessary dependencies:

- **`gcp`**: Google Cloud Service Account JWT RS256 token minter. **Zero Google Cloud SDK dependencies** (pure standard library `crypto/rsa` and `crypto/x509`).
- **`copilot`**: GitHub Copilot OAuth Device Flow (`/login/device/code`), session exchange, token cache, and CLI bridge.
- **`codex`**: OpenAI ChatGPT/Codex OAuth session flow, PKCE exchange, and automatic token refresh.
- **`browseroauth`**: Storage-neutral browser OAuth primitives with caller-supplied endpoints and client configuration, PKCE S256, state generation, code exchange, and refresh.
- **`antigravity`**: Storage-neutral Google Antigravity OAuth flow and typed Cloud Code Assist account/project discovery, built on `browseroauth`.
- **`anthropic`**: Anthropic setup-token validation and request-header selection for setup tokens or API keys.
- **`tokenstore`**: A storage contract and refresh coordinator that spend a rotating refresh token exactly once, even when several processes share one credential store. It includes an in-memory reference store and the `tokenstore/storetest` conformance suite.

No package reads environment variables or runs an `init` function; callers
supply all configuration explicitly. An architecture test enforces this.

## Installation

```bash
# Core interfaces
go get github.com/xibodev/llm-provider-auth

# Or install specific drivers directly
go get github.com/xibodev/llm-provider-auth/gcp
go get github.com/xibodev/llm-provider-auth/copilot
go get github.com/xibodev/llm-provider-auth/codex
go get github.com/xibodev/llm-provider-auth/browseroauth
go get github.com/xibodev/llm-provider-auth/antigravity
go get github.com/xibodev/llm-provider-auth/anthropic
go get github.com/xibodev/llm-provider-auth/tokenstore
```

`browseroauth` deliberately does not open a browser, run a callback listener, or
persist tokens. The caller owns those concerns and supplies the redirect URI,
OAuth endpoints, client credentials, scopes, and any provider-specific
authorization or token parameters.

`browseroauth.Config.ClientAuthMode` is required. Use `public_pkce` for public
clients, which require PKCE and never send a client secret, or
`client_secret_post` for confidential clients, which require the secret and
send it in token request bodies. Unknown and zero-valued modes are rejected.

`antigravity` likewise performs no browser, listener, storage, UI, environment,
or file operations. The caller supplies its Google OAuth client ID, client
secret when required by its explicit client auth mode, and redirect URI. The
package supplies canonical scopes and endpoints, requests offline consent,
exchanges and refreshes tokens, and discovers only the Cloud Code Assist project
returned by Google. `CompleteAuthorization` validates callback state before
exchanging the authorization code.

## Quick Start

### Google Cloud Service Account (Vertex AI / Gemini)

```go
import "github.com/xibodev/llm-provider-auth/gcp"

// Parse a service account key read from a file or a secret manager.
cred, err := gcp.Parse(keyJSON)
if err != nil {
    log.Fatal(err)
}

// Keep one TokenCache for the process. It owns its cached tokens, HTTP client
// and clock, and mints a new token shortly before the cached one expires.
var tokens gcp.TokenCache
token, err := tokens.AccessToken(cred, gcp.CloudPlatformScope)
request.Header.Set("Authorization", "Bearer "+token)
```

### GitHub Copilot Device Code Flow & Session Exchange

```go
import "github.com/xibodev/llm-provider-auth/copilot"

client := copilot.New(copilot.Config{
    CacheDir:   cacheDir, // empty disables the disk cache
    UseGhCLI:   true,     // allow `gh auth token` as the last token source
    AllowProxy: true,     // explicit opt-in; read copilot.TOSWarning first
})

// Start device login
flow, err := client.StartDeviceFlow()
fmt.Printf("Visit %s and enter code: %s\n", flow.VerificationURI, flow.UserCode)

// Poll every flow.Interval seconds until authorized
result := client.PollDeviceFlowTokenOnce(flow.DeviceCode)
if result.Status == "authorized" {
    session, err := client.GetSessionForOAuth(result.AccessToken, false)
    // Send session.Token as a Bearer token to session.ChatBaseURL.
}
```

`copilot` reads no environment variables and keeps no process-wide state.
Share one `Client` per configuration: it serializes concurrent polls of one
device code. A product whose settings change at runtime uses
`copilot.NewDynamic(func() copilot.Config { ... })`, and each operation reads
one snapshot. Errors state only what went wrong; match `ErrProxyDisabled`,
`ErrNoOAuthToken`, or `ErrOAuthTokenRejected` with `errors.Is` to add guidance
that names your own settings.

Earlier releases read `GITHUB_COPILOT_OAUTH_TOKEN`,
`LLMGW_GITHUB_COPILOT_OAUTH_TOKEN`, `LLMGW_GITHUB_COPILOT_CACHE_DIR`, and
`LLMGW_EXPERIMENTAL_COPILOT_PROVIDER`, defaulted the cache to
`~/.llmgw/cache`, and enabled the gh CLI. A product that relied on that behavior
maps those values onto `Config.OAuthToken`, `Config.CacheDir`,
`Config.AllowProxy`, and `Config.UseGhCLI` itself.

## Refresh-safe credential storage

Providers such as OpenAI rotate refresh tokens and detect reuse: presenting an
old refresh token can revoke the whole grant. `tokenstore` prevents two
goroutines or processes from spending the same refresh token.

A store implements `tokenstore.Store`:

- `Load`, `Save`, `ReplaceIfCurrent`, and `RevokeIfCurrent`, with an opaque
  revision assigned on every write. Conditional writes return `ErrConflict`
  when the revision moved.
- A required `Lease(ctx, key)`. The lease must be exclusive across every
  process sharing the store. File-backed stores should hold an OS advisory
  lock on a separate lock file, because a data file rewritten by
  temp-file-and-rename loses any lock held on it.

`tokenstore.Coordinator` combines the two guarantees:

```go
coordinator, err := tokenstore.NewCoordinator(store, func(ctx context.Context, current tokenstore.Record) (tokenstore.Record, error) {
    tokens, err := codex.Refresh(clientID, current.RefreshToken)
    if err != nil {
        return tokenstore.Record{}, err // *codex.RefreshError reports terminal grants
    }
    refreshed := tokenstore.Record{
        AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
        IDToken: tokens.IDToken, TokenType: tokens.TokenType, AccountID: tokens.AccountID,
    }
    if tokens.ExpiresAt > 0 {
        refreshed.Expiry = time.Unix(tokens.ExpiresAt, 0)
    }
    return refreshed, nil
})

record, err := coordinator.Token(ctx, "openai")        // refreshes near expiry
record, err = coordinator.Rejected(ctx, "openai", record) // after an upstream 401
```

The coordinator provides these guarantees:

- It refreshes under the lease, then re-reads, so a waiter uses a refresh that
  another holder already completed.
- It never lets a refresh change the bound `AccountID`.
- It revokes the credential when the provider rejects the grant permanently.
  `IsTerminal` classifies the refresh error.
- It never overwrites a login that lands during a refresh.
- It keeps token material out of errors and out of `Record`'s `String`,
  `GoString`, and `slog` output.

Every store implementation should run the conformance suite:

```go
func TestConformance(t *testing.T) {
    storetest.Run(t, func(t *testing.T) storetest.Opener {
        path := filepath.Join(t.TempDir(), "auth.json")
        return func(t *testing.T) tokenstore.Store { return mystore.Open(path) }
    })
}
```

## License

MIT

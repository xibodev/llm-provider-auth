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

// Parse service account JSON (from file or secret manager)
cred, err := gcp.ParseCredential(keyJSON)
if err != nil {
    log.Fatal(err)
}

// Mint OAuth2 access token with auto-refresh and memory cache
token, err := gcp.TokenForCredential(ctx, cred, gcp.CloudPlatformScope)
fmt.Println("Bearer:", token.AccessToken)
```

### GitHub Copilot Device Code Flow & Session Exchange

```go
import "github.com/xibodev/llm-provider-auth/copilot"

// Start device login
flow, err := copilot.StartDeviceFlow()
fmt.Printf("Visit %s and enter code: %s\n", flow.VerificationURI, flow.UserCode)

// Poll until authorized
result := copilot.PollDeviceFlowTokenOnce(flow.DeviceCode)
if result.Status == "authorized" {
    session, err := copilot.ResolveSession()
    fmt.Println("Copilot Token:", session.Token)
}
```

## License

MIT

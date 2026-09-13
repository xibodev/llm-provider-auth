# llm-provider-auth

Modular Go credential resolvers, OAuth device flows, and session token brokers for LLM providers.

## Modules & Drivers

Each driver is an independent subpackage with zero unnecessary dependencies:

- **`gcp`**: Google Cloud Service Account JWT RS256 token minter. **Zero Google Cloud SDK dependencies** (pure standard library `crypto/rsa` and `crypto/x509`).
- **`copilot`**: GitHub Copilot OAuth Device Flow (`/login/device/code`), session exchange, token cache, and CLI bridge.
- **`codex`**: OpenAI ChatGPT/Codex OAuth session flow, PKCE exchange, and automatic token refresh.

## Installation

```bash
# Core interfaces
go get github.com/xibodev/llm-provider-auth

# Or install specific drivers directly
go get github.com/xibodev/llm-provider-auth/gcp
go get github.com/xibodev/llm-provider-auth/copilot
go get github.com/xibodev/llm-provider-auth/codex
```

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

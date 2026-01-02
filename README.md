# openai-auth

A Rust library for OpenAI/ChatGPT OAuth 2.0 authentication with PKCE support.

Provides both **synchronous** (blocking) and **asynchronous** (runtime-agnostic) APIs for authenticating with OpenAI's OAuth 2.0 endpoints.

## Features

- ✅ **Sync & Async APIs** - Choose blocking or async based on your needs
- ✅ **Runtime Agnostic** - Async API works with tokio, async-std, smol, etc.
- ✅ **PKCE Support** - Secure SHA-256 PKCE authentication flow  
- ✅ **Fully Configurable** - Custom client IDs, endpoints, redirect URIs, ports
- ✅ **Browser Integration** - Auto-open browser for authorization (default enabled)
- ✅ **Callback Server** - Optional local server for automatic callback handling
- ✅ **JWT Utilities** - Extract ChatGPT account ID from access tokens
- ✅ **API Key Exchange** - Exchange id_token for OpenAI API key (Codex CLI flow)
- ✅ **No Token Storage** - You control how/where to persist tokens

## Installation

```toml
[dependencies]
openai-auth = "0.1"
```

## Quick Start (Async API - Default)

```rust
use openai_auth::{OAuthClient, OAuthConfig};

#[tokio::main]  // or async-std, smol, etc.
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow()?;
    
    println!("Visit: {}", flow.authorization_url);
    
    let tokens = client.exchange_code("code", &flow.pkce_verifier).await?;
    println!("Got access token!");
    
    // Later, refresh if needed
    if tokens.is_expired() {
        let new_tokens = client.refresh_token(&tokens.refresh_token).await?;
    }
    
    Ok(())
}
```

## Quick Start (Blocking API)

```rust
use openai_auth::{blocking::OAuthClient, OAuthConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow()?;
    
    println!("Visit: {}", flow.authorization_url);
    // User visits URL and gets authorization code...
    
    let tokens = client.exchange_code("code", &flow.pkce_verifier)?;
    println!("Got access token!");
    
    Ok(())
}
```

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `async` | Asynchronous API (runtime-agnostic) | ✅ Yes |
| `blocking` | Synchronous/blocking API | ❌ No |
| `browser` | Auto-open browser for authorization | ✅ Yes |
| `callback-server` | Local server for OAuth callback (requires tokio) | ❌ No |
| `full` | Enable all features | ❌ No |

### Enable blocking API:

```toml
[dependencies]
openai-auth = { version = "0.1", features = ["blocking"] }
```

### Enable callback server (full automation):

```toml
[dependencies]
openai-auth = { version = "0.1", features = ["callback-server"] }
tokio = { version = "1", features = ["full"] }
```

## Custom Configuration

```rust
use openai_auth::{OAuthClient, OAuthConfig};

let config = OAuthConfig::builder()
    .client_id("my-client-id")
    .redirect_port(8080)  // Custom port
    .build();

let client = OAuthClient::new(config)?;
```

## Examples

See the `examples/` directory for complete working examples:

- `01_basic_manual_sync.rs` - Basic sync flow with manual code entry
- `02_with_browser_sync.rs` - Sync with browser auto-open
- `03_basic_manual_async.rs` - Basic async flow
- `04_callback_server.rs` - Full automation with callback server
- `05_id_token_sync.rs` - Exchange the code for an API key (blocking)
- `06_callback_custom_html.rs` - Callback server with custom HTML responses

Run examples with:

```bash
cargo run --example 01_basic_manual_sync
cargo run --example 04_callback_server --features full
cargo run --example 05_id_token_sync --features blocking
cargo run --example 06_callback_custom_html --features full
```

## Custom Callback HTML

You can provide a custom HTML responder for the callback server:

```rust
use openai_auth::{run_callback_server_with_html, CallbackEvent};

let html = |event: CallbackEvent| match event {
    CallbackEvent::Success { .. } => "<html>OK</html>".to_string(),
    CallbackEvent::Error { reason } => format!("<html>Error: {}</html>", reason),
    CallbackEvent::StateMismatch => "<html>State mismatch</html>".to_string(),
    CallbackEvent::MissingCode => "<html>Missing code</html>".to_string(),
};

let code_future = run_callback_server_with_html(1455, &flow.state, html);
```

## Token Storage

This library intentionally does **not** handle token persistence. You should store tokens securely based on your application's needs.

Recommended approaches:
- **System Keychain**: Use [`keyring`](https://crates.io/crates/keyring) crate
- **Encrypted Files**: Encrypt tokens before writing to disk
- **Environment Variables**: For development/testing only

See `examples/08_keyring_storage_sync.rs` for a secure storage example.

## API Overview

### Async API (default, runtime-agnostic)

```rust
use openai_auth::OAuthClient;

let client = OAuthClient::new(config)?;

// Start flow (sync - no I/O needed)
let flow = client.start_flow()?;

// Async methods
let tokens = client.exchange_code(code, &flow.pkce_verifier).await?;
let new_tokens = client.refresh_token(&tokens.refresh_token).await?;

// Extract account ID from JWT (sync)
let account_id = client.extract_account_id(&tokens.access_token)?;
```

### API Key Exchange (Codex CLI flow)

```rust
use openai_auth::OAuthClient;

let client = OAuthClient::new(config)?;
let flow = client.start_flow()?;
let tokens = client.exchange_code_for_api_key(code, &flow.pkce_verifier).await?;

// Use tokens.api_key for OpenAI API requests
let api_key = tokens.api_key.as_deref();
```

### Blocking API

```rust
use openai_auth::blocking::OAuthClient;

let client = OAuthClient::new(config)?;

// Start flow (generates PKCE, returns auth URL)
let flow = client.start_flow()?;

// Exchange code for tokens
let tokens = client.exchange_code(code, &flow.pkce_verifier)?;

// Refresh expired tokens
let new_tokens = client.refresh_token(&tokens.refresh_token)?;
```

### Browser Integration

```rust
use openai_auth::open_browser;

let flow = client.start_flow()?;
open_browser(&flow.authorization_url)?;  // Opens user's default browser
```

### Callback Server (requires `callback-server` feature)

```rust
use openai_auth::{OAuthClient, run_callback_server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = OAuthClient::new(config)?;
    let flow = client.start_flow()?;
    
    // Start server and wait for callback
    let code = run_callback_server(1455, &flow.state).await?;
    let tokens = client.exchange_code(&code, &flow.pkce_verifier).await?;
    
    Ok(())
}
```

## Requirements

- **Rust 1.70+**
- **ChatGPT Plus or Pro subscription** (for OAuth access)

## License

MIT

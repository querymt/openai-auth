//! Full automatic OAuth flow with local callback server
//!
//! This example demonstrates the most convenient flow: browser auto-opens
//! and a local server automatically captures the authorization code.
//!
//! Note: Requires tokio runtime.
//!
//! Required features: `async`, `browser`, `callback-server` (or use `full`)
//!
//! Run with: cargo run --example 04_callback_server

use openai_auth::{open_browser, run_callback_server, OAuthClient, OAuthConfig, Result};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== OpenAI OAuth - Automatic with Callback Server ===\n");

    let config = OAuthConfig::builder().redirect_port(1455).build();

    let client = OAuthClient::new(config)?;
    let flow = client.start_flow()?;

    println!("🌐 Opening browser and starting callback server...");

    // Start callback server
    let code_future = run_callback_server(1455, &flow.state);

    // Open browser
    match open_browser(&flow.authorization_url) {
        Ok(_) => println!("✅ Browser opened! Waiting for authorization..."),
        Err(e) => {
            println!("⚠️  Could not open browser: {}", e);
            println!("Please manually visit: {}", flow.authorization_url);
        }
    }

    // Wait for callback
    println!("\n⏳ Waiting for OAuth callback...");
    let code = code_future.await?;
    println!("✅ Received authorization code!");

    // Exchange for tokens
    println!("\n🔄 Exchanging code for tokens...");
    let tokens = client.exchange_code(&code, &flow.pkce_verifier).await?;

    println!("\n✅ Success!");
    println!(
        "Access token: {}...",
        &tokens.access_token[..30.min(tokens.access_token.len())]
    );
    println!("Expires in: {:?}", tokens.expires_in());

    if let Ok(account_id) = client.extract_account_id(&tokens.access_token) {
        println!("ChatGPT Account ID: {}", account_id);
    }

    Ok(())
}

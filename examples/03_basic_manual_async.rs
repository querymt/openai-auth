//! Basic OAuth flow with manual code entry (asynchronous)
//!
//! This example demonstrates the async API. Works with any async runtime
//! (tokio, async-std, smol, etc.). This example uses tokio.
//!
//! Required features: `async`
//!
//! Run with: cargo run --example 03_basic_manual_async

use openai_auth::{OAuthClient, OAuthConfig};
use std::io::{self, Write};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== OpenAI OAuth - Basic Manual Flow (Async) ===\n");

    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow()?;

    println!("📋 Please visit this URL to authorize:");
    println!("{}\n", flow.authorization_url);

    print!("Paste the authorization code here: ");
    io::stdout().flush()?;

    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let code = code.trim();

    println!("\n🔄 Exchanging code for tokens...");
    // Note: No more _async suffix!
    let tokens = client.exchange_code(code, &flow.pkce_verifier).await?;

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

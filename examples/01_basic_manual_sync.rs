//! Basic OAuth flow with manual code entry (synchronous/blocking)
//!
//! This example demonstrates the simplest OAuth flow where the user
//! manually copies and pastes the authorization code. Uses blocking I/O,
//! no async runtime required.
//!
//! Required features: `blocking`
//!
//! Run with: cargo run --example 01_basic_manual_sync

use openai_auth::{OAuthConfig, blocking::OAuthClient};
use std::io::{self, Write};

fn main() -> anyhow::Result<()> {
    println!("=== OpenAI OAuth - Basic Manual Flow (Sync) ===\n");

    // Create client with default configuration
    let client = OAuthClient::new(OAuthConfig::default())?;

    // Step 1: Start OAuth flow
    println!("Starting OAuth flow...");
    let flow = client.start_flow()?;

    println!("\n📋 Please visit this URL to authorize:");
    println!("{}\n", flow.authorization_url);

    // Step 2: Get code from user
    print!("Paste the authorization code here: ");
    io::stdout().flush()?;

    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let code = code.trim();

    // Step 3: Exchange code for tokens
    println!("\n🔄 Exchanging code for tokens...");
    let tokens = client.exchange_code(code, &flow.pkce_verifier)?;

    println!("\n✅ Success!");
    println!(
        "Access token: {}...",
        &tokens.access_token[..30.min(tokens.access_token.len())]
    );
    println!(
        "Refresh token: {}...",
        &tokens.refresh_token[..30.min(tokens.refresh_token.len())]
    );
    println!("Expires in: {:?}", tokens.expires_in());

    // Step 4: Extract account ID from JWT
    println!("\n🔍 Extracting account ID from token...");
    match client.extract_account_id(&tokens.access_token) {
        Ok(account_id) => println!("ChatGPT Account ID: {}", account_id),
        Err(e) => println!("⚠️  Could not extract account ID: {}", e),
    }

    println!("\n💡 Tip: Save these tokens securely to avoid re-authentication!");
    println!("   See example 08_keyring_storage_sync for a secure storage solution.");

    Ok(())
}

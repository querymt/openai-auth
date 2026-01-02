//! OAuth flow with automatic browser opening (synchronous)
//!
//! This example demonstrates using the browser feature to automatically
//! open the authorization URL in the user's default browser.
//!
//! Required features: `blocking`, `browser`
//!
//! Run with: cargo run --example 02_with_browser_sync

use openai_auth::{OAuthConfig, blocking::OAuthClient, open_browser};
use std::io::{self, Write};

fn main() -> anyhow::Result<()> {
    println!("=== OpenAI OAuth - With Browser Auto-Open (Sync) ===\n");

    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow()?;

    println!("🌐 Opening browser for authorization...");

    // Automatically open browser
    match open_browser(&flow.authorization_url) {
        Ok(_) => println!("✅ Browser opened! Please authorize in your browser."),
        Err(e) => {
            println!("⚠️  Could not open browser: {}", e);
            println!("Please manually visit: {}", flow.authorization_url);
        }
    }

    print!("\nPaste the authorization code here: ");
    io::stdout().flush()?;

    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let code = code.trim();

    println!("\n🔄 Exchanging code for tokens...");
    let tokens = client.exchange_code(code, &flow.pkce_verifier)?;

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

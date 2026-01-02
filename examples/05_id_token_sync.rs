//! Exchange the authorization code for an OpenAI API key (synchronous/blocking)
//!
//! This example demonstrates using `exchange_code_for_api_key` to obtain
//! an API key in the same flow.
//!
//! Required features: `blocking`
//!
//! Run with: cargo run --example 05_id_token_sync

use openai_auth::{OAuthConfig, blocking::OAuthClient};
use std::io::{self, Write};

fn main() -> anyhow::Result<()> {
    println!("=== OpenAI OAuth - API Key Exchange (Sync) ===\n");

    let client = OAuthClient::new(OAuthConfig::default())?;
    let flow = client.start_flow()?;

    println!("📋 Please visit this URL to authorize:");
    println!("{}\n", flow.authorization_url);

    print!("Paste the authorization code here: ");
    io::stdout().flush()?;

    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let code = code.trim();

    println!("\n🔄 Exchanging code for tokens + API key...");
    let tokens = client.exchange_code_for_api_key(code, &flow.pkce_verifier)?;

    println!("\n✅ Success!");
    println!(
        "Access token: {}...",
        &tokens.access_token[..30.min(tokens.access_token.len())]
    );
    if let Some(api_key) = tokens.api_key.as_deref() {
        println!("API key: {}...", &api_key[..30.min(api_key.len())]);
    }
    println!("Expires in: {:?}", tokens.expires_in());

    Ok(())
}

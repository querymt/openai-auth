//! OAuth callback server with custom HTML responses
//!
//! This example demonstrates customizing the HTML shown in the browser
//! when the OAuth callback completes.
//!
//! Required features: `async`, `browser`, `callback-server` (or use `full`)
//!
//! Run with: cargo run --example 06_callback_custom_html --features full

use openai_auth::{
    CallbackEvent, OAuthClient, OAuthConfig, Result, open_browser, run_callback_server_with_html,
};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== OpenAI OAuth - Custom Callback HTML ===\n");

    let config = OAuthConfig::builder().redirect_port(1455).build();
    let client = OAuthClient::new(config)?;
    let flow = client.start_flow()?;

    println!("🌐 Opening browser and starting callback server...");

    let html = |event: CallbackEvent| match event {
        CallbackEvent::Success { .. } => r#"
            <html>
                <head><title>All set</title></head>
                <body>
                    <h1>Success</h1>
                    <p>You can return to the app.</p>
                </body>
            </html>
            "#
        .to_string(),
        CallbackEvent::Error { reason } => format!(
            r#"
            <html>
                <head><title>Authorization Failed</title></head>
                <body>
                    <h1>Authorization Failed</h1>
                    <p>Error: {}</p>
                </body>
            </html>
            "#,
            reason
        ),
        CallbackEvent::StateMismatch => r#"
            <html>
                <head><title>State mismatch</title></head>
                <body>
                    <h1>State mismatch</h1>
                    <p>Please restart the flow.</p>
                </body>
            </html>
            "#
        .to_string(),
        CallbackEvent::MissingCode => r#"
            <html>
                <head><title>Missing code</title></head>
                <body>
                    <h1>Missing code</h1>
                    <p>Please try again.</p>
                </body>
            </html>
            "#
        .to_string(),
    };

    let code_future = run_callback_server_with_html(1455, &flow.state, html);

    match open_browser(&flow.authorization_url) {
        Ok(_) => println!("✅ Browser opened! Waiting for authorization..."),
        Err(e) => {
            println!("⚠️  Could not open browser: {}", e);
            println!("Please manually visit: {}", flow.authorization_url);
        }
    }

    println!("\n⏳ Waiting for OAuth callback...");
    let code = code_future.await?;
    println!("✅ Received authorization code!");

    println!("\n🔄 Exchanging code for tokens...");
    let tokens = client.exchange_code(&code, &flow.pkce_verifier).await?;

    println!("\n✅ Success!");
    println!(
        "Access token: {}...",
        &tokens.access_token[..30.min(tokens.access_token.len())]
    );
    if let Some(api_key) = tokens.api_key.as_deref() {
        println!("API key: {}...", &api_key[..30.min(api_key.len())]);
    }
    println!("Expires in: {:?}", tokens.expires_in());

    if let Ok(account_id) = client.extract_account_id(&tokens.access_token) {
        println!("ChatGPT Account ID: {}", account_id);
    }

    Ok(())
}

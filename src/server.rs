use std::sync::{Arc, Mutex};
use tiny_http::{Request, Response, Server};
use tokio::sync::oneshot;

use crate::{OpenAIAuthError, Result};

#[derive(Debug)]
struct CallbackData {
    code: String,
    _state: String,
}

struct ServerState {
    tx: Mutex<Option<oneshot::Sender<Result<CallbackData>>>>,
    expected_state: String,
    html_responder: Arc<dyn Fn(CallbackEvent) -> String + Send + Sync>,
}

/// Callback events for customizing the HTML response.
#[derive(Debug, Clone)]
pub enum CallbackEvent {
    Success { code: String },
    Error { reason: String },
    StateMismatch,
    MissingCode,
}

/// Run a local OAuth callback server
///
/// This starts a local HTTP server that listens for the OAuth callback.
/// When the callback is received, it extracts the authorization code and
/// returns it.
///
/// **Note:** This feature requires tokio and is only available when the
/// `callback-server` feature is enabled.
///
/// # Arguments
///
/// * `port` - The port to listen on (e.g., 1455)
/// * `expected_state` - The CSRF state token to validate against
///
/// # Returns
///
/// The authorization code from the callback
///
/// # Errors
///
/// Returns an error if:
/// - The server fails to start
/// - An OAuth error is received
/// - The state token doesn't match
/// - The callback times out
///
/// # Example
///
/// ```no_run
/// use openai_auth::{OAuthClient, OAuthConfig, run_callback_server};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = OAuthClient::new(OAuthConfig::default())?;
/// let flow = client.start_flow()?;
///
/// // Start callback server in background
/// let code_future = run_callback_server(1455, &flow.state);
///
/// println!("Visit: {}", flow.authorization_url);
///
/// // Wait for callback
/// let code = code_future.await?;
/// let tokens = client.exchange_code(&code, &flow.pkce_verifier).await?;
/// # Ok(())
/// # }
/// ```
pub async fn run_callback_server(port: u16, expected_state: &str) -> Result<String> {
    run_callback_server_with_html(port, expected_state, default_callback_html).await
}

/// Run a local OAuth callback server with a custom HTML responder.
///
/// The responder receives a `CallbackEvent` describing the outcome and
/// should return the HTML to display to the user.
pub async fn run_callback_server_with_html(
    port: u16,
    expected_state: &str,
    html_responder: impl Fn(CallbackEvent) -> String + Send + Sync + 'static,
) -> Result<String> {
    let (tx, rx) = oneshot::channel();

    let state = Arc::new(ServerState {
        tx: Mutex::new(Some(tx)),
        expected_state: expected_state.to_string(),
        html_responder: Arc::new(html_responder),
    });

    let addr = format!("127.0.0.1:{}", port);

    // Spawn blocking task for tiny_http server
    tokio::task::spawn_blocking(move || run_sync_server(&addr, state));

    // Wait for callback
    match rx.await {
        Ok(Ok(callback_data)) => Ok(callback_data.code),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(OpenAIAuthError::CallbackServer(
            "Server shut down unexpectedly".to_string(),
        )),
    }
}

fn run_sync_server(addr: &str, state: Arc<ServerState>) -> Result<()> {
    let server = Server::http(addr).map_err(|e| {
        OpenAIAuthError::CallbackServer(format!("Failed to bind to {}: {}", addr, e))
    })?;

    for request in server.incoming_requests() {
        let url = request.url();

        // Only handle /auth/callback requests
        if url.starts_with("/auth/callback") {
            let should_stop = handle_callback_request(request, &state);
            if should_stop {
                break;
            }
        } else {
            // Return 404 for other paths
            let response = Response::from_string("Not Found").with_status_code(404);
            let _ = request.respond(response);
        }
    }

    Ok(())
}

fn handle_callback_request(request: Request, state: &Arc<ServerState>) -> bool {
    // Parse query parameters from URL
    let url = request.url();
    let query_str = url.split('?').nth(1).unwrap_or("");
    let params = querystring::querify(query_str);

    // Extract parameters
    let code = params
        .iter()
        .find(|(k, _)| *k == "code")
        .map(|(_, v)| v.to_string());
    let received_state = params
        .iter()
        .find(|(k, _)| *k == "state")
        .map(|(_, v)| v.to_string());
    let error = params
        .iter()
        .find(|(k, _)| *k == "error")
        .map(|(_, v)| v.to_string());

    // Process the callback and generate response
    let (html, should_stop) = process_callback(code, received_state, error, state);

    // Send HTML response
    let response = Response::from_string(html).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
            .unwrap(),
    );

    let _ = request.respond(response);
    should_stop
}

fn process_callback(
    code: Option<String>,
    received_state: Option<String>,
    error: Option<String>,
    state: &Arc<ServerState>,
) -> (String, bool) {
    // Check for OAuth errors
    if let Some(error) = error {
        let _ = state.tx.lock().unwrap().take().map(|tx| {
            tx.send(Err(OpenAIAuthError::OAuth(format!(
                "OAuth error: {}",
                error
            ))))
        });
        return (
            (state.html_responder)(CallbackEvent::Error { reason: error }),
            true,
        );
    }

    // Validate state
    let received_state_str = received_state.as_deref().unwrap_or("");
    if received_state_str != state.expected_state {
        let _ = state.tx.lock().unwrap().take().map(|tx| {
            tx.send(Err(OpenAIAuthError::OAuth(
                "State mismatch - possible CSRF attack".to_string(),
            )))
        });
        return ((state.html_responder)(CallbackEvent::StateMismatch), true);
    }

    // Extract code
    match code {
        Some(code) => {
            let _ = state.tx.lock().unwrap().take().map(|tx| {
                tx.send(Ok(CallbackData {
                    code: code.clone(),
                    _state: received_state_str.to_string(),
                }))
            });
            (
                (state.html_responder)(CallbackEvent::Success { code }),
                true,
            )
        }
        None => {
            let _ = state
                .tx
                .lock()
                .unwrap()
                .take()
                .map(|tx| tx.send(Err(OpenAIAuthError::InvalidAuthorizationCode)));
            ((state.html_responder)(CallbackEvent::MissingCode), true)
        }
    }
}

fn default_callback_html(event: CallbackEvent) -> String {
    match event {
        CallbackEvent::Success { .. } => r#"
            <html>
                <head><title>Authorization Successful</title></head>
                <body>
                    <h1>Authorization Successful!</h1>
                    <p>You have successfully authorized the application.</p>
                    <p>You can close this window and return to the terminal.</p>
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
                    <p>You can close this window.</p>
                </body>
            </html>
            "#,
            reason
        ),
        CallbackEvent::StateMismatch => r#"
            <html>
                <head><title>Authorization Failed</title></head>
                <body>
                    <h1>Authorization Failed</h1>
                    <p>Security validation failed. Please try again.</p>
                    <p>You can close this window.</p>
                </body>
            </html>
            "#
        .to_string(),
        CallbackEvent::MissingCode => r#"
            <html>
                <head><title>Authorization Failed</title></head>
                <body>
                    <h1>Authorization Failed</h1>
                    <p>No authorization code received.</p>
                    <p>You can close this window.</p>
                </body>
            </html>
            "#
        .to_string(),
    }
}

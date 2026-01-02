//! # openai-auth
//!
//! A Rust library for OpenAI/ChatGPT OAuth 2.0 authentication with PKCE support.
//!
//! This library provides both synchronous (blocking) and asynchronous (runtime-agnostic)
//! APIs for authenticating with OpenAI's OAuth 2.0 endpoints.
//!
//! ## Features
//!
//! - **Async API** (default): Runtime-agnostic async operations
//! - **Blocking API** (optional): Blocking operations, no async runtime required
//! - **PKCE Support**: Secure PKCE (SHA-256) authentication flow
//! - **Configurable**: Custom client IDs, endpoints, redirect URIs
//! - **Browser Integration**: Auto-open browser for authorization (default)
//! - **Callback Server**: Local server for automatic callback handling (optional, requires tokio)
//! - **JWT Utilities**: Extract ChatGPT account ID from access tokens
//! - **API Key Exchange**: Exchange id_token for OpenAI API key (Codex CLI flow)
//!
//! ## Quick Start (Async API)
//!
//! ```no_run
//! use openai_auth::{OAuthClient, OAuthConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = OAuthClient::new(OAuthConfig::default())?;
//!     let flow = client.start_flow()?;
//!     
//!     println!("Visit: {}", flow.authorization_url);
//!     // Get code from user...
//!     
//!     let tokens = client.exchange_code("code", &flow.pkce_verifier).await?;
//!     println!("Got tokens!");
//!     Ok(())
//! }
//! ```
//!
//! ## Quick Start (Blocking API)
//!
//! ```no_run
//! use openai_auth::{blocking::OAuthClient, OAuthConfig};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = OAuthClient::new(OAuthConfig::default())?;
//!     let flow = client.start_flow()?;
//!     
//!     println!("Visit: {}", flow.authorization_url);
//!     // Get code from user...
//!     
//!     let tokens = client.exchange_code("code", &flow.pkce_verifier)?;
//!     println!("Got tokens!");
//!     Ok(())
//! }
//! ```

mod error;
mod jwt;
mod types;

#[cfg(feature = "async")]
mod client;

#[cfg(feature = "blocking")]
pub mod blocking;

#[cfg(feature = "browser")]
mod browser;

#[cfg(feature = "callback-server")]
mod server;

// Public API exports
pub use error::{OpenAIAuthError, Result};
pub use types::{OAuthConfig, OAuthConfigBuilder, OAuthFlow, TokenSet};

#[cfg(feature = "async")]
pub use client::OAuthClient;

#[cfg(feature = "browser")]
pub use browser::open_browser;

#[cfg(feature = "callback-server")]
pub use server::{CallbackEvent, run_callback_server, run_callback_server_with_html};

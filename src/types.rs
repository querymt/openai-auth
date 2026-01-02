use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// OAuth token set containing access token, refresh token, and expiration info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    /// The access token used to authenticate API requests
    pub access_token: String,
    /// The ID token returned by OpenAI (used for API key exchange)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The refresh token used to obtain new access tokens
    pub refresh_token: String,
    /// Unix timestamp (seconds) when the access token expires
    pub expires_at: u64,
    /// OpenAI API key derived from token exchange
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

impl TokenSet {
    /// Check if the token is expired or will expire soon (within 5 minutes)
    ///
    /// This includes a 5-minute buffer to prevent race conditions where a token
    /// expires between checking and using it.
    pub fn is_expired(&self) -> bool {
        self.expires_in() <= Duration::from_secs(300)
    }

    /// Get the duration until the token expires
    ///
    /// Returns `Duration::ZERO` if the token is already expired.
    pub fn expires_in(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.expires_at > now {
            Duration::from_secs(self.expires_at - now)
        } else {
            Duration::ZERO
        }
    }
}

/// OAuth authorization flow information
///
/// Contains the authorization URL and PKCE verifier needed to complete
/// the OAuth flow.
#[derive(Debug, Clone)]
pub struct OAuthFlow {
    /// The URL the user should visit to authorize the application
    pub authorization_url: String,
    /// The PKCE verifier used to exchange the authorization code for tokens
    pub pkce_verifier: String,
    /// The CSRF state token for security validation
    pub state: String,
}

/// Configuration for the OpenAI OAuth client
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth client ID (default: "app_EMoamEEZ73f0CkXaXp7hrann")
    pub client_id: String,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token exchange endpoint URL
    pub token_url: String,
    /// Redirect URI for OAuth callback (default: "http://localhost:1455/auth/callback")
    pub redirect_uri: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            client_id: "app_EMoamEEZ73f0CkXaXp7hrann".to_string(),
            auth_url: "https://auth.openai.com/oauth/authorize".to_string(),
            token_url: "https://auth.openai.com/oauth/token".to_string(),
            redirect_uri: "http://localhost:1455/auth/callback".to_string(),
        }
    }
}

impl OAuthConfig {
    /// Create a new config builder
    pub fn builder() -> OAuthConfigBuilder {
        OAuthConfigBuilder::default()
    }
}

/// Builder for OAuthConfig
#[derive(Debug, Clone, Default)]
pub struct OAuthConfigBuilder {
    client_id: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    redirect_uri: Option<String>,
}

impl OAuthConfigBuilder {
    /// Set the OAuth client ID
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the authorization endpoint URL
    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    /// Set the token exchange endpoint URL
    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = Some(token_url.into());
        self
    }

    /// Set the redirect URI
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    /// Set the redirect URI with a custom port
    pub fn redirect_port(mut self, port: u16) -> Self {
        self.redirect_uri = Some(format!("http://localhost:{}/auth/callback", port));
        self
    }

    /// Build the OAuthConfig
    pub fn build(self) -> OAuthConfig {
        let defaults = OAuthConfig::default();
        OAuthConfig {
            client_id: self.client_id.unwrap_or(defaults.client_id),
            auth_url: self.auth_url.unwrap_or(defaults.auth_url),
            token_url: self.token_url.unwrap_or(defaults.token_url),
            redirect_uri: self.redirect_uri.unwrap_or(defaults.redirect_uri),
        }
    }
}

/// Token response from OAuth server
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

impl From<TokenResponse> for TokenSet {
    fn from(response: TokenResponse) -> Self {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + response.expires_in.unwrap_or(3600);

        TokenSet {
            access_token: response.access_token,
            id_token: response.id_token,
            refresh_token: response.refresh_token.unwrap_or_default(),
            expires_at,
            api_key: None,
        }
    }
}

/// Generate a random state string for CSRF protection
pub(crate) fn generate_random_state() -> String {
    use base64::{Engine as _, engine::general_purpose};
    use rand::Rng;

    let random_bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().r#gen()).collect();
    general_purpose::URL_SAFE_NO_PAD.encode(&random_bytes)
}

pub(crate) fn generate_pkce_pair() -> (String, String) {
    use base64::{Engine as _, engine::general_purpose};
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(digest);
    (challenge, verifier)
}

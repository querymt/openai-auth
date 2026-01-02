use url::Url;

use crate::types::TokenResponse;
use crate::{OAuthConfig, OAuthFlow, OpenAIAuthError, Result, TokenSet};

/// Blocking OpenAI OAuth client for authentication
///
/// This client handles the OAuth 2.0 flow with PKCE for OpenAI/ChatGPT authentication
/// using blocking/synchronous operations.
///
/// # Example
///
/// ```no_run
/// use openai_auth::{blocking::OAuthClient, OAuthConfig};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = OAuthClient::new(OAuthConfig::default())?;
///     let flow = client.start_flow()?;
///     
///     println!("Visit: {}", flow.authorization_url);
///     // User authorizes and you get the code...
///     
///     let tokens = client.exchange_code("code", &flow.pkce_verifier)?;
///     println!("Got tokens!");
///     Ok(())
/// }
/// ```
pub struct OAuthClient {
    config: OAuthConfig,
}

impl OAuthClient {
    /// Create a new OAuth client with the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - OAuth configuration (client ID, endpoints, redirect URI)
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid
    pub fn new(config: OAuthConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Start the OAuth authorization flow
    ///
    /// This generates a PKCE challenge and creates the authorization URL
    /// that the user should visit to authorize the application.
    ///
    /// # Returns
    ///
    /// An `OAuthFlow` containing the authorization URL, PKCE verifier,
    /// and CSRF state token
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use openai_auth::{blocking::OAuthClient, OAuthConfig};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = OAuthClient::new(OAuthConfig::default())?;
    /// let flow = client.start_flow()?;
    /// println!("Visit: {}", flow.authorization_url);
    /// # Ok(())
    /// # }
    /// ```
    pub fn start_flow(&self) -> Result<OAuthFlow> {
        // Generate random state for CSRF protection
        let state = crate::types::generate_random_state();
        let (pkce_challenge, pkce_verifier) = crate::types::generate_pkce_pair();

        // Build authorization URL
        let mut url = Url::parse(&self.config.auth_url)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", "openid profile email offline_access")
            .append_pair("code_challenge", &pkce_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state)
            .append_pair("id_token_add_organizations", "true")
            .append_pair("codex_cli_simplified_flow", "true")
            .append_pair("originator", "codex_cli_rs");

        Ok(OAuthFlow {
            authorization_url: url.to_string(),
            pkce_verifier,
            state,
        })
    }

    /// Exchange an authorization code for access and refresh tokens
    ///
    /// After the user authorizes the application, they'll receive an authorization
    /// code. This method exchanges that code for access and refresh tokens.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the OAuth callback
    /// * `verifier` - The PKCE verifier from the original flow
    ///
    /// # Returns
    ///
    /// A `TokenSet` containing access token, refresh token, and expiration time
    ///
    /// # Errors
    ///
    /// Returns an error if the token exchange fails (invalid code, network error, etc.)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use openai_auth::{blocking::OAuthClient, OAuthConfig};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = OAuthClient::new(OAuthConfig::default())?;
    /// # let flow = client.start_flow()?;
    /// let code = "authorization_code_from_callback";
    /// let tokens = client.exchange_code(code, &flow.pkce_verifier)?;
    /// println!("Access token expires in: {:?}", tokens.expires_in());
    /// # Ok(())
    /// # }
    /// ```
    pub fn exchange_code(&self, code: &str, verifier: &str) -> Result<TokenSet> {
        let client = reqwest::blocking::Client::new();

        let params = [
            ("grant_type", "authorization_code"),
            ("client_id", &self.config.client_id),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", &self.config.redirect_uri),
        ];

        let response = client
            .post(&self.config.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();
            return Err(OpenAIAuthError::Http { status, body });
        }

        let token_response: TokenResponse = response.json()?;
        Ok(TokenSet::from(token_response))
    }

    /// Exchange an authorization code and return a TokenSet with an API key.
    ///
    /// This mirrors the Codex CLI flow by exchanging the `id_token` for an
    /// OpenAI API key using the token-exchange grant.
    pub fn exchange_code_for_api_key(&self, code: &str, verifier: &str) -> Result<TokenSet> {
        let mut tokens = self.exchange_code(code, verifier)?;
        let id_token = tokens.id_token.as_deref().ok_or_else(|| {
            OpenAIAuthError::TokenExchange("missing id_token for api key exchange".to_string())
        })?;
        let api_key = self.obtain_api_key(id_token)?;
        tokens.api_key = Some(api_key);
        Ok(tokens)
    }

    /// Exchange an OpenAI id_token for an API key access token.
    pub fn obtain_api_key(&self, id_token: &str) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct ExchangeResponse {
            access_token: String,
        }

        let client = reqwest::blocking::Client::new();
        let params = [
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("client_id", &self.config.client_id),
            ("requested_token", "openai-api-key"),
            ("subject_token", id_token),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:id_token",
            ),
        ];

        let response = client
            .post(&self.config.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();
            return Err(OpenAIAuthError::Http { status, body });
        }

        let exchange: ExchangeResponse = response.json()?;
        Ok(exchange.access_token)
    }

    /// Refresh an expired access token
    ///
    /// When an access token expires, use the refresh token to obtain a new
    /// access token without requiring the user to re-authorize.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The refresh token from a previous token exchange
    ///
    /// # Returns
    ///
    /// A new `TokenSet` with fresh access token
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh fails (invalid refresh token, network error, etc.)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use openai_auth::{blocking::OAuthClient, OAuthConfig, TokenSet};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = OAuthClient::new(OAuthConfig::default())?;
    /// # let tokens = TokenSet {
    /// #     access_token: "".into(),
    /// #     refresh_token: "refresh".into(),
    /// #     expires_at: 0,
    /// # };
    /// if tokens.is_expired() {
    ///     let new_tokens = client.refresh_token(&tokens.refresh_token)?;
    ///     println!("Refreshed! New token expires in: {:?}", new_tokens.expires_in());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet> {
        let client = reqwest::blocking::Client::new();

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.config.client_id),
        ];

        let response = client
            .post(&self.config.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();
            return Err(OpenAIAuthError::ApiKeyExchange { status, body });
        }

        let token_response: TokenResponse = response.json()?;
        Ok(TokenSet::from(token_response))
    }

    /// Extract ChatGPT account ID from an access token
    ///
    /// OpenAI access tokens contain the ChatGPT account ID in their JWT claims.
    /// This is useful for making API requests that require the account ID.
    ///
    /// # Arguments
    ///
    /// * `access_token` - The access token to extract the account ID from
    ///
    /// # Returns
    ///
    /// The ChatGPT account ID as a string
    ///
    /// # Errors
    ///
    /// Returns an error if the JWT is malformed or doesn't contain the account ID
    pub fn extract_account_id(&self, access_token: &str) -> Result<String> {
        crate::jwt::extract_account_id(access_token)
    }
}

impl Default for OAuthClient {
    fn default() -> Self {
        Self::new(OAuthConfig::default()).expect("Failed to create OAuth client with defaults")
    }
}

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::{OpenAIAuthError, Result};

/// OpenAI-specific auth claims within JWT
#[derive(Debug, Serialize, Deserialize)]
struct OpenAIAuth {
    #[serde(rename = "chatgpt_account_id")]
    chatgpt_account_id: Option<String>,
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    #[serde(rename = "https://api.openai.com/auth")]
    openai_auth: Option<OpenAIAuth>,
}

/// Extract ChatGPT account ID from access token JWT
///
/// This function decodes the JWT without verifying the signature (since we
/// already trust the token from the OAuth flow) and extracts the account ID
/// from the custom claims.
///
/// # Arguments
///
/// * `token` - The JWT access token from OpenAI
///
/// # Returns
///
/// The ChatGPT account ID as a string
///
/// # Errors
///
/// Returns an error if:
/// - The JWT is malformed
/// - The required claim is missing
pub fn extract_account_id(token: &str) -> Result<String> {
    // Decode without verification (we just need claims)
    // The token comes from OpenAI's OAuth flow, so we trust it
    let mut validation = Validation::new(Algorithm::RS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;

    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(&[]), &validation)?;

    token_data
        .claims
        .openai_auth
        .and_then(|auth| auth.chatgpt_account_id)
        .ok_or_else(|| OpenAIAuthError::MissingJwtClaim("chatgpt_account_id".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_account_id_missing_claim() {
        // A token without the required claim should return an error
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid";
        let result = extract_account_id(token);
        assert!(result.is_err());
    }
}

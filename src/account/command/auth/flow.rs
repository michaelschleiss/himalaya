use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::Engine;

use super::error::AuthError;
use super::provider::{AuthProvider, ProviderConfig};

/// OAuth 2.0 tokens returned from the authorization server
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

/// Token request for authorization code exchange
#[derive(Debug, Serialize)]
struct TokenRequest {
    client_id: String,
    client_secret: String,
    code: String,
    grant_type: String,
    code_verifier: String,
}

/// Token response from token endpoint
#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// OAuth 2.0 Authorization Code Flow handler with PKCE (RFC 7636)
pub struct OAuthFlow {
    provider: AuthProvider,
    client_id: String,
    client_secret: String,
}

impl OAuthFlow {
    /// Create a new OAuth flow
    pub fn new(
        provider: AuthProvider,
        _account_name: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Self {
            provider,
            client_id,
            client_secret,
        }
    }

    /// Execute the complete OAuth 2.0 Authorization Code Flow with copy-paste pattern
    pub async fn execute(&self) -> Result<OAuthTokens, AuthError> {
        let config = self.provider.config();

        // Step 1: Generate PKCE code challenge and verifier
        let (code_challenge, code_verifier) = Self::generate_pkce_pair();

        // Step 2: Generate state for CSRF protection
        let state = Self::generate_state();

        // Step 3: Build authorization URL
        let auth_url = self.build_authorization_url(&config, &state, &code_challenge)?;

        // Step 4: Display authorization URL to user
        println!("\n🔐 Please visit this URL to authorize Himalaya:\n");
        println!("  {}\n", auth_url);
        println!("After authorizing, copy the authorization code from the page.\n");

        // Step 5: Prompt user to paste authorization code
        let authorization_code = self.prompt_for_authorization_code()?;

        // Step 6: Exchange authorization code for tokens
        let tokens = self
            .exchange_code_for_tokens(&config, &authorization_code, &code_verifier)
            .await?;

        println!("✓ Authorization successful");

        Ok(tokens)
    }

    /// Generate PKCE code challenge and verifier
    fn generate_pkce_pair() -> (String, String) {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let verifier: String = (0..128)
            .map(|_| {
                let idx = rng.gen_range(0..PKCE_CHARSET.len());
                PKCE_CHARSET[idx] as char
            })
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(&verifier);
        let hash = hasher.finalize();

        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let challenge = engine.encode(&hash[..]);

        (challenge, verifier)
    }

    /// Generate random state for CSRF protection
    fn generate_state() -> String {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..PKCE_CHARSET.len());
                PKCE_CHARSET[idx] as char
            })
            .collect()
    }

    /// Build the authorization URL
    fn build_authorization_url(
        &self,
        config: &ProviderConfig,
        state: &str,
        code_challenge: &str,
    ) -> Result<String, AuthError> {
        let params = [
            ("client_id", self.client_id.as_str()),
            ("response_type", "code"),
            ("scope", &config.scopes_str()),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
        ];

        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        Ok(format!("{}?{}", config.auth_url, query))
    }

    /// Prompt user to enter the authorization code
    fn prompt_for_authorization_code(&self) -> Result<String, AuthError> {
        use std::io::{self, BufRead, Write};

        print!("Enter the authorization code: ");
        io::stdout().flush().map_err(|e| {
            AuthError::ConfigError(format!("Failed to flush stdout: {}", e))
        })?;

        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut code = String::new();
        handle.read_line(&mut code).map_err(|e| {
            AuthError::ConfigError(format!("Failed to read authorization code: {}", e))
        })?;

        let code = code.trim();
        if code.is_empty() {
            return Err(AuthError::ConfigError(
                "Authorization code cannot be empty".to_string(),
            ));
        }

        Ok(code.to_string())
    }

    /// Exchange authorization code for tokens
    async fn exchange_code_for_tokens(
        &self,
        config: &ProviderConfig,
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuthTokens, AuthError> {
        let client = reqwest::Client::new();

        let request = TokenRequest {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            code: code.to_string(),
            grant_type: "authorization_code".to_string(),
            code_verifier: code_verifier.to_string(),
        };

        println!("🔄 Exchanging authorization code for tokens...");

        let response = client
            .post(config.token_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::TokenExchangeFailed(format!(
                "Failed to exchange authorization code: {}",
                error_text
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| AuthError::TokenExchangeFailed(format!(
                "Failed to parse token response: {}",
                e
            )))?;

        println!("✓ Tokens obtained");

        Ok(OAuthTokens {
            access_token: token_response.access_token,
            refresh_token: token_response.refresh_token,
            expires_in: token_response.expires_in,
        })
    }
}

/// Characters allowed in PKCE code verifier (RFC 7636)
const PKCE_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_tokens_creation() {
        let tokens = OAuthTokens {
            access_token: "test_token".to_string(),
            refresh_token: Some("refresh_token".to_string()),
            expires_in: Some(3600),
        };

        assert_eq!(tokens.access_token, "test_token");
        assert!(tokens.refresh_token.is_some());
    }

    #[test]
    fn test_pkce_pair_generation() {
        let (challenge, verifier) = OAuthFlow::generate_pkce_pair();

        // Verify challenge and verifier are not empty
        assert!(!challenge.is_empty());
        assert!(!verifier.is_empty());

        // Verifier should be 128 chars
        assert_eq!(verifier.len(), 128);

        // Challenge should be URL-safe base64 encoded (no padding)
        assert!(!challenge.contains("+"));
        assert!(!challenge.contains("/"));
        assert!(!challenge.contains("="));
    }

    #[test]
    fn test_state_generation() {
        let state = OAuthFlow::generate_state();

        // State should be 32 characters
        assert_eq!(state.len(), 32);

        // State should only contain valid PKCE characters
        for c in state.chars() {
            assert!(PKCE_CHARSET.contains(&(c as u8)));
        }
    }
}

use std::time::Duration;
use tokio::time::{interval, timeout};
use serde::{Deserialize, Serialize};

use super::error::AuthError;
use super::provider::{AuthProvider, ProviderConfig};

/// OAuth 2.0 tokens returned from the authorization server
#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

/// Device authorization request response (RFC 8628)
#[derive(Debug, Serialize, Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_url: String,
    expires_in: u64,
    #[serde(default)]
    interval: u64,
}

/// Token poll request for device flow
#[derive(Debug, Serialize)]
struct DeviceTokenRequest {
    client_id: String,
    client_secret: String,
    device_code: String,
    grant_type: String,
}

/// Token response from token endpoint
#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

/// OAuth 2.0 Device Authorization Flow handler (RFC 8628)
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

    /// Execute the complete OAuth 2.0 Device Authorization Flow
    pub async fn execute(&self) -> Result<OAuthTokens, AuthError> {
        let config = self.provider.config();

        println!("📱 Requesting device authorization code...");

        // Step 1: Request device code
        let device_auth = self.request_device_code(&config).await?;

        // Step 2: Display device code to user
        println!("\n🔐 Device authorization required!");
        println!("\nPlease visit this URL on any device:");
        println!("\n  {}\n", device_auth.verification_url);
        println!("Enter the code: {}\n", device_auth.user_code);
        println!("Waiting for authorization (up to {} seconds)...", device_auth.expires_in);

        // Step 3: Poll for token with exponential backoff
        let tokens = self
            .poll_for_token(&config, &device_auth)
            .await?;

        println!("\n✓ Authorization successful");

        Ok(tokens)
    }

    /// Request device authorization code from the provider
    async fn request_device_code(&self, config: &ProviderConfig) -> Result<DeviceAuthResponse, AuthError> {
        let client = reqwest::Client::new();

        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", &config.scopes_str()),
        ];

        let response = client
            .post(config.device_authorization_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::TokenExchangeFailed(format!(
                "Failed to get device code: {}",
                error_text
            )));
        }

        response
            .json::<DeviceAuthResponse>()
            .await
            .map_err(|e| AuthError::TokenExchangeFailed(format!(
                "Failed to parse device auth response: {}",
                e
            )))
    }

    /// Poll token endpoint until user authorizes or flow expires
    async fn poll_for_token(
        &self,
        config: &ProviderConfig,
        device_auth: &DeviceAuthResponse,
    ) -> Result<OAuthTokens, AuthError> {
        let client = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(device_auth.expires_in);

        // Use suggested interval, minimum 1 second
        let poll_interval = Duration::from_secs(std::cmp::max(device_auth.interval, 1));
        let mut interval_handle = interval(poll_interval);

        loop {
            // Check if we've exceeded the expiration time
            if tokio::time::Instant::now() >= deadline {
                return Err(AuthError::CallbackTimeout);
            }

            // Wait before next poll (except first time)
            interval_handle.tick().await;

            // Prepare token request
            let request_body = DeviceTokenRequest {
                client_id: self.client_id.clone(),
                client_secret: self.client_secret.clone(),
                device_code: device_auth.device_code.clone(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            };

            // Poll token endpoint
            let response = match timeout(Duration::from_secs(10),
                client.post(config.token_url).json(&request_body).send()
            ).await {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    return Err(AuthError::NetworkError(e.to_string()));
                }
                Err(_) => {
                    return Err(AuthError::NetworkError("Token endpoint timeout".to_string()));
                }
            };

            if !response.status().is_success() {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                return Err(AuthError::TokenExchangeFailed(error_text));
            }

            let token_response: TokenResponse = response
                .json()
                .await
                .map_err(|e| AuthError::TokenExchangeFailed(format!(
                    "Failed to parse token response: {}",
                    e
                )))?;

            // Check for authorization_pending (user hasn't authorized yet)
            if let Some(error) = token_response.error {
                match error.as_str() {
                    "authorization_pending" => {
                        // User hasn't authorized yet, keep polling
                        continue;
                    }
                    "slow_down" => {
                        // Server asked us to slow down, increase interval
                        interval_handle = interval(poll_interval * 2);
                        continue;
                    }
                    "expired_token" => {
                        return Err(AuthError::CallbackTimeout);
                    }
                    "access_denied" => {
                        return Err(AuthError::UserCancelled);
                    }
                    _ => {
                        return Err(AuthError::TokenExchangeFailed(error));
                    }
                }
            }

            // Success! We got tokens
            println!("🔄 Exchanging device code for tokens...");
            println!("✓ Tokens obtained");

            return Ok(OAuthTokens {
                access_token: token_response.access_token,
                refresh_token: token_response.refresh_token,
                expires_in: token_response.expires_in,
            });
        }
    }
}

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
}

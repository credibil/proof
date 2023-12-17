use chrono::{DateTime, Utc};
use vercre_didcore::{error::Err, tracerr, Result};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthType, AuthUrl, ClientId, ClientSecret,
    Scope, TokenResponse, TokenUrl,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};

const AZURE_PUBLIC_CLOUD: &str = "https://login.microsoftonline.com";
const AUDIENCE: &str = "https://vault.azure.net";

/// Access token.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessToken {
    pub token: String,
    pub expires: DateTime<Utc>,
}

/// Access token implementation.
impl AccessToken {
    /// Access token as a string.
    pub fn as_str(&self) -> &str {
        self.token.as_str()
    }

    /// Get the access token using environment variables. The following environment variables are
    /// required:
    ///
    /// | Variable              | Description                                                      |
    /// |-----------------------|------------------------------------------------------------------|
    /// | `AZURE_TENANT_ID`     | The Azure Active Directory tenant(directory) ID.                 |
    /// | `AZURE_CLIENT_ID`     | The client(application) ID of an App Registration in the tenant. |
    /// | `AZURE_CLIENT_SECRET` | A client secret that was generated for the App Registration.     |
    pub async fn get_token() -> Result<Self> {
        let tenant = match std::env::var("AZURE_TENANT_ID") {
            Ok(t) => t,
            Err(_) => tracerr!(
                Err::InvalidConfig,
                "AZURE_TENANT_ID environment variable not set"
            ),
        };
        let client = match std::env::var("AZURE_CLIENT_ID") {
            Ok(c) => c,
            Err(_) => tracerr!(
                Err::InvalidConfig,
                "AZURE_CLIENT_ID environment variable not set"
            ),
        };
        let secret = match std::env::var("AZURE_CLIENT_SECRET") {
            Ok(s) => s,
            Err(_) => tracerr!(
                Err::InvalidConfig,
                "AZURE_CLIENT_SECRET environment variable not set"
            ),
        };

        let t_url = Url::parse(&format!(
            "{}/{}/oauth2/v2.0/token",
            AZURE_PUBLIC_CLOUD, tenant
        ))?;
        let token_url = TokenUrl::from_url(t_url);
        let a_url = Url::parse(&format!(
            "{}/{}/oauth2/v2.0/authorize",
            AZURE_PUBLIC_CLOUD, tenant
        ))?;
        let auth_url = AuthUrl::from_url(a_url);

        let client = BasicClient::new(
            ClientId::new(client),
            Some(ClientSecret::new(secret)),
            auth_url,
            Some(token_url),
        )
        .set_auth_type(AuthType::RequestBody);
        let token_res = match client
            .exchange_client_credentials()
            .add_scope(Scope::new(format!("{AUDIENCE}/.default")))
            .request_async(async_http_client)
            .await
        {
            Ok(t) => t,
            Err(_) => tracerr!(Err::AuthError, "Failed to get access token."),
        };

        Ok(Self {
            token: token_res.access_token().secret().to_string(),
            expires: Utc::now() + token_res.expires_in().unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Get an access token without error.
    #[tokio::test]
    #[ignore]
    async fn get_token() {
        let token = AccessToken::get_token().await;
        assert!(token.is_ok());
        println!("{}", token.unwrap().as_str());
    }
}

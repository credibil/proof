use base64ct::{Base64UrlUnpadded, Encoding};
use reqwest::{Response, Url};
use serde::{Deserialize, Serialize};
use did_core::error::Err;
use did_core::{tracerr, Result};

use super::auth::AccessToken;
use super::key_bundle::{Deleted, KeyBundle};
use crate::error::ApiErrorResponse;
use crate::key_bundle::{JwkCurve, JwkOperation, JwkType, KeyList};

const API_VERSION: &str = "7.4";
// Maximum number of versions of a key to query when looking for the immediate previous version.
const MAX_KEY_VERSIONS: usize = 25;

/// Azure Key Vault client.
#[derive(Clone)]
pub struct KeyVault {
    /// Vault URL
    vault_url: String,
    /// Reusable HTTP client
    http_client: reqwest::Client,
}

// Struct used internally for key creation requests.
#[derive(Debug, Serialize)]
struct CreateKeyRequest {
    kty: JwkType,
    key_ops: Vec<JwkOperation>,
    crv: JwkCurve,
    attributes: SettableAttributes,
}

// Struct used internally for key update requests.
#[derive(Debug, Serialize)]
struct UpdateKeyRequest {
    attributes: SettableAttributes,
}

// Attributes that can be set when creating/updating a key. (A subset of those available in the
// Azure API).
#[derive(Debug, Serialize)]
struct SettableAttributes {
    enabled: bool,
}

/// Sign request body.
#[derive(Serialize)]
pub struct SigningRequest {
    /// Algorithm
    alg: String,
    /// Message to sign
    value: String,
}

/// Signature response.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SignatureResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    aad: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iv: Option<String>,
    /// Key identifier
    kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    /// Signature
    value: String,
}

/// Azure Key Vault client constructor and vault operation methods.
impl KeyVault {
    /// Constructor.
    ///
    /// # Arguments
    ///
    /// * `vault_url` - URL of the Azure Key Vault.
    ///
    /// # Panics
    ///
    /// If the HTTP client cannot be created.
    pub fn new(vault_url: &str) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("failed to create HTTP client.");
        Self {
            vault_url: vault_url.to_string(),
            http_client,
        }
    }

    /// Add a key to the key vault.
    ///
    /// # Arguments
    ///
    /// * `key_name` - Name of the key to add.
    /// * `active` - Indicator of whether the key should be active.
    ///
    /// # Returns
    ///
    /// The [`super::key_bundle::KeyBundle`] created.
    ///
    /// # Errors
    ///
    /// * URL parsing error if constructing URL from configuration and key name fails.
    /// * `Err::RequestError` if the request to the underlying API fails.
    /// * `Err::DeserializationError` if the response from the underlying API cannot be
    /// deserialized.
    pub async fn create_key(&self, key_name: &str, active: bool) -> Result<KeyBundle> {
        let token = AccessToken::get_token().await?;

        let mut url = Url::parse(&format!("{}/keys/{}/create", self.vault_url, key_name))?;
        url.query_pairs_mut().append_pair("api-version", API_VERSION);

        let create_request = CreateKeyRequest {
            kty: JwkType::EC,
            key_ops: vec![JwkOperation::Sign, JwkOperation::Verify],
            crv: JwkCurve::Secp256k1,
            attributes: SettableAttributes { enabled: active },
        };
        let request = self.http_client.post(url).bearer_auth(token.as_str()).json(&create_request);

        let response = match request.send().await {
            Ok(res) => res,
            Err(e) => {
                tracerr!(Err::RequestError, "unable to make request: {}", e);
            }
        };
        unpack_response(response).await
    }

    /// Activate a key in the key vault.
    ///
    /// # Arguments
    ///
    /// * `key_name` - Name of the key to activate.
    ///
    /// # Errors
    ///
    /// * URL parsing error if constructing URL from configuration and key name fails.
    /// * `Err::RequestError` if the request to the underlying API fails.
    /// * `Err::DeserializationError` if the response from the underlying API cannot be
    /// deserialized.
    pub async fn activate_key(&self, key_name: &str) -> Result<KeyBundle> {
        let token = AccessToken::get_token().await?;
        // version is required by the API. Try empty string.
        let version = "";

        let mut url = Url::parse(&format!("{}/keys/{}/{}", self.vault_url, key_name, version))?;
        url.query_pairs_mut().append_pair("api-version", API_VERSION);

        let update_request = UpdateKeyRequest {
            attributes: SettableAttributes { enabled: true },
        };
        let request = self.http_client.patch(url).bearer_auth(token.as_str()).json(&update_request);

        let response = match request.send().await {
            Ok(res) => res,
            Err(e) => {
                tracerr!(Err::RequestError, "unable to make request: {}", e);
            }
        };
        unpack_response(response).await
    }

    /// Get a key from the vault.
    ///
    /// # Arguments
    ///
    /// * `key_name` - Name of the key to get.
    /// * `key_version` - Version of the key to get. If `None`, the latest version is returned.
    ///
    /// # Returns
    ///
    /// The [`super::key_bundle::KeyBundle`] requested. If there is no such key, an error is
    /// returned.
    ///
    /// # Errors
    ///
    /// * URL parsing error if constructing URL from configuration and key name fails.
    /// * `Err::RequestError` if the request to the underlying API fails.
    /// * `Err::DeserializationError` if the response from the underlying API cannot be
    /// deserialized.
    pub async fn get_key(&self, key_name: &str, key_version: Option<&str>) -> Result<KeyBundle> {
        let token = AccessToken::get_token().await?;

        let mut url = Url::parse(&format!("{}/keys/{}/", self.vault_url, key_name))?;
        if let Some(key_version) = key_version {
            url = url.join(key_version)?;
        }
        url.query_pairs_mut().append_pair("api-version", API_VERSION);

        let res = match self.http_client.get(url).bearer_auth(token.as_str()).send().await {
            Ok(res) => res,
            Err(e) => {
                tracerr!(Err::RequestError, "unable to make request: {}", e);
            }
        };
        unpack_response(res).await
    }

    /// Get the previous version of a key from the vault. That is, the version immediately prior to
    /// the current version.
    ///
    /// # Arguments
    ///
    /// * `key_name` - Name of the key to get.
    ///
    /// # Returns
    ///
    /// The [`super::key_bundle::KeyBundle`] requested. If there is no such key, an error is returned.
    ///
    /// # Errors
    ///
    /// * URL parsing error if constructing URL from configuration and key name fails.
    /// * `Err::RequestError` if the request to the underlying API fails.
    /// * `Err::DeserializationError` if the response from the underlying API cannot be
    /// deserialized.
    /// * `Err::KeyNotFound` if there is no previous version of the key.
    pub async fn get_previous_version(&self, key_name: &str) -> Result<KeyBundle> {
        let token = AccessToken::get_token().await?;

        let mut url = Url::parse(&format!("{}/keys/{}/versions", self.vault_url, key_name))?;
        url.query_pairs_mut().append_pair("maxresults", &MAX_KEY_VERSIONS.to_string());
        url.query_pairs_mut().append_pair("api-version", API_VERSION);

        let res = match self.http_client.get(url).bearer_auth(token.as_str()).send().await {
            Ok(res) => res,
            Err(e) => {
                tracerr!(Err::RequestError, "unable to make request: {}", e);
            }
        };
        let list = unpack_response::<KeyList>(res).await?;
        // bail if there is no version other than the latest one
        if list.value.len() < 2 {
            tracerr!(Err::KeyNotFound, "no previous version found");
        }
        // sort the list by created date, in reverse order
        let mut sorted = list.value;
        sorted.sort_by(|a, b| b.attributes.created.cmp(&a.attributes.created));

        // get full key information for the second item in the list and return it
        let version = version_from_key_id(&sorted[1].kid);
        self.get_key(key_name, Some(version)).await
    }

    /// Remove a key from the vault.
    ///
    /// # Arguments
    ///
    /// * `key_name` - Name of the key to remove.
    ///
    /// # Returns
    ///
    /// The [`super::key_bundle::KeyBundle`] removed. If there is no such key, an error is returned.
    ///
    /// # Errors
    ///
    /// * URL parsing error if constructing URL from configuration and key name fails.
    /// * `Err::RequestError` if the request to the underlying API fails.
    /// * `Err::DeserializationError` if the response from the underlying API cannot be
    /// deserialized.
    pub async fn delete_key(&self, key_name: &str) -> Result<Deleted> {
        let token = AccessToken::get_token().await?;

        let mut url = Url::parse(&format!("{}/keys/{}", self.vault_url, key_name))?;
        url.query_pairs_mut().append_pair("api-version", API_VERSION);

        let res = match self.http_client.delete(url).bearer_auth(token.as_str()).send().await {
            Ok(res) => res,
            Err(e) => {
                tracerr!(Err::RequestError, "unable to make request: {}", e);
            }
        };
        unpack_response(res).await
    }

    /// Sign a message using a key from the vault.
    ///
    /// # Arguments
    ///
    /// * `key_name` - Name of the key to use for signing.
    /// * `key_version` - Version of the key to use. If `None`, the latest version is used.
    /// * `algorithm` - Algorithm to use for signing.
    /// * `message` - Message to sign.
    ///
    /// # Returns
    ///
    /// The signature for the message, and the ID of the public key that can be used to verify.
    ///
    /// # Errors
    ///
    /// * URL parsing error if constructing URL from configuration, key name and key version fails.
    /// * `Err::RequestError` if the request to the underlying API fails.
    /// * `Err::DeserializationError` if the response from the underlying API cannot be
    /// deserialized.
    pub async fn sign(
        &self, key_name: &str, key_version: Option<&str>, message: &[u8],
    ) -> Result<(Vec<u8>, String)> {
        let token = AccessToken::get_token().await?;

        let mut url = Url::parse(&format!("{}/keys/{}/", self.vault_url, key_name))?;
        if let Some(key_version) = key_version {
            url = url.join(key_version)?;
        }
        url = url.join("sign")?;
        url.query_pairs_mut().append_pair("api-version", API_VERSION);

        let body = SigningRequest {
            alg: "ES256K".to_string(),
            value: Base64UrlUnpadded::encode_string(message),
        };
        let res =
            match self.http_client.post(url).bearer_auth(token.as_str()).json(&body).send().await {
                Ok(res) => res,
                Err(e) => {
                    tracerr!(Err::RequestError, "unable to make request: {}", e);
                }
            };
        let sig = unpack_response::<SignatureResponse>(res).await?;

        println!("sig: {:?}", sig.value);

        // Azure returns a base64 URL-encoded string with r & s concatenated.
        Ok((sig.value.into_bytes(), sig.kid))
    }
}

// Helper function to get the version from a key ID.
fn version_from_key_id(key_id: &str) -> &str {
    let parts: Vec<&str> = key_id.split('/').collect();
    parts[parts.len() - 1]
}

// Helper to unpack any response from the Azure API.
async fn unpack_response<T>(res: Response) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    if res.status().is_success() {
        match res.json::<T>().await {
            Ok(obj) => Ok(obj),
            Err(err) => {
                tracerr!(Err::DeserializationError, "unable to deserialize response: {}", err)
            }
        }
    } else {
        match res.json::<ApiErrorResponse>().await {
            Ok(err) => {
                if err.error.code.as_str() == "KeyNotFound" {
                    Err(Err::KeyNotFound.into())
                } else {
                    tracerr!(
                        Err::ApiError,
                        "code: {}, message: {}",
                        err.error.code,
                        err.error.message
                    )
                }
            }
            Err(err) => tracerr!(Err::Unknown, "{}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> KeyVault {
        let url = std::env::var("AZURE_KEY_VAULT").expect("AZURE_KEY_VAULT env var not set");
        KeyVault::new(url.as_str())
    }

    // Get a non-existent key and check not-found error.
    #[tokio::test]
    #[ignore]
    async fn get_missing_key() {
        let client = test_client();
        // Try getting non-existent key from Azure Key Vault
        match client.get_key("unlikely-test", None).await {
            Ok(_) => panic!("Should not have found key."),
            Err(e) => {
                if !e.is(Err::KeyNotFound) {
                    panic!("Unexpected error: {}", e);
                }
            }
        };
    }

    // Create a key, then get it, then delete it. All without error.
    #[tokio::test]
    #[ignore]
    async fn create_key_then_get_then_delete_key() {
        let client = test_client();

        let key_name = format!("test-key-{}", uuid::Uuid::new_v4());

        // Create key in Azure Key Vault
        let key_bundle = client.create_key(&key_name, true).await.expect("Failed to create key.");

        // Retrieve the key and check it sufficiently matches the created one.
        let key_bundle2 = client.get_key(&key_name, None).await.expect("Failed to get key.");
        assert_eq!(key_bundle.key.id, key_bundle2.key.id);
        assert!(key_bundle2.attributes.enabled.is_some_and(|enabled| enabled));

        // Delete the key, check deletion and check it sufficiently matches the created one.
        let key_bundle3 = client.delete_key(&key_name).await.expect("Failed to delete key.");
        assert_eq!(key_bundle.key.id, key_bundle3.key_bundle.key.id);
        assert!(key_bundle3.date.is_some());
    }
}

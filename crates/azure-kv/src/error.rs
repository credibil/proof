use serde::Deserialize;

/// Error returned from Azure Key Vault.
#[derive(Debug, Deserialize)]
pub struct ApiErrorResponse {
    /// Error details.
    pub error: ApiErrorDetail,
}

/// Error returned from Azure Key Vault.
#[derive(Debug, Deserialize)]
pub struct ApiErrorDetail {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

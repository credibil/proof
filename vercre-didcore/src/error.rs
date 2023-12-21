//! # DID Core Errors
//!
//! This module defines the error types used by the DID Core library, including for traits that
//! may be implemented in other crates.

use std::fmt::Display;

use thiserror::Error;

/// Simplify creation of errors with tracing.
///
/// # Example
/// ```
/// use didcore::error::Err;
/// use didcore::{error, Result};
///
/// fn with_msg() -> Result<(), Err> {
///     error!(Err::InvalidRequest, "message: {}", "some message")
/// }
///
/// fn no_msg() -> Result<(), Err> {
///     error!(Err::InvalidRequest)
/// }
/// ```
#[macro_export]
macro_rules! tracerr {
    // with context
    ($code:expr, $($msg:tt)*) => {
        {
        use $crate::error::Context as _;
        tracing::error!($($msg)*);
        return Err($code).context(format!($($msg)*));
        }
    };
    // no context
    ($code:expr) => {
        {
        tracing::error!("{}", $code);
        return Err($code.into());
        }
    }
}

/// Public error type for DID Core.
#[derive(Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] anyhow::Error);

impl Error {
    /// Transfer the error to `OAuth2` compatible format.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.0.root_cause().to_string(),
            "error_description": self.to_string(),
        })
    }

    /// Returns true if `E` is the type held by this error object.
    #[must_use]
    pub fn is(&self, err: Err) -> bool {
        self.0.downcast_ref::<Err>().map_or(false, |e| e == &err)
    }
}

/// Typed errors for DID Core.
#[derive(Clone, Copy, Error, Debug, PartialEq, Eq)]
pub enum Err {
    /// Hash is not a valid SHA-256 hash.
    #[error("invalid_hash")]
    InvalidHash,

    /// Invalid format. (See context for details)
    #[error("invalid_format")]
    InvalidFormat,

    /// Invalid input. Used where a verification fails that is more complex than a simple incorrect
    /// format. (See context for details)
    #[error("invalid_input")]
    InvalidInput,

    /// Invalid key is where the format of the key is incorrect or the cryptographic algorithm
    /// specified by the key is not supported.
    #[error("invalid_key")]
    InvalidKey,

    /// Invalid patch. This is used when a patch for a DID document is verified for consistency.
    #[error("invalid_patch")]
    InvalidPatch,

    /// Key not found. This is in response to parsing a DID Document for a public key and not
    /// finding one for the specified purpose or asking a keyring for a public key and not finding
    /// one for the specified operation.
    #[error("key_not_found")]
    KeyNotFound,

    /// An error was returned from a downstream API
    #[error("api_error")]
    ApiError,

    /// An error occurred trying to deserialize data.
    #[error("deserialization_error")]
    DeserializationError,

    /// An error occurred trying to serialize data.
    #[error("serialization_error")]
    SerializationError,

    /// Environment configuration could not be resolved.
    #[error("invalid_config")]
    InvalidConfig,

    /// Authentication failed.
    #[error("auth_error")]
    AuthError,

    /// Request failed. This is used when a request to a downstream API fails to connect or get a
    /// response.
    #[error("request_error")]
    RequestError,

    /// Failure to sign a message.
    #[error("signing_error")]
    SigningError,

    /// Failure to verify a signature.
    #[error("failed_signature_verification")]
    FailedSignatureVerification,

    /// A requested key signing algorithm is not supported by either the signer or the key store.
    #[error("unsupported_algorithm")]
    UnsupportedAlgorithm,

    /// An expiry date is in the past.
    #[error("expired")]
    Expired,

    /// An unspecified error occurred (see context for information)
    #[error("unknown")]
    Unknown,

    /// Feature is not yet implemented.
    #[error("not_implemented")]
    NotImplemented,

    /// Feature is not supported.
    #[error("not_supported")]
    NotSupported,

    /// No DID document was found for the requested DID.
    #[error("not_found")]
    NotFound,
}

/// Context is used to decorate errors with useful context information.
pub trait Context<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Adds context to the error.
    ///
    /// # Arguments
    ///
    /// * `context` - The context to add to the error.
    ///
    /// # Returns
    ///
    /// Original return object or error with context appended.
    ///
    /// # Errors
    ///
    /// * Original error with context appended.
    fn context<C>(self, context: C) -> Result<T, Error>
    where
        C: Display + Send + Sync + 'static;
}

impl<T, E> Context<T, E> for core::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context<C>(self, context: C) -> Result<T, Error>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => Err(Error(anyhow::Error::from(e).context(context))),
        }
    }
}

impl From<Err> for Error {
    fn from(error: Err) -> Self {
        Error(error.into())
    }
}

impl From<base64ct::Error> for Error {
    fn from(err: base64ct::Error) -> Error {
        Error(err.into())
    }
}

impl From<ecdsa::Error> for Error {
    fn from(err: ecdsa::Error) -> Error {
        Error(err.into())
    }
}

impl From<multihash::Error> for Error {
    fn from(err: multihash::Error) -> Error {
        Error(err.into())
    }
}

impl From<regex::Error> for Error {
    fn from(err: regex::Error) -> Error {
        Error(err.into())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error(err.into())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error(err.into())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Error {
        Error(err.into())
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error(err.into())
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;

    use super::*;
    use crate::Result;

    #[test]
    fn base_err() {
        let err: Error = Err::InvalidFormat.into();

        assert_eq!(
            err.to_json(),
            json!({"error":"invalid_format","error_description":"invalid_format"})
        );
    }

    #[test]
    fn context_err() {
        let res: Result<()> = Err(Err::InvalidFormat).context("Invalid format description");
        let err = res.expect_err("expected error");

        assert_eq!(
            err.to_json(),
            json!({"error":"invalid_format","error_description":"Invalid format description"})
        );
    }

    #[test]
    fn test_macro() {
        let subscriber = FmtSubscriber::builder().with_max_level(Level::ERROR).finish();
        tracing::subscriber::set_global_default(subscriber).expect("setting subscriber failed");

        let Err(e) = run_macro() else {
            panic!("expected error");
        };

        assert_eq!(e.to_string(), "test me");
    }

    fn run_macro() -> Result<()> {
        tracerr!(Err::InvalidFormat, "test {}", "me")
    }
}

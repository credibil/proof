//! Cryptographic key management, signing and verification.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

pub mod keyring;
pub mod signer;

use crate::{error::Err, tracerr, Result};

/// Key operation type. The intent of the key for use in signing a DID document or any message,
/// updating a DID document or recovering one.
#[derive(Clone, Hash, Eq, PartialEq)]
pub enum KeyOperation {
    /// Sign a DID document or other message.
    Sign,
    /// Update a DID document.
    Update,
    /// Recover a DID document.
    Recover,
}

/// Simplified JSON Web Key (JWK) key structure.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Jwk {
    /// Key type.
    pub kty: String,
    /// Cryptographic curve type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Secret key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl Jwk {
    /// Attempt to match the public key parameters to one of the algorithm types supported by the
    /// Credibil framework.
    ///
    /// # Returns
    ///
    /// The algorithm type implied by the key structure.
    ///
    /// # Errors
    ///
    /// * `Err::InvalidKey` - The key structure cannot be interpreted to a supported format.
    pub fn infer_algorithm(&self) -> Result<Algorithm> {
        match (self.kty.clone(), self.crv.clone()) {
            (t, c) if t == *"EC" && c == Some("secp256k1".to_string()) => Ok(Algorithm::Secp256k1),
            // TODO: Add more key type algorithms here.
            _ => tracerr!(Err::InvalidKey, "Unknown key type and curve combination"),
        }
    }

    /// Check that the structure of the provided public key is valid for one of the specified
    /// signing schemes and return the algorithm type.
    ///
    /// # Arguments
    ///
    /// * `schemes` - List of signing schemes to check against.
    ///
    /// # Returns
    ///
    /// The algorithm type implied by the key structure.
    ///
    /// # Errors
    ///
    /// * `Err::InvalidKey` - The key structure is invalid.
    /// * `Err::UnsupportedAlgorithm` - The algorithm inferred from the key structure is not
    /// included in the set of algorithms to check against.
    pub fn check(&self, schemes: &[Algorithm]) -> Result<Algorithm> {
        let scheme = self.infer_algorithm()?;
        if !schemes.contains(&scheme) {
            tracerr!(
                Err::UnsupportedAlgorithm,
                "Unsupported signing algorithm on key"
            );
        }
        match scheme {
            Algorithm::Secp256k1 => {
                let x = self.x.clone().unwrap_or_default();
                if x.is_empty() {
                    tracerr!(Err::InvalidKey, "Missing x coordinate");
                }
                match Base64UrlUnpadded::decode_vec(&x) {
                    Ok(raw_x) => {
                        if raw_x.len() != 32 {
                            tracerr!(
                                Err::InvalidKey,
                                "Invalid x coordinate length. Expected 32 bytes, got {}",
                                raw_x.len()
                            );
                        }
                    }
                    Err(e) => tracerr!(Err::InvalidKey, "Invalid x coordinate encoding: {}", e),
                };
                let y = self.y.clone().unwrap_or_default();
                if y.is_empty() {
                    tracerr!(Err::InvalidKey, "Missing y coordinate");
                }
                match Base64UrlUnpadded::decode_vec(&y) {
                    Ok(raw_y) => {
                        if raw_y.len() != 32 {
                            tracerr!(
                                Err::InvalidKey,
                                "Invalid y coordinate length. Expected 32 bytes, got {}",
                                raw_y.len()
                            );
                        }
                    }
                    Err(e) => tracerr!(Err::InvalidKey, "Invalid y coordinate encoding: {}", e),
                };
            }
        }
        Ok(scheme)
    }
}

/// Display key operation type as a string.
impl std::fmt::Display for KeyOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyOperation::Sign => write!(f, "sign"),
            KeyOperation::Update => write!(f, "update"),
            KeyOperation::Recover => write!(f, "recover"),
        }
    }
}

/// Types of key signature algorithm supported by the Credibil framework.
#[derive(Clone, Copy)]
pub enum Algorithm {
    /// ECDSA using the secp256k1 curve.
    Secp256k1,
}

/// Key signature type display label.
impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Secp256k1 => write!(f, "ES256K"),
        }
    }
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Algorithm::Secp256k1, Algorithm::Secp256k1) => true,
        }
    }
}
impl Eq for Algorithm {}

/// Verification method type for a key signature type.
impl Algorithm {
    /// Get the verification method type for the specified key signature type.
    #[must_use]
    pub fn cryptosuite(&self) -> String {
        match self {
            Algorithm::Secp256k1 => "EcdsaSecp256k1VerificationKey2019".to_string(),
        }
    }
}

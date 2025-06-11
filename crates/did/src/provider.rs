//! # `Proof`

use anyhow::Result;
use credibil_ecc::{Entry, Signer};
use credibil_jose::{KeyBinding, PublicKeyJwk};
use serde::{Deserialize, Serialize};

use crate::key;

/// [`Signature`] is used to provide public key material that can be used for
/// signature verification.
///
/// Extends the `credibil_infosec::Signer` trait.
pub trait Signature: Signer + Send + Sync {
    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    ///
    /// Async and fallible because the implementer may need to access key
    /// information to construct the method reference.
    fn verification_method(&self) -> impl Future<Output = Result<VerifyBy>> + Send;
}

impl Signature for Entry {
    async fn verification_method(&self) -> Result<VerifyBy> {
        let vk = self.verifying_key().await?;
        let jwk = PublicKeyJwk::from_bytes(&vk)?;
        let vm = key::did_from_jwk(&jwk)?;
        Ok(VerifyBy::KeyId(vm))
    }
}

/// Sources of public key material supported.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum VerifyBy {
    /// The ID of the public key used for verifying the associated signature.
    ///
    /// If the identity is bound to a DID, the key ID refers to a DID URL
    /// which identifies a particular key in the DID Document describing
    /// the identity.
    ///
    /// Alternatively, the ID may refer to a key inside a JWKS.
    #[serde(rename = "kid")]
    KeyId(String),

    /// Contains the public key material required to verify the associated
    /// signature.
    #[serde(rename = "jwk")]
    Jwk(PublicKeyJwk),
}

impl Default for VerifyBy {
    fn default() -> Self {
        Self::KeyId(String::new())
    }
}

impl TryInto<KeyBinding> for VerifyBy {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<KeyBinding, Self::Error> {
        match self {
            Self::KeyId(kid) => Ok(KeyBinding::Kid(kid)),
            Self::Jwk(jwk) => Ok(KeyBinding::Jwk(jwk)),
        }
    }
}

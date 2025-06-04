//! # Provider Traits

use anyhow::Result;
use credibil_jose::{KeyBinding, PublicKeyJwk};
use credibil_se::Signer;
use serde::{Deserialize, Serialize};

use crate::did::Document;

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
    fn verification_method(&self) -> impl Future<Output = Result<Key>> + Send;
}

/// [`IdentityResolver`] is used to proxy the resolution of an identity.
///
/// Implementers need only return the identity specified by the url. This
/// may be by directly dereferencing the URL, looking up a local cache, or
/// fetching from a remote resolver, or using a ledger or log that contains
/// identity material.
///
/// For example, a DID resolver for `did:webvh` would fetch the DID log from the
/// the specified URL and use any query parameters (if any) to derefence the
/// specific DID document and return that.
pub trait IdentityResolver: Send + Sync + Clone {
    /// Resolve the URL to identity information such as a DID Document or
    /// certificate.
    ///
    /// The default implementation is a no-op since for some methods, such as
    /// `did:key`, the URL contains sufficient information to verify the
    /// signature of an identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be resolved.
    fn resolve(&self, url: &str) -> impl Future<Output = Result<Identity>> + Send;
}

/// Return value from an identity resolver.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Eq)]
pub enum Identity {
    /// A decentralized identifier.
    DidDocument(Document),
}

/// Types of public key material supported by this crate.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Key {
    /// Contains a key ID that a verifier can use to dereference a key.
    ///
    /// For example, if the identity is bound to a DID, the key ID refers
    /// to a DID URL which identifies a particular key in the DID Document
    /// that describes the identity.
    ///
    /// Alternatively, the ID may refer to a key inside a JWKS.
    #[serde(rename = "kid")]
    KeyId(String),

    /// Contains the key material the new Credential shall be bound to.
    #[serde(rename = "jwk")]
    Jwk(PublicKeyJwk),
}

impl Default for Key {
    fn default() -> Self {
        Self::KeyId(String::new())
    }
}

impl TryInto<KeyBinding> for Key {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<KeyBinding, Self::Error> {
        match self {
            Self::KeyId(kid) => Ok(KeyBinding::Kid(kid)),
            Self::Jwk(jwk) => Ok(KeyBinding::Jwk(jwk)),
        }
    }
}

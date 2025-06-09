//! # Docstore

use std::sync::LazyLock;

use anyhow::Result;
use credibil_ecc::Signer;
use credibil_jose::{KeyBinding, PublicKeyJwk};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::Document;

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

/// [`JwkResolver`] is used to proxy the resolution of an identity.
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

/// `Datastore` is used by implementers to provide data storage
/// capability.
pub trait Docstore: Send + Sync {
    /// Store a data item in the underlying item store.
    fn put(
        &self, owner: &str, partition: &str, key: &str, data: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    /// Fetches a single item from the underlying store, returning `None` if
    /// no match was found.
    fn get(
        &self, owner: &str, partition: &str, key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    // /// Delete the specified data item.
    // fn delete(
    //     &self, owner: &str, partition: &str, key: &str,
    // ) -> impl Future<Output = Result<()>> + Send;

    // /// Fetches all matching items from the underlying store.
    // fn get_all(
    //     &self, owner: &str, partition: &str,
    // ) -> impl Future<Output = Result<Vec<(String, Vec<u8>)>>> + Send;
}

static STORE: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

/// A simple in-memory document store that implements the `Docstore` trait.
#[derive(Clone, Debug)]
pub struct Store;

impl Docstore for Store {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.insert(key, data.to_vec());
        Ok(())
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{owner}-{partition}-{key}");
        let Some(bytes) = STORE.get(&key) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    // async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
    //     let key = format!("{owner}-{partition}-{key}");
    //     STORE.remove(&key);
    //     Ok(())
    // }

    // async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
    //     let all = STORE
    //         .iter()
    //         .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
    //         .map(|r| (r.key().to_string(), r.value().clone()))
    //         .collect::<Vec<_>>();
    //     Ok(all)
    // }
}

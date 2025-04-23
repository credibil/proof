//! # DID Operations and Resolver
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations
//! for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

pub mod core;
pub mod did;
pub mod document;
mod error;
pub mod key;
pub mod proof;
mod resolve;
pub mod web;
pub mod webvh;
mod url;

use std::{fmt::{Display, Formatter}, future::Future, str::FromStr};

use anyhow::anyhow;
use credibil_infosec::{jose::jws::Key, Signer};
use serde::{Deserialize, Serialize};

pub use credibil_infosec::{Curve, KeyType, PublicKeyJwk};
pub use document::*;
pub use resolve::*;
pub use error::Error;
pub use url::*;

// TODO: set context based on key format:
// - Ed25519VerificationKey2020	https://w3id.org/security/suites/ed25519-2020/v1
// - JsonWebKey2020	https://w3id.org/security/suites/jws-2020/v1
// Perhaps

/// Candidate contexts to add to a DID document.
pub const BASE_CONTEXT: [&str; 3] =
    ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://w3id.org/security/suites/jws-2020/v1"];

/// DID methods supported by this crate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `did:key`
    #[default]
    Key,

    /// `did:web`
    Web,

    /// `did:webvh`
    WebVh,
}

impl FromStr for Method {
    type Err = Error;

    /// Parse a string into a [`Method`].
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid method.
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "key" => Ok(Self::Key),
            "web" => Ok(Self::Web),
            "webvh" => Ok(Self::WebVh),
            _ => Err(Error::MethodNotSupported(s.to_string())),
        }
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key => write!(f, "key"),
            Self::Web => write!(f, "web"),
            Self::WebVh => write!(f, "webvh"),
        }
    }
}

/// Returns DID-specific errors.
pub type Result<T> = std::result::Result<T, Error>;

/// [`SignerExt`] is used to provide public key material that can be used for
/// signature verification.
/// 
/// Extends the `credibil_infosec::Signer` trait.
pub trait SignerExt: Signer + Send + Sync {
    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    ///
    /// Async and fallible because the implementer may need to access key
    /// information to construct the method reference.
    fn verification_method(&self) -> impl Future<Output = anyhow::Result<Key>> + Send;
}

/// [`DidResolver`] is used to proxy the resolution of a DID document. 
///
/// Implementers need only return the DID document specified by the url. This
/// may be by directly dereferencing the URL, looking up a local cache, or
/// fetching from a remote DID resolver, or using a ledger or log that contains
/// DID document versions.
///
/// For example, a DID resolver for `did:web` would fetch the DID document from
/// the specified URL. A DID resolver for `did:dht`should forward the request to
/// a remote DID resolver for the DHT network.
pub trait DidResolver: Send + Sync + Clone {
    /// Resolve the DID URL to a DID Document.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID URL cannot be resolved.
    fn resolve(&self, url: &str) -> impl Future<Output = anyhow::Result<Document>> + Send;
}

/// The purpose key material will be used for.
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Serialize, Eq)]
pub enum KeyPurpose {
    /// The document's `verification_method` field.
    VerificationMethod,

    /// The document's `authentication` field.
    Authentication,

    /// The document's `assertion_method` field.
    AssertionMethod,

    /// The document's `key_agreement` field.
    KeyAgreement,

    /// The document's `capability_invocation` field.
    CapabilityInvocation,

    /// The document's `capability_delegation` field.
    CapabilityDelegation,
}

impl Display for KeyPurpose {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationMethod => write!(f, "verificationMethod"),
            Self::Authentication => write!(f, "authentication"),
            Self::AssertionMethod => write!(f, "assertionMethod"),
            Self::KeyAgreement => write!(f, "keyAgreement"),
            Self::CapabilityInvocation => write!(f, "capabilityInvocation"),
            Self::CapabilityDelegation => write!(f, "capabilityDelegation"),
        }
    }
}

impl FromStr for KeyPurpose {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "verificationMethod" => Ok(Self::VerificationMethod),
            "authentication" => Ok(Self::Authentication),
            "assertionMethod" => Ok(Self::AssertionMethod),
            "keyAgreement" => Ok(Self::KeyAgreement),
            "capabilityInvocation" => Ok(Self::CapabilityInvocation),
            "capabilityDelegation" => Ok(Self::CapabilityDelegation),
            _ => Err(anyhow!("Invalid key purpose").into()),
        }
    }
}
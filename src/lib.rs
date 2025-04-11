//! # DID Operations and Resolver
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations
//! for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

// TODO: add support for the following:
//   key type: EcdsaSecp256k1VerificationKey2019 | JsonWebKey2020 |
// Ed25519VerificationKey2020 |             Ed25519VerificationKey2018 |
// X25519KeyAgreementKey2019   crv: Ed25519 | secp256k1 | P-256 | P-384 | p-521

pub mod core;
pub mod document;
mod error;
pub mod jwk;
pub mod key;
pub mod proof;
mod resolve;
pub mod web;
pub mod webvh;
mod url;

use std::{fmt::{Display, Formatter}, future::Future, str::FromStr};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

pub use credibil_infosec::{Curve, KeyType, PublicKeyJwk};
pub use document::*;
pub use resolve::*;
pub use error::Error;
pub use url::*;

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
const X25519_CODEC: [u8; 2] = [0xec, 0x01];

/// DID methods supported by this crate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// The `did:jwk` method.
    Jwk,

    /// The `did:key` method.
    #[default]
    Key,

    /// The `did:web` method.
    Web,

    /// The `did:webvh` method.
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
            "jwk" => Ok(Self::Jwk),
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
            Self::Jwk => write!(f, "jwk"),
            Self::Key => write!(f, "key"),
            Self::Web => write!(f, "web"),
            Self::WebVh => write!(f, "webvh"),
        }
    }
}

/// Returns DID-specific errors.
pub type Result<T> = std::result::Result<T, Error>;

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

/// [`DidOperator`] is used by implementers to provide material required for DID
/// document operations — creation, update, etc.
pub trait DidOperator: Send + Sync {
    /// Provides verification material to be used for the specified
    /// verification method.
    fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk>;
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
//! # DID Operations and Resolver
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations
//! for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::anyhow;

mod document;
pub mod key;
mod resolve;
mod url;
pub mod web;
pub mod webvh;

pub use document::{
    Document, DocumentBuilder, DocumentMetadata, DocumentMetadataBuilder, KeyEncoding, KeyId,
    KeyPurpose, MethodType, Service, ServiceBuilder, VerificationMethod, VerificationMethodBuilder,
};
pub use resolve::{Resource, deref_url, dereference, document_resource};
pub use url::{QueryParams, Url};

// TODO: set context based on key format:
// - Ed25519VerificationKey2020	https://w3id.org/security/suites/ed25519-2020/v1
// - JsonWebKey2020	https://w3id.org/security/suites/jws-2020/v1
// Perhaps this needs to be an enum with Display impl?
/// Candidate contexts to add to a DID document.
pub const BASE_CONTEXT: [&str; 3] = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
];

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
    type Err = anyhow::Error;

    /// Parse a string into a [`Method`].
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid method.
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "key" => Ok(Self::Key),
            "web" => Ok(Self::Web),
            "webvh" => Ok(Self::WebVh),
            _ => Err(anyhow!("method not supported: {s}")),
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

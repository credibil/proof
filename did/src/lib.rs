//! # DID Operations and Resolver
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations
//! for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

pub mod key;
pub mod web;
pub mod webvh;

mod document;
mod proof;
mod provider;
mod resolve;
mod service;
mod url;
mod verification;

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use credibil_ecc::{Entry, Signer};
use credibil_jose::PublicKeyJwk;

pub use self::document::*;
pub use self::provider::*;
pub use self::resolve::{Resource, deref_url, dereference, document_resource};
pub use self::service::*;
pub use self::url::{QueryParams, Url};
pub use self::verification::*;
// use crate::provider::{IdentityResolver, Signature, VerifyBy};

/// Retrieve the JWK specified by the provided DID URL.
///
/// # Errors
///
/// TODO: Document errors
pub async fn did_jwk(did_url: &str, resolver: &impl IdentityResolver) -> Result<PublicKeyJwk> {
    let deref = crate::dereference(did_url, resolver)
        .await
        .map_err(|e| anyhow!("issue dereferencing DID URL {did_url}: {e}"))?;
    let Resource::VerificationMethod(vm) = deref else {
        return Err(anyhow!("Identity method not found"));
    };
    vm.key.jwk().map_err(|e| anyhow!("JWK not found: {e}"))
}

impl Signature for Entry {
    async fn verification_method(&self) -> Result<VerifyBy> {
        let vk = self.verifying_key().await?;
        let jwk = PublicKeyJwk::from_bytes(&vk)?;
        let vm = key::did_from_jwk(&jwk)?;
        Ok(VerifyBy::KeyId(vm))
    }
}

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

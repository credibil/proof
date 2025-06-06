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
pub mod proof;
mod provider;

use anyhow::{Result, anyhow};
use credibil_ecc::{Entry, Signer};
use credibil_jose::PublicKeyJwk;
pub use provider::*;
pub use {credibil_ecc as ecc, credibil_jose as jose};

use crate::did::Resource;

/// Retrieve the JWK specified by the provided DID URL.
///
/// # Errors
///
/// TODO: Document errors
pub async fn did_jwk(did_url: &str, resolver: &impl IdentityResolver) -> Result<PublicKeyJwk> {
    let deref = did::dereference(did_url, resolver)
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
        let vm = did::key::did_from_jwk(&jwk)?;
        Ok(VerifyBy::KeyId(vm))
    }
}

//! # Proof

mod create;
mod provider;

use anyhow::{Result, anyhow};
pub use credibil_did::{ProofResolver, ProofType, Signature, VerifyBy};
use credibil_ecc::{Entry, Signer};
use credibil_jose::PublicKeyJwk;
pub use {credibil_did as did, credibil_ecc as ecc, credibil_jose as jose};

pub use self::create::*;
pub use self::provider::*;

/// Retrieve the JWK specified by the provided DID URL.
///
/// # Errors
///
/// TODO: Document errors
pub async fn did_jwk(did_url: &str, resolver: &impl ProofResolver) -> Result<PublicKeyJwk> {
    let deref = crate::dereference(did_url, resolver)
        .await
        .map_err(|e| anyhow!("issue dereferencing DID URL {did_url}: {e}"))?;
    let Resource::VerificationMethod(vm) = deref else {
        return Err(anyhow!("ProofType method not found"));
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

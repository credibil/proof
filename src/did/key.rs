//! # DID Key
//!
//! The `did:key` method is a DID method for static cryptographic keys. At its
//! core, it is based on expanding a cryptographic public key into a DID
//! Document.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-key>
//! - <https://w3c.github.io/did-resolution>

mod resolve;

use credibil_jose::PublicKeyJwk;
pub use resolve::*;

/// Construct a `did:key` from a public key.
///
/// # Errors
/// Will fail if the public key cannot be converted to multibase form.
pub fn did_from_jwk(jwk: &PublicKeyJwk) -> anyhow::Result<String> {
    let multi = jwk.to_multibase()?;
    Ok(format!("did:key:{multi}#{multi}"))
}

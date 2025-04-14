//! # DID Key URL helpers

use credibil_infosec::PublicKeyJwk;

/// Construct a `did:key` DID from a public key that is in JWK format.
/// 
/// # Errors
/// Will return an error if the JWK cannot be converted to a multibase key.
pub fn did_from_jwk(jwk: &PublicKeyJwk) -> anyhow::Result<String> {
    let mb = jwk.to_multibase()?;
    Ok(format!("did:key:{mb}#{mb}"))
}

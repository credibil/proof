//! Helper functions for hashing and multi-hashing data, and generating random strings.

use base64ct::{Base64UrlUnpadded, Encoding};
use multihash::Multihash;
use olpc_cjson::CanonicalFormatter;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{error::Err, tracerr, Result};

const SHA2_256: u64 = 0x12;

/// Transforms the provided data into a base64-encoded multihash. It creates canonical JSON,
/// multi-hashes it using SHA256, and then base64-encodes the result.
/// See [JSON Canonicalization Scheme (JCS)](https://identity.foundation/JCS/) for details.
///
/// # Arguments
///
/// * `data` - The data to hash.
///
/// # Returns
///
/// A base64-encoded multi-hash of the data.
///
/// # Errors
///
/// * Serialization error if the data cannot be serialized.
/// * Multi-hash error if the data cannot be hashed.
pub fn hash_data(data: &impl Serialize) -> Result<String> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    data.serialize(&mut ser)?;
    let multi = multi_hash(&buf)?;
    Ok(Base64UrlUnpadded::encode_string(&multi))
}

/// Hash the public key by hashing the canoncial JSON representation and then multi-hashing the
/// hash.
///
/// # Arguments
///
/// * `data` - The public key data to hash.
///
/// # Returns
///
/// A base64-encoded multi-hash of the public key.
///
/// # Errors
///
/// * Serialization error if the public key cannot be serialized.
/// * Multi-hash error if the public key cannot be hashed.
pub fn hash_commitment(data: &impl Serialize) -> Result<String> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    data.serialize(&mut ser)?;
    let hashed = hash_bytes(&buf);
    let multi = multi_hash(&hashed)?;
    Ok(Base64UrlUnpadded::encode_string(&multi))
}

/// Hashes the provided data using SHA256.
fn hash_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Multi-hashes the provided data using SHA256.
fn multi_hash(data: &[u8]) -> Result<Vec<u8>> {
    let hashed = hash_bytes(data);
    let mhash = Multihash::<64>::wrap(SHA2_256, &hashed)?;
    Ok(mhash.to_bytes())
}

/// Check the provided string is a valid multi-hash.
///
/// # Arguments
///
/// * `hash` - The hash to check.
///
/// # Returns
///
/// An `Ok` result if the hash is valid, otherwise an `Err` result.
///
/// # Errors
///
/// * `InvalidHash` - The hash is not a valid multi-hash.
pub fn check(hash: &str) -> Result<()> {
    let decoded = Base64UrlUnpadded::decode_vec(hash)?;
    let wrapped = Multihash::<64>::from_bytes(&decoded)?;
    if wrapped.code() != SHA2_256 {
        tracerr!(Err::InvalidHash, "Invalid hash code: {}", wrapped.code());
    }
    Ok(())
}

/// Random hex string generator
#[must_use]
pub fn rand_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Jwk;

    #[test]
    fn multi_hash_ok() {
        let data = b"Hello, world!";

        let mhash = multi_hash(data).expect("failed to create multi-hash");
        let wrapped = Multihash::<64>::from_bytes(&mhash).expect("failed to wrap multi-hash");

        let mut sha = Sha256::new();
        sha.update(data);
        let hash = sha.finalize();

        assert_eq!(wrapped.digest(), &hash[..]);
    }

    #[test]
    fn hash_data_ok() {
        #[derive(Serialize)]
        struct Msg {
            msg: String,
        }
        let data = Msg {
            msg: "Hello, world!".to_string(),
        };

        let hash = hash_data(&data).expect("failed to create multi-hash");
        let decoded = Base64UrlUnpadded::decode_vec(&hash).expect("failed to decode hash");

        let wrapped = Multihash::<64>::from_bytes(&decoded).expect("failed to wrap multi-hash");
        assert_eq!(wrapped.code(), SHA2_256);
    }

    #[test]
    fn hash_commitment_ok() {
        let key = Jwk {
            kty: "EC".to_string(),
            crv: Some("secp256k1".to_string()),
            x: Some("nIqlRCx0eyBSXcQnqDpReS;v4zuWhwCRWssoc9L_nj6A".to_string()),
            y: Some("iG29VK6l2U5sKBZUSJePvyFusXgSlK2dDFlWaCM8F7k".to_string()),
            ..Default::default()
        };

        let hash = hash_commitment(&key);
        assert!(hash.is_ok());
    }
}

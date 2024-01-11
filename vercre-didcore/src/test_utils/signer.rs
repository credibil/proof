//! Signer for use in tests. Uses a hard-coded key.
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::{
    signature::{Signer as EcdsaSigner, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use k256::Secp256k1;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::Err;
use crate::keys::{signer::Signer, Algorithm, KeyOperation};
use crate::{tracerr, Result};

/// Sample signing key structure for testing purposes.
#[derive(Serialize)]
pub struct SignKey {
    d: String,
    kty: String,
    crv: String,
    x: String,
    y: String,
}

// Elliptic curve signing key using the secp256k1 curve. To arrive at the hard-coded values for this
// key you can use the following code:
// let sk = k256::SecretKey::random(&mut OsRng);
// let j = sk.to_jwk_string();
// println!("jwk: {:#?}", j);
impl SignKey {
    fn new() -> Self {
        // jwkEs256k1Private
        Self {
            d: "CB6W6NKEuI4uiYiyM2CM4YzczOYXdx-ykAe5rlZaB-Q".to_string(),
            kty: "EC".to_string(),
            crv: "secp256k1".to_string(),
            x: "XFl4fd9n4qp2Gcc2_oqqUsI3uT63o3Jt0f54DiNOijw".to_string(),
            y: "IH_q19UKDu_jkIwtehWU7NiaXk7CaGoD-XRcuuqcgQ0".to_string(),
        }
    }
}

/// Test signer for use in tests.
#[derive(Default)]
pub struct Test {}

#[allow(async_fn_in_trait)]
impl Signer for Test {
    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![Algorithm::Secp256k1]
    }

    async fn try_sign_op(
        &self,
        msg: &[u8],
        _: &KeyOperation,
        _: Option<Algorithm>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        let hdr_b = serde_json::to_vec(&json!({"alg": Algorithm::Secp256k1.to_string()}))
            .expect("failed to serialize");
        let hdr_64 = Base64UrlUnpadded::encode_string(&hdr_b);
        let msg_64 = Base64UrlUnpadded::encode_string(msg);
        let mut payload = [hdr_64.as_bytes(), b".", msg_64.as_bytes()].concat();
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        let sign_key = SignKey::new();
        let d_b = Base64UrlUnpadded::decode_vec(&sign_key.d).expect("failed to decode");
        let key: SigningKey<Secp256k1> =
            SigningKey::from_slice(&d_b).expect("failed to create key");
        let sig: Signature<Secp256k1> = key.sign(&digest);
        let encoded_sig = Base64UrlUnpadded::encode_string(&sig.to_bytes());

        payload.extend(b".");
        payload.extend(encoded_sig.as_bytes());
        Ok((payload, None))
    }

    async fn verify(&self, msg: &[u8], signature: &[u8], _: Option<&str>) -> Result<()> {
        let hdr_b = serde_json::to_vec(&json!({"alg": Algorithm::Secp256k1.to_string()}))
            .expect("failed to serialize");
        let hdr_64 = Base64UrlUnpadded::encode_string(&hdr_b);
        let msg_64 = Base64UrlUnpadded::encode_string(msg);
        let payload = [hdr_64.as_bytes(), b".", msg_64.as_bytes()].concat();
        let digest: [u8; 32] = Sha256::digest(payload).into();

        let sign_key = SignKey::new();

        let mut sec1 = vec![0x04];
        let mut x = match Base64UrlUnpadded::decode_vec(&sign_key.x) {
            Ok(x) => x,
            Err(e) => panic!("Error decoding x coordinate: {e}"),
        };
        sec1.append(&mut x);
        let mut y = match Base64UrlUnpadded::decode_vec(&sign_key.y) {
            Ok(y) => y,
            Err(e) => panic!("Error decoding x coordinate: {e}"),
        };
        sec1.append(&mut y);
        let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
            Ok(vk) => vk,
            Err(e) => panic!("Error creating verifying key: {e}"),
        };

        let mut decoded_signature = [0u8; 128];
        let decoded_sig = Base64UrlUnpadded::decode(signature, &mut decoded_signature)?;
        let sig = Signature::<k256::Secp256k1>::from_slice(decoded_sig)?;

        match vk.verify(&digest, &sig) {
            Ok(()) => Ok(()),
            Err(e) => tracerr!(
                Err::FailedSignatureVerification,
                "Error verifying signature: {}",
                e
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::{
        elliptic_curve::SecretKey,
        signature::{Signer as EcdsaSigner, Verifier},
        Signature, SigningKey,
    };
    use rand::rngs::OsRng;

    use crate::keys::signer::Signer;

    #[test]
    fn demo_sign_verify() {
        let msg = b"hello world";

        // package and sign
        let hdr_b = serde_json::to_vec(&json!({"alg": "ES256K"})).expect("failed to serialize");
        let hdr_64 = Base64UrlUnpadded::encode_string(&hdr_b);
        let msg_64 = Base64UrlUnpadded::encode_string(msg);
        let mut payload = [hdr_64.as_bytes(), b".", msg_64.as_bytes()].concat();
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        let sk = SecretKey::<k256::Secp256k1>::random(&mut OsRng);
        let j = sk.to_jwk_string();
        println!("private key: {:#?}", j);

        let pk = sk.public_key();
        let j = pk.to_jwk_string();
        println!("public key: {:#?}", j);

        let sign_key = SigningKey::from(sk);
        let raw_sig: Signature<k256::Secp256k1> = sign_key.sign(&digest);
        println!("raw_sig: {:#?}", raw_sig);
        let encoded_sig = Base64UrlUnpadded::encode_string(&raw_sig.to_bytes());
        payload.extend(b".");
        payload.extend(encoded_sig.as_bytes());

        let data = String::from_utf8(payload).expect("failed to convert bytes to string");
        println!("data: {}", data);

        // unpackage and verify
        let parts = data.rsplit_once('.').expect("expected two parts but got none");
        let payload = parts.0.as_bytes();
        let digest: [u8; 32] = Sha256::digest(payload).into();

        let encoded_sig = parts.1;
        let decoded_sig = Base64UrlUnpadded::decode_vec(encoded_sig).expect("failed to decode");
        let raw_sig = Signature::<k256::Secp256k1>::from_slice(&decoded_sig)
            .expect("failed to create signature");

        let vk = sign_key.verifying_key();
        assert!(vk.verify(&digest, &raw_sig).is_ok());
    }

    #[tokio::test]
    async fn sign_then_verify() {
        let msg = b"hello world";
        let signer = Test {};
        let (signed, _) = signer.try_sign(msg, None).await.expect("failed to sign");
        let parts = signed.split(|s| *s == b'.').collect::<Vec<&[u8]>>();
        assert_eq!(parts.len(), 3);
        let sig = parts[2];
        signer.verify(msg, sig, None).await.expect("failed to verify");
    }
}

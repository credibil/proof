//! # DID Key Operations
//!
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Key.
//!
//! See <https://w3c-ccg.github.io/did-method-key>

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde_json::json;

use super::DidJwk;
use crate::core::Kind;
use crate::document::{CreateOptions, Document, MethodType, PublicKeyFormat, VerificationMethod};
use crate::error::Error;
use crate::{DidOperator, KeyPurpose};

impl DidJwk {
    /// Create operation for `did:jwk`.
    /// 
    /// # Errors
    /// TODO: Document errors
    pub fn create(op: &impl DidOperator, options: CreateOptions) -> crate::Result<Document> {
        let Some(verifying_key) = op.verification(KeyPurpose::VerificationMethod) else {
            return Err(Error::Other(anyhow!("no verification key")));
        };

        let serialized = serde_json::to_vec(&verifying_key)
            .map_err(|e| Error::Other(anyhow!("issue serializing key: {e}")))?;
        let encoded = Base64UrlUnpadded::encode_string(&serialized);
        let did = format!("did:jwk:{encoded}");

        // key agreement
        // <https://w3c-ccg.github.io/did-method-key/#encryption-method-creation-algorithm>
        let key_agreement = if options.enable_encryption_key_derivation {
            let key_bytes = Base64UrlUnpadded::decode_vec(&verifying_key.x)
                .map_err(|e| Error::InvalidPublicKey(format!("issue decoding key: {e}")))?;

            // derive an X25519 public encryption key from the Ed25519 key
            let edwards_y = CompressedEdwardsY::from_slice(&key_bytes).map_err(|e| {
                Error::InvalidPublicKey(format!("public key is not Edwards Y: {e}"))
            })?;
            let Some(edwards_pt) = edwards_y.decompress() else {
                return Err(Error::InvalidPublicKey(
                    "Edwards Y cannot be decompressed to point".into(),
                ));
            };
            let x25519_bytes = edwards_pt.to_montgomery().to_bytes();

            let mut jwk = verifying_key.clone();
            jwk.x = Base64UrlUnpadded::encode_string(&x25519_bytes);
            let method_type = MethodType::JsonWebKey2020;
            let key_format = PublicKeyFormat::PublicKeyJwk { public_key_jwk: jwk };

            Some(vec![Kind::Object(VerificationMethod {
                id: format!("{did}#key-1"),
                controller: did.clone(),
                type_: method_type,
                key: key_format,
                ..VerificationMethod::default()
            })])
        } else {
            None
        };

        let verif_type = &options.method_type;
        let context = Kind::Object(json!({
            "publicKeyJwk": {
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
            },
            verif_type.to_string(): format!("https://w3id.org/security#{verif_type}"),
        }));

        let kid = format!("{did}#key-0");

        let key_format = match options.method_type {
            MethodType::Multikey
            | MethodType::Ed25519VerificationKey2020
            | MethodType::X25519KeyAgreementKey2020 => {
                // multibase encode the public key
                PublicKeyFormat::PublicKeyMultibase {
                    public_key_multibase: verifying_key.to_multibase()?,
                }
            }
            MethodType::JsonWebKey2020 | MethodType::EcdsaSecp256k1VerificationKey2019 => {
                PublicKeyFormat::PublicKeyJwk {
                    public_key_jwk: verifying_key,
                }
            }
        };

        Ok(Document {
            context: vec![Kind::String(options.default_context), context],
            id: did.clone(),
            verification_method: Some(vec![VerificationMethod {
                id: kid.clone(),
                controller: did,
                type_: options.method_type,
                key: key_format,
                ..VerificationMethod::default()
            }]),
            authentication: Some(vec![Kind::String(kid.clone())]),
            assertion_method: Some(vec![Kind::String(kid.clone())]),
            capability_invocation: Some(vec![Kind::String(kid.clone())]),
            capability_delegation: Some(vec![Kind::String(kid)]),
            key_agreement,
            ..Document::default()
        })
    }

    #[allow(dead_code)]
    /// Read operation for `did:jwk`.
    /// 
    /// # Errors
    /// TODO: Document errors
    pub fn read(_did: &str, _: CreateOptions) -> crate::Result<Document> {
        // self.resolve(did, options)
        unimplemented!("read")
    }
}

#[cfg(test)]
mod test {
    use credibil_infosec::{Curve, KeyType, PublicKeyJwk};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn create() {
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let op = Operator;
        let res = DidJwk::create(&op, options).expect("should create");

        let json = serde_json::to_string_pretty(&res).expect("should serialize");
        println!("{json}");
    }

    struct Operator;
    impl DidOperator for Operator {
        fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
            match purpose {
                KeyPurpose::VerificationMethod => {
                    let key = generate();

                    Some(PublicKeyJwk {
                        kty: KeyType::Okp,
                        crv: Curve::Ed25519,
                        x: Base64UrlUnpadded::encode_string(&key),
                        ..PublicKeyJwk::default()
                    })
                }
                _ => panic!("unsupported purpose"),
            }
        }
    }

    // HACK: generate a key pair
    #[allow(dead_code)]
    pub fn generate() -> Vec<u8> {
        // TODO: pass in public key
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let secret = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        println!("signing: {secret}");

        signing_key.verifying_key().to_bytes().to_vec()
    }
}

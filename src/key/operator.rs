//! # DID Key Operations
//!
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Key.
//!
//! See <https://w3c-ccg.github.io/did-method-key>

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use multibase::Base;
use serde_json::json;

use super::DidKey;
use crate::core::Kind;
use crate::document::{CreateOptions, Document, MethodType, PublicKeyFormat, VerificationMethod};
use crate::error::Error;
use crate::{DidOperator, ED25519_CODEC, KeyPurpose, X25519_CODEC};

impl DidKey {
    /// Create a DID Document from the verifying key provided by [`DidOperator`].
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied verifying key is not found or not a
    /// valid format.
    pub fn create(op: &impl DidOperator, options: CreateOptions) -> crate::Result<Document> {
        let Some(verifying_key) = op.verification(KeyPurpose::VerificationMethod) else {
            return Err(Error::Other(anyhow!("no verification key")));
        };
        let key_bytes = Base64UrlUnpadded::decode_vec(&verifying_key.x)
            .map_err(|e| Error::InvalidPublicKey(format!("issue decoding key: {e}")))?;

        let mut multi_bytes = ED25519_CODEC.to_vec();
        multi_bytes.extend_from_slice(&key_bytes);
        let multikey = multibase::encode(Base::Base58Btc, &multi_bytes);

        let did = format!("did:key:{multikey}");

        let context = if options.public_key_format == PublicKeyFormat::Multikey
            || options.public_key_format == PublicKeyFormat::Ed25519VerificationKey2020
        {
            Kind::String("https://w3id.org/security/data-integrity/v1".into())
        } else {
            let verif_type = &options.public_key_format;
            Kind::Object(json!({
                "publicKeyJwk": {
                    "@id": "https://w3id.org/security#publicKeyJwk",
                    "@type": "@json"
                },
                verif_type.to_string(): format!("https://w3id.org/security#{verif_type}"),
            }))
        };

        // key agreement
        // <https://w3c-ccg.github.io/did-method-key/#encryption-method-creation-algorithm>
        let key_agreement = if options.enable_encryption_key_derivation {
            let verifier_bytes: [u8; PUBLIC_KEY_LENGTH] = key_bytes.try_into().map_err(|_| {
                Error::InvalidPublicKey(format!("public key is not {PUBLIC_KEY_LENGTH} bytes"))
            })?;
            let verifier = VerifyingKey::from_bytes(&verifier_bytes).map_err(|e| {
                Error::InvalidPublicKey(format!("public key is not correct size: {e}"))
            })?;
            let x25519_bytes = verifier.to_montgomery().to_bytes();

            // base58B encode the raw key
            let mut multi_bytes = vec![];
            multi_bytes.extend_from_slice(&X25519_CODEC);
            multi_bytes.extend_from_slice(&x25519_bytes);
            let multikey = multibase::encode(Base::Base58Btc, &multi_bytes);

            let method_type = match options.public_key_format {
                PublicKeyFormat::Multikey => MethodType::Multikey {
                    public_key_multibase: multikey.clone(),
                },
                _ => return Err(Error::InvalidPublicKey("Unsupported public key format".into())),
            };

            Some(vec![Kind::Object(VerificationMethod {
                id: format!("{did}#{multikey}"),
                controller: did.clone(),
                method_type,
                ..VerificationMethod::default()
            })])
        } else {
            None
        };

        let kid = format!("{did}#{multikey}");

        let method_type = match options.public_key_format {
            PublicKeyFormat::Multikey => MethodType::Multikey {
                public_key_multibase: multikey,
            },
            _ => MethodType::JsonWebKey {
                public_key_jwk: verifying_key,
            },
        };

        Ok(Document {
            context: vec![Kind::String(options.default_context), context],
            id: did.clone(),
            verification_method: Some(vec![VerificationMethod {
                id: kid.clone(),
                controller: did,
                method_type,
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
        let res = DidKey::create(&op, options).expect("should create");

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
        let signing_key = SigningKey::generate(&mut OsRng);
        let secret = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        println!("secret: {secret}");

        signing_key.verifying_key().to_bytes().to_vec()
    }
}

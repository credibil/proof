//! # DID Web Operations
//!
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Key.
//!
//! See <https://w3c-ccg.github.io/did-method-web>

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use curve25519_dalek::edwards::CompressedEdwardsY;
use multibase::Base;
use url::Url;

use super::DidWeb;
use crate::core::Kind;
use crate::document::{CreateOptions, Document, MethodType, PublicKeyFormat, VerificationMethod};
use crate::error::Error;
use crate::{DidOperator, ED25519_CODEC, KeyPurpose, X25519_CODEC};

// TODO: request public key from DidOperator for each verification relationship

impl DidWeb {
    /// Create a new DID Document from the provided `did:web` DID URL.
    ///
    /// # Errors
    ///
    /// Will fail if the DID URL is not a valid or the verifying key is invalid.
    pub fn create(
        url: &str, op: &impl DidOperator, options: CreateOptions,
    ) -> crate::Result<Document> {
        // create identifier from url
        let url =
            Url::parse(url).map_err(|e| Error::InvalidDid(format!("issue parsing url: {e}")))?;
        let host = url.host_str().ok_or(Error::InvalidDid("no host in url".into()))?;
        let mut did = format!("did:web:{host}");
        if let Some(path) = url.path().strip_prefix('/')
            && !path.is_empty()
        {
            did = format!("{did}:{}", path.replace('/', ":"));
        }

        // get DID controller's verification key
        let Some(verifying_key) = op.verification(KeyPurpose::VerificationMethod) else {
            return Err(Error::Other(anyhow!("no verification key")));
        };
        let key_bytes = Base64UrlUnpadded::decode_vec(&verifying_key.x)
            .map_err(|e| Error::InvalidPublicKey(format!("issue decoding key: {e}")))?;

        // key agreement
        // <https://w3c-ccg.github.io/did-method-key/#encryption-method-creation-algorithm>
        let key_agreement = if options.enable_encryption_key_derivation {
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

            let method_type = match options.public_key_format {
                PublicKeyFormat::Multikey => {
                    let mut multi_bytes = X25519_CODEC.to_vec();
                    multi_bytes.extend_from_slice(&x25519_bytes);
                    MethodType::Multikey {
                        public_key_multibase: multibase::encode(Base::Base58Btc, &multi_bytes),
                    }
                }
                PublicKeyFormat::JsonWebKey => {
                    let mut jwk = verifying_key.clone();
                    jwk.x = Base64UrlUnpadded::encode_string(&x25519_bytes);
                    MethodType::JsonWebKey { public_key_jwk: jwk }
                }

                _ => return Err(Error::InvalidPublicKey("Unsupported public key format".into())),
            };

            Some(vec![Kind::Object(VerificationMethod {
                id: format!("{did}#key-1"),
                controller: did.clone(),
                method_type,
                ..VerificationMethod::default()
            })])
        } else {
            None
        };

        let kid = format!("{did}#key-0");
        let method_type = match options.public_key_format {
            PublicKeyFormat::Multikey => {
                // multibase encode the public key
                let mut multi_bytes = ED25519_CODEC.to_vec();
                multi_bytes.extend_from_slice(&key_bytes);
                MethodType::Multikey {
                    public_key_multibase: multibase::encode(Base::Base58Btc, &multi_bytes),
                }
            }
            PublicKeyFormat::JsonWebKey => MethodType::JsonWebKey {
                public_key_jwk: verifying_key,
            },
            _ => return Err(Error::InvalidPublicKey("Unsupported public key format".into())),
        };

        let context = Kind::String("https://w3id.org/security/data-integrity/v1".into());

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

    // #[allow(dead_code)]
    // pub fn read(_did: &str, _: CreateOptions) -> crate::Result<Document> {
    //     // self.create(did, options)
    //     unimplemented!("read")
    // }
}

#[cfg(test)]
mod test {
    use credibil_infosec::{Curve, KeyType, PublicKeyJwk};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    struct MockOperator;
    impl DidOperator for MockOperator {
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

    #[test]
    fn create() {
        let url = "https://demo.credibil.io/entity/funder";
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let op = MockOperator;
        let res = DidWeb::create(url, &op, options).expect("should create");

        let json = serde_json::to_string_pretty(&res).expect("should serialize");
        println!("{json}");
    }

    #[test]
    fn create_2() {
        let url = "https://demo.credibil.io/entity/funder";
        let mut options = CreateOptions::default();
        options.enable_encryption_key_derivation = true;

        let op = MockOperator;
        let res = DidWeb::create(url, &op, options).expect("should create");

        let json = serde_json::to_string_pretty(&res).expect("should serialize");
        println!("{json}");
    }

    // generate a key pair
    pub fn generate() -> Vec<u8> {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let secret = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        println!("signing: {secret}");

        signing_key.verifying_key().to_bytes().to_vec()
    }
}

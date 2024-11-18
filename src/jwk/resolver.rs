//! # DID Key Resolver
//!
//! The `did:key` method is a DID method for static cryptographic keys. At its
//! core, it is based on expanding a cryptographic public key into a DID
//! Document.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-key>
//! - <https://w3c.github.io/did-resolution>

use std::sync::LazyLock;

use base64ct::{Base64UrlUnpadded, Encoding};
use regex::Regex;
use serde_json::json;

use super::DidJwk;
use crate::document::{CreateOptions, MethodType};
use crate::error::Error;
use crate::resolution::{ContentType, Metadata, Options, Resolved};
use crate::{DidOperator, DidResolver, KeyPurpose, PublicKeyJwk};

static DID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^did:jwk:(?<jwk>[A-Za-z0-9-=—]+)$").expect("should compile"));

struct Operator(MethodType);
impl DidOperator for Operator {
    fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
        match purpose {
            KeyPurpose::VerificationMethod => self.0.jwk().ok(),
            _ => panic!("unsupported purpose"),
        }
    }
}

impl DidJwk {
    pub fn resolve(did: &str, _: Option<Options>, _: impl DidResolver) -> crate::Result<Resolved> {
        // check DID is valid AND extract key
        let Some(caps) = DID_REGEX.captures(did) else {
            return Err(Error::InvalidDid("DID is not a valid did:jwk".into()));
        };
        // let enc = &caps["jwk"];

        let decoded = Base64UrlUnpadded::decode_vec(&caps["jwk"])
            .map_err(|e| Error::InvalidDid(format!("issue decoding key: {e}")))?;
        let jwk = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidDid(format!("issue deserializing key: {e}")))?;
        let op = Operator(MethodType::JsonWebKey { public_key_jwk: jwk });

        // per the spec, use the create operation to generate a DID document
        let options = CreateOptions {
            enable_encryption_key_derivation: true,
            ..CreateOptions::default()
        };

        let document = Self::create(op, options).map_err(|e| Error::InvalidDid(e.to_string()))?;

        Ok(Resolved {
            context: "https://w3id.org/did-resolution/v1".into(),
            metadata: Metadata {
                content_type: ContentType::DidLdJson,
                additional: Some(json!({
                    "pattern": "^did:jwk:[A-Za-z0-9-=—]+$",
                    "did": {
                        "didString": did,
                        "methodSpecificId": did[8..],
                        "method": "jwk"
                    }
                })),
                ..Metadata::default()
            },
            document: Some(document),
            ..Resolved::default()
        })
    }
}

#[cfg(test)]
mod test {
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;
    use crate::document::Document;

    const DID: &str = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiJKSnpQaTRxeTJydktTVk85RjItMDVWV2VYMm9oc3dYN1NUbzg3TUdxcVB3IiwieSI6IkMxUnRGbnFXOWxOTEI1ejcycG9uMTIzZHh2MWtEcVUzUWw1QjhzMFdjXzQifQ";

    #[derive(Clone)]
    struct MockResolver;
    impl DidResolver for MockResolver {
        async fn resolve(&self, _url: &str) -> anyhow::Result<Document> {
            Ok(Document::default())
        }
    }

    #[tokio::test]
    async fn resolve() {
        let resolved = DidJwk::resolve(DID, None, MockResolver).expect("should resolve");
        assert_snapshot!("resolved", resolved);
    }
}

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

use regex::Regex;
use serde_json::json;

use super::DidKey;
use crate::document::{CreateOptions, PublicKeyFormat};
use crate::error::Error;
use crate::operation::resolve::{ContentType, Metadata, Resolved};
use crate::{DidOperator, KeyPurpose, PublicKeyJwk};

static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:(?<identifier>z[a-km-zA-HJ-NP-Z1-9]+)$").expect("should compile")
});

struct Operator(PublicKeyFormat);
impl DidOperator for Operator {
    fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
        match purpose {
            KeyPurpose::VerificationMethod => self.0.jwk().ok(),
            _ => panic!("unsupported purpose"),
        }
    }
}

impl DidKey {
    /// Resolve the provided `did:key` URL to a DID Document.
    /// 
    /// # Errors
    /// 
    /// Will fail if the DID is not a valid `did:key` URL.
    pub fn resolve(did: &str) -> crate::Result<Resolved> {
        // check DID is valid AND extract key
        let Some(caps) = DID_REGEX.captures(did) else {
            return Err(Error::InvalidDid("DID is not a valid did:key".into()));
        };
        let multikey = &caps["identifier"];

        let op = Operator(PublicKeyFormat::PublicKeyMultibase {
            public_key_multibase: multikey.to_string(),
        });

        // per the spec, use the create operation to generate a DID document
        let options = CreateOptions {
            enable_encryption_key_derivation: true,
            ..CreateOptions::default()
        };

        let document = Self::create(&op, options).map_err(|e| Error::InvalidDid(e.to_string()))?;

        Ok(Resolved {
            context: "https://w3id.org/did-resolution/v1".into(),
            metadata: Metadata {
                content_type: ContentType::DidLdJson,
                additional: Some(json!({
                    "pattern": "^did:key:z[a-km-zA-HJ-NP-Z1-9]+$",
                    "did": {
                        "didString": did,
                        "methodSpecificId": did[8..],
                        "method": "key"
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
    use super::*;

    // const DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";

    #[tokio::test]
    async fn resolve() {
        let resolved = DidKey::resolve(DID).expect("should resolve");
        println!("{}", serde_json::to_string_pretty(&resolved).unwrap());
        // assert_snapshot!("resolved", resolved);
    }
}

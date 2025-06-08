//! # DID Document
//!
//! A DID Document is a JSON-LD document that contains information related to a
//! DID.

use anyhow::Result;
use credibil_jose::PublicKeyJwk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::Kind;

/// A DID document can express verification methods, such as cryptographic
/// public keys, which can be used to authenticate or authorize interactions
/// with the DID subject or associated parties.
///
/// For example, a cryptographic
/// public key can be used as a verification method with respect to a digital
/// signature; in such usage, it verifies that the signer could use the
/// associated cryptographic private key. Verification methods might take many
/// parameters. An example of this is a set of five cryptographic keys from
/// which any three are required to contribute to a cryptographic threshold
/// signature.
///
/// MAY include additional properties which can be determined from the
/// verification method as registered in the
/// [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Only used when the verification method uses terms not defined in the
    /// containing document.
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Kind<Value>>,

    /// A DID that identifies the verification method.
    pub id: String,

    /// The DID of the controller of the verification method.
    pub controller: String,

    /// The format of the public key material.
    #[serde(flatten)]
    pub key: KeyFormat,
}

impl VerificationMethod {
    /// Infer the DID from the key ID.
    #[must_use]
    pub fn did(&self) -> String {
        self.id.split('#').next().unwrap_or_default().to_string()
    }
}

/// The format of the public key material.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all_fields = "camelCase")]
#[serde(tag = "type")]
pub enum KeyFormat {
    /// The key is encoded as a Multibase string.
    Multikey {
        /// The public key encoded as a Multibase.
        public_key_multibase: String,
    },

    /// The key is encoded as a JWK.
    JsonWebKey {
        /// The public key encoded as a JWK.
        public_key_jwk: PublicKeyJwk,
    },
}

impl Default for KeyFormat {
    fn default() -> Self {
        Self::Multikey {
            public_key_multibase: String::new(),
        }
    }
}

impl KeyFormat {
    /// Return the key as a JWK
    ///
    /// # Errors
    /// Will return an error if the key is multibase encoded and cannot be
    /// decoded.
    pub fn jwk(&self) -> Result<PublicKeyJwk> {
        match self {
            Self::JsonWebKey { public_key_jwk } => Ok(public_key_jwk.clone()),
            Self::Multikey { public_key_multibase } => {
                PublicKeyJwk::from_multibase(public_key_multibase)
            }
        }
    }

    /// Return the key as a multibase string.
    ///
    /// # Errors
    /// Will return an error if the key is a JWK and cannot be encoded as a
    /// multibase string.
    pub fn multibase(&self) -> Result<String> {
        match self {
            Self::JsonWebKey { public_key_jwk } => public_key_jwk.to_multibase(),
            Self::Multikey { public_key_multibase } => Ok(public_key_multibase.clone()),
        }
    }
}

impl From<PublicKeyJwk> for KeyFormat {
    fn from(jwk: PublicKeyJwk) -> Self {
        Self::JsonWebKey { public_key_jwk: jwk }
    }
}

impl From<String> for KeyFormat {
    fn from(multibase: String) -> Self {
        Self::Multikey {
            public_key_multibase: multibase,
        }
    }
}

/// A builder for creating a verification method.
#[derive(Default)]
pub struct VerificationMethodBuilder {
    key: KeyFormat,
    did: String,
    id_type: KeyId,
    // method_type: MethodType,
}

impl VerificationMethodBuilder {
    /// Creates a new `VerificationMethodBuilder` with the given public key.
    #[must_use]
    pub fn new(key: impl Into<KeyFormat>) -> Self {
        Self {
            key: key.into(),
            ..Default::default()
        }
    }

    /// Specify how to construct the key ID.
    #[must_use]
    pub fn did(mut self, did: impl Into<String>) -> Self {
        self.did = did.into();
        self
    }

    /// Specify how to construct the key ID.
    #[must_use]
    pub fn key_id(mut self, id_type: KeyId) -> Self {
        self.id_type = id_type;
        self
    }

    /// Build the verification method.
    ///
    /// # Errors
    ///
    /// Will fail if the key format does not match the method type, or if the
    /// key cannot be converted to a multibase string or JWK.
    pub fn build(self) -> Result<VerificationMethod> {
        let suffix = match self.id_type {
            KeyId::Did => String::new(),
            KeyId::Authorization(auth_key) => format!("#{auth_key}"),
            KeyId::Verification => {
                let mb = match &self.key {
                    KeyFormat::JsonWebKey { public_key_jwk } => public_key_jwk.to_multibase()?,
                    KeyFormat::Multikey { public_key_multibase } => public_key_multibase.clone(),
                };
                format!("#{mb}")
            }
            KeyId::Index(index) => format!("#{index}"),
        };

        Ok(VerificationMethod {
            id: format!("{}{suffix}", self.did),
            controller: self.did,
            key: self.key,
            ..VerificationMethod::default()
        })
    }
}

/// Instruction to the `VerificationMethodBuilder` on how to construct the key
/// ID.
#[derive(Default)]
pub enum KeyId {
    /// Use the DID as the identifier without any fragment.
    #[default]
    Did,

    /// Use the provided multibase authorization key and append to the document
    /// identifier (DID URL).
    Authorization(String),

    /// Use the verification method key from the `DidOperator` to construct a
    /// multibase value to append to the document identifier (DID URL).
    Verification,

    /// Append the document identifier (DID URL) with a prefix and an
    /// incrementing index. Use an empty string for the prefix if only the index
    /// is required.
    ///
    /// # Examples
    ///
    /// `did:<method>:<method-specific-identifier>#key-0`.
    Index(String),
}

/// The purpose key material will be used for.
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Serialize, Eq)]
pub enum KeyPurpose {
    /// The document's `verification_method` field.
    VerificationMethod,

    /// The document's `authentication` field.
    Authentication,

    /// The document's `assertion_method` field.
    AssertionMethod,

    /// The document's `key_agreement` field.
    KeyAgreement,

    /// The document's `capability_invocation` field.
    CapabilityInvocation,

    /// The document's `capability_delegation` field.
    CapabilityDelegation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create() {
        let key = PublicKeyJwk::from_multibase("z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu")
            .unwrap();
        let vm = VerificationMethodBuilder::new(key)
            .did("did:web:example.com")
            .key_id(KeyId::Verification)
            .build()
            .unwrap();

        assert_eq!(vm.id, "did:web:example.com#z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu");
        assert_eq!(vm.controller, "did:web:example.com");
        assert_eq!(
            vm.key,
            KeyFormat::JsonWebKey {
                public_key_jwk: PublicKeyJwk::from_multibase(
                    "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
                )
                .unwrap(),
            }
        );
    }

    #[test]
    fn json_web_key() {
        let jwk = PublicKeyJwk::from_multibase("z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu")
            .unwrap();
        let vm = VerificationMethodBuilder::new(jwk)
            .did("did:web:example.com")
            .key_id(KeyId::Verification)
            .build()
            .unwrap();

        let ser = serde_json::to_value(&vm).unwrap();
        let json = serde_json::json!({
            "id": "did:web:example.com#z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu",
            "controller": "did:web:example.com",
            "type": "JsonWebKey",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "Zmq-CJA17UpFeVmJ-nIKDuDEhUnoRSNIXFbxyBtCh6Y"
            }
        });
        assert_eq!(ser, json,);
    }

    #[test]
    fn multikey() {
        let multikey = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu".to_string();
        let vm = VerificationMethodBuilder::new(multikey)
            .did("did:web:example.com")
            .key_id(KeyId::Verification)
            .build()
            .unwrap();

        let ser = serde_json::to_value(&vm).unwrap();
        let json = serde_json::json!({
            "id": "did:web:example.com#z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu",
            "controller": "did:web:example.com",
            "type": "Multikey",
            "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
        });
        assert_eq!(ser, json,);
    }
}

//! Verification methods allow public keys to be associated with a DID.

use std::{convert::Infallible, fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::keys::Jwk;

/// A DID document can express verification methods, such as cryptographic public keys, which can be
/// used to authenticate or authorize interactions with the DID subject or associated parties.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VerificationMethod {
    /// Identifier for the verification method. The value must be a string that conforms to DID URL
    /// Syntax which can be a relative DID URL that is confined to the DID document. Relative URLs
    /// are assumed by default.
    pub id: String,
    /// The type of verification method. One that is registered in a DID specification registry.
    /// https://www.w3.org/TR/did-spec-registries/
    #[serde(rename = "type")]
    pub type_: String,
    /// Identifier for the controller of the verification method. A DID.
    pub controller: String,
    /// The public key material of the verification method, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Jwk>,
    /// The public key material of the verification method, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    /// Account ID for block-chain based public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_account_id: Option<String>,
}

/// Key purpose type.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyPurpose {
    #[default]
    /// The authentication verification relationship is used to specify how the DID subject is
    /// expected to be authenticated, for purposes such as logging into a website or engaging in
    /// any sort of challenge-response protocol.
    Authentication,
    /// The assertionMethod verification relationship is used to specify how the DID subject is
    /// expected to express claims, such as for the purposes of issuing a Verifiable Credential
    AssertionMethod,
    /// The capabilityInvocation verification relationship is used to specify a verification method
    /// that might be used by the DID subject to invoke a cryptographic capability, such as the
    /// authorization to update the DID Document.
    CapabilityInvocation,
    /// The capabilityDelegation verification relationship is used to specify a mechanism that might
    /// be used by the DID subject to delegate a cryptographic capability to another party, such as
    /// delegating the authority to access a specific HTTP API to a subordinate.
    CapabilityDelegation,
    /// The keyAgreement verification relationship is used to specify how an entity can generate
    /// encryption material in order to transmit confidential information intended for the DID
    /// subject, such as for the purposes of establishing a secure communication channel with the
    /// recipient.
    KeyAgreement,
}

impl Display for KeyPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyPurpose::Authentication => write!(f, "authentication"),
            KeyPurpose::AssertionMethod => write!(f, "assertionMethod"),
            KeyPurpose::CapabilityInvocation => write!(f, "capabilityInvocation"),
            KeyPurpose::CapabilityDelegation => write!(f, "capabilityDelegation"),
            KeyPurpose::KeyAgreement => write!(f, "keyAgreement"),
        }
    }
}

/// A reference to a verification method or an embedded verification method object, as used by the
/// "authentication" and other similar fields in a [`DidDocument`].
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmRelationship {
    /// Key identifier referring to a verification method elsewhere in the DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Embedded verification method object in the case where the verification method is not
    /// referred to by key identifier.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<VerificationMethod>,
}

/// Deserialise a verification method relationship in the case it is a string - the ID of a
/// verification method specified elsewhere in the DID document.
impl FromStr for VmRelationship {
    type Err = Infallible;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            key_id: Some(id.to_string()),
            verification_method: None,
        })
    }
}

/// Partial Equality for verification method relationship.
impl PartialEq for VmRelationship {
    fn eq(&self, other: &Self) -> bool {
        if self.key_id.is_some() && other.key_id.is_some() {
            return self.key_id == other.key_id;
        }
        if let Some(me) = &self.verification_method {
            if let Some(them) = &other.verification_method {
                return me == them;
            }
        }
        false
    }
}
impl Eq for VmRelationship {}

/// Convert a verification method into a verification method relationship. Note that this will only
/// pick up the ID of the verification method to refer to and will *not* embed the verification
/// method itself. If your implementation uses embeded keys, build the reference manually.
impl From<&VerificationMethod> for VmRelationship {
    fn from(vm: &VerificationMethod) -> Self {
        Self {
            key_id: Some(vm.id.clone()),
            verification_method: None,
        }
    }
}

/// Serialize a verification method relationship to a string or object. If the `key_id` field is
/// set, serialize to a string, otherwise serialize to an embedded verification method.
impl Serialize for VmRelationship {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match (&self.key_id, &self.verification_method) {
            (Some(id), None) => serializer.serialize_str(id),
            (None, Some(vm)) => vm.serialize(serializer),
            _ => Err(serde::ser::Error::custom(
                "Verification method reference must be a string or object",
            )),
        }
    }
}

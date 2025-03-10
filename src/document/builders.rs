//! # DID Operations
//!
//! This crate provides helpers for DID operations that are independent of the
//! DID method.
//!
//! See [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-1.0/)
//! for more information.
//!

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::PublicKeyJwk;
use multibase::Base;
use serde_json::Value;

use crate::{core::{Kind, Quota}, ED25519_CODEC};

use super::{Document, DocumentMetadata, MethodType, PublicKeyFormat, Service, VerificationMethod};

/// A builder for creating a DID Document.
#[derive(Default)]
pub struct DocumentBuilder {
    // Document under construction
    doc: Document,
}

impl DocumentBuilder {
    /// Creates a new `DocumentBuilder` with the given DID URL.
    #[must_use]
    pub fn new(did: &str) -> Self {
        let doc = Document {
            id: did.to_string(),
            ..Document::default()
        };
        Self { doc }
    }

    /// Add an also-known-as identifier.
    #[must_use]
    pub fn also_known_as(mut self, aka: &str) -> Self {
        self.doc.also_known_as.get_or_insert(vec![]).push(aka.to_string());
        self
    }

    /// Add a controller.
    /// 
    /// Chain to add multiple controllers.
    #[must_use]
    pub fn controller(mut self, controller: &str) -> Self {
        match self.doc.controller {
            Some(c) => match c {
                Quota::One(cont) => {
                    self.doc.controller = Some(Quota::Many(vec![cont, controller.to_string()]));
                },
                Quota::Many(mut cont) => {
                    cont.push(controller.to_string());
                    self.doc.controller = Some(Quota::Many(cont));
                },
            }
            None => {
                self.doc.controller = Some(Quota::One(controller.to_string()));
            }
        }
        self
    }

    /// Add a service endpoint.
    /// 
    /// Chain to add multiple service endpoints.
    #[must_use]
    pub fn service(mut self, service: &Service) -> Self {
        self.doc.service.get_or_insert(vec![]).push(service.clone());
        self
    }

    /// Add a context.
    ///
    /// Chain to add multiple contexts.
    #[must_use]
    pub fn context(mut self, context: &Kind<Value>) -> Self {
        self.doc.context.push(context.clone());
        self
    }

    /// Add a verification method.
    ///
    /// Chain to add multiple verification methods.
    #[must_use]
    pub fn verification_method(mut self, vm: &VerificationMethod) -> Self {
        self.doc.verification_method.get_or_insert(vec![]).push(vm.clone());
        self
    }

    /// Add a verification relationship.
    ///
    /// Pass the ID of the verification method to associate with the
    /// relationship or a complete `VerificationMethod` instance if a standalone
    /// method is required.
    /// 
    /// Chain to add multiple relationships.
    ///
    /// # Errors
    ///
    /// If this method is used for key agreement, an error will occur if a
    /// standalone verification method is not used.
    pub fn verification_relationship(
        mut self, relationship: &VerificationRelationship, vm: &Kind<VerificationMethod>,
    ) -> anyhow::Result<Self> {
        match relationship {
            VerificationRelationship::Authentication => {
                self.doc.authentication.get_or_insert(vec![]).push(vm.clone());
            }
            VerificationRelationship::AssertionMethod => {
                self.doc.assertion_method.get_or_insert(vec![]).push(vm.clone());
            }
            VerificationRelationship::KeyAgreement => match vm {
                Kind::Object(vm) => {
                    self.doc.key_agreement.get_or_insert(vec![]).push(Kind::Object(vm.clone()));
                }
                Kind::String(_) => {
                    return Err(anyhow!(
                        "key agreement must be handled by the encryption method creation algorithm"
                    ));
                }
            },
            VerificationRelationship::CapabilityInvocation => {
                self.doc.capability_invocation.get_or_insert(vec![]).push(vm.clone());
            }
            VerificationRelationship::CapabilityDelegation => {
                self.doc.capability_delegation.get_or_insert(vec![]).push(vm.clone());
            }
        }
        Ok(self)
    }

    /// Set default metadata with created timestamp and build the DID Document.
    #[must_use]
    pub fn build(mut self) -> Document {
        let md = DocumentMetadata {
            created: chrono::Utc::now(),
            ..Default::default()
        };
        self.doc.did_document_metadata = Some(md);
        self.doc
    }
}

/// Verification relationships.
///
/// <https://www.w3.org/TR/did-1.0/#verification-relationships>
#[derive(Debug, Clone)]
pub enum VerificationRelationship {
    /// <https://www.w3.org/TR/did-1.0/#authentication>
    Authentication,

    /// <https://www.w3.org/TR/did-1.0/#assertion>
    AssertionMethod,

    /// <https://www.w3.org/TR/did-1.0/#key-agreement>
    KeyAgreement,

    /// <https://www.w3.org/TR/did-1.0/#capability-invocation>
    CapabilityInvocation,

    /// <https://www.w3.org/TR/did-1.0/#capability-delegation>
    CapabilityDelegation,
}

/// A builder for creating a verification method.
#[derive(Default)]
pub struct VerificationMethodBuilder {
    vm_key: PublicKeyJwk,
    did: String,
    kid: String,
    method: MethodType,
}

impl VerificationMethodBuilder {
    /// Creates a new `VerificationMethodBuilder` with the given public key.
    #[must_use]
    pub fn new(verifying_key: &PublicKeyJwk) -> Self {
        Self {
            vm_key: verifying_key.clone(),
            ..Default::default()
        }
    }

    /// Specify how to construct the key ID.
    ///
    /// # Errors
    ///
    /// Will fail if the ID type requires a multibase value but construction of
    /// that value fails.
    pub fn key_id(mut self, did: &str, id_type: VmKeyId) -> anyhow::Result<Self> {
        self.did = did.to_string();
        match id_type {
            VmKeyId::Authorization(auth_key) => {
                let mb = auth_key.to_multibase()?;
                self.kid = format!("{did}#{mb}");
            }
            VmKeyId::Verification => {
                let mb = self.vm_key.to_multibase()?;
                self.kid = format!("{did}#{mb}");
            }
            VmKeyId::Index(index) => {
                self.kid = format!("{did}#key-{index}");
            }
        }
        Ok(self)
    }

    /// Specify the public key format.
    ///
    /// # Errors
    ///
    /// Will fail if required format is multibase but the public key cannot be
    /// decoded into bytes.
    pub fn public_key_format(mut self, format: &PublicKeyFormat) -> anyhow::Result<Self> {
        self.method = match format {
            PublicKeyFormat::Multikey => {
                // multibase encode the public key
                let key_bytes = Base64UrlUnpadded::decode_vec(&self.vm_key.x)?;
                let mut multi_bytes = ED25519_CODEC.to_vec();
                multi_bytes.extend_from_slice(&key_bytes);
                MethodType::Multikey {
                    public_key_multibase: multibase::encode(Base::Base58Btc, &multi_bytes),
                }
            }
            PublicKeyFormat::JsonWebKey => MethodType::JsonWebKey {
                public_key_jwk: self.vm_key.clone(),
            },
            _ => return Err(anyhow!("unsupported public key format")),
        };
        Ok(self)
    }

    /// Build the verification method.
    #[must_use]
    pub fn build(self) -> VerificationMethod {
        VerificationMethod {
            id: self.kid,
            controller: self.did,
            method_type: self.method,
            ..VerificationMethod::default()
        }
    }
}

/// Instruction to the `VerificationMethodBuilder` on how to construct the key
/// ID.
pub enum VmKeyId {
    /// Use the provided authorization key and construct a multibase value from
    /// that to append to the document identifier (DID URL).
    Authorization(PublicKeyJwk),

    /// Use the verification method key from the `DidOperator` to construct a
    /// multibase value to append to the document identifier (DID URL).
    Verification,

    /// Increment an index to append to the document identifier (DID URL).
    ///
    /// `key-0`, `key-1`, etc.
    Index(u32),
}

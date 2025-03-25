//! # DID Document helpers.
//!
//! This module provides helpers to create and manipulate DID Documents
//! independent of the DID method.
//!
//! See [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-1.0/)
//! for more information.
//!

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::PublicKeyJwk;
use curve25519_dalek::edwards::CompressedEdwardsY;
use multibase::Base;
use serde_json::Value;

use crate::{
    KeyPurpose,
    core::{Kind, OneMany},
};

use crate::document::{
    Document, DocumentMetadata, MethodType, PublicKeyFormat, Service, VerificationMethod,
};

/// A builder for creating a DID Document.
#[derive(Clone, Debug, Default)]
pub struct DocumentBuilder<O> {
    /// Operation being performed
    pub operation: O,

    // Document under construction
    doc: Document,
}

// Typestate state guards for a `DocumentBuilder`.

/// The `DocumentBuilder` is being used to create new DID document.
#[derive(Default)]
pub struct Create;
/// The `DocumentBuilder` is being used to update an existing DID document.
#[derive(Default)]
pub struct Update;

impl<O> DocumentBuilder<O> {
    /// Creates a new `DocumentBuilder` with the given DID URL.
    #[must_use]
    pub fn new(did: &str) -> DocumentBuilder<Create> {
        let doc = Document {
            id: did.to_string(),
            ..Document::default()
        };
        DocumentBuilder { operation: Create, doc }
    }

    /// Creates a new `DocumentBuilder` from an existing `Document`.
    #[must_use]
    pub fn from(doc: Document) -> DocumentBuilder<Update> {
        DocumentBuilder {
            operation: Update,
            doc,
        }
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
                OneMany::One(cont) => {
                    self.doc.controller = Some(OneMany::Many(vec![cont, controller.to_string()]));
                }
                OneMany::Many(mut cont) => {
                    cont.push(controller.to_string());
                    self.doc.controller = Some(OneMany::Many(cont));
                }
            },
            None => {
                self.doc.controller = Some(OneMany::One(controller.to_string()));
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
    pub fn verification_method(
        mut self, vm: &Kind<VerificationMethod>, purpose: &KeyPurpose,
    ) -> anyhow::Result<Self> {
        match purpose {
            KeyPurpose::Authentication => {
                self.doc.authentication.get_or_insert(vec![]).push(vm.clone());
            }
            KeyPurpose::AssertionMethod => {
                self.doc.assertion_method.get_or_insert(vec![]).push(vm.clone());
            }
            KeyPurpose::KeyAgreement => match vm {
                Kind::Object(vm) => {
                    self.doc.key_agreement.get_or_insert(vec![]).push(Kind::Object(vm.clone()));
                }
                Kind::String(_) => {
                    return Err(anyhow!(
                        "key agreement must be handled by the encryption method creation algorithm"
                    ));
                }
            },
            KeyPurpose::CapabilityInvocation => {
                self.doc.capability_invocation.get_or_insert(vec![]).push(vm.clone());
            }
            KeyPurpose::CapabilityDelegation => {
                self.doc.capability_delegation.get_or_insert(vec![]).push(vm.clone());
            }
            KeyPurpose::VerificationMethod => match vm {
                Kind::Object(vm) => {
                    self.doc.verification_method.get_or_insert(vec![]).push(vm.clone());
                }
                Kind::String(_) => {
                    return Err(anyhow!(
                        "verification method must be a standalone verification method"
                    ));
                }
            },
        }
        Ok(self)
    }

    /// Retrieve the current `DID` from the builder.
    ///
    /// Note that although the `DID` (document identifier) is called for in the
    /// constructor of this builder, some DID methods may use temporary values
    /// and replace the DID in the final document. Users of this function should
    /// be aware of the DID method context in which it is used to determine the
    /// reliability of the value.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.doc.id
    }
}

impl<Create> DocumentBuilder<Create> {
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

impl<Update> DocumentBuilder<Update> {
    /// Construct a new DID `Document` with updated timestamp.
    #[must_use]
    pub fn update(mut self) -> Document {
        let mut md = self.doc.did_document_metadata.clone().unwrap_or_default();
        md.updated = Some(chrono::Utc::now());
        self.doc.did_document_metadata = Some(md);
        self.doc
    }
}

/// A builder for creating a verification method.
#[derive(Default)]
pub struct VerificationMethodBuilder {
    vm_key: PublicKeyJwk,
    did: String,
    kid: String,
    method: MethodType,
    format: PublicKeyFormat,
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

    /// Specify the verification method type.
    ///
    /// To generate an `X25519` public encryption key from an `Ed25519` key, use
    /// [`derive_key_agreement`] instead of this function.
    ///
    /// # Errors
    ///
    /// Will fail if required format is multibase but the public key cannot be
    /// decoded into bytes.
    /// TODO: Is there a nicer way to handle this? This type mapping is
    /// awkward.
    pub fn method_type(mut self, mtype: &MethodType) -> anyhow::Result<Self> {
        self.method = mtype.clone();
        self.format = match mtype {
            MethodType::Multikey
            | MethodType::Ed25519VerificationKey2020
            | MethodType::X25519KeyAgreementKey2020 => {
                // multibase encode the public key
                PublicKeyFormat::PublicKeyMultibase {
                    public_key_multibase: self.vm_key.to_multibase()?,
                }
            }
            MethodType::JsonWebKey2020 | MethodType::EcdsaSecp256k1VerificationKey2019 => {
                PublicKeyFormat::PublicKeyJwk {
                    public_key_jwk: self.vm_key.clone(),
                }
            }
        };
        Ok(self)
    }

    /// Special case for specifying the public key format: derive a `X25519` key
    /// agreement verification method from an `Ed25519` key.
    ///
    /// # Errors
    ///
    /// Will fail if decoding or computing the Edwards Curve point fails.
    pub fn derive_key_agreement(mut self) -> anyhow::Result<Self> {
        // derive an X25519 public encryption key from the Ed25519 key
        let key_bytes = Base64UrlUnpadded::decode_vec(&self.vm_key.x)?;
        let edwards_y = CompressedEdwardsY::from_slice(&key_bytes)?;
        let Some(edwards_point) = edwards_y.decompress() else {
            bail!("Edwards Y cannot be decompressed to a point");
        };
        let x25519_bytes = edwards_point.to_montgomery().to_bytes();
        self.method = MethodType::X25519KeyAgreementKey2020;
        self.format = PublicKeyFormat::PublicKeyMultibase {
            public_key_multibase: multibase::encode(Base::Base58Btc, x25519_bytes),
        };
        Ok(self)
    }

    /// Build the verification method.
    #[must_use]
    pub fn build(self) -> VerificationMethod {
        VerificationMethod {
            id: self.kid,
            controller: self.did,
            type_: self.method,
            key: self.format,
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

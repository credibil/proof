//! # DID Document
//!
//! A DID Document is a JSON-LD document that contains information related to a
//! DID.

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use anyhow::{Result, anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use credibil_ecc::{PublicKey, X25519_CODEC, derive_x25519_public};
use credibil_jose::PublicKeyJwk;
use multibase::Base;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::BASE_CONTEXT;
use crate::core::{Kind, OneMany};

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

impl Display for KeyPurpose {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationMethod => write!(f, "verificationMethod"),
            Self::Authentication => write!(f, "authentication"),
            Self::AssertionMethod => write!(f, "assertionMethod"),
            Self::KeyAgreement => write!(f, "keyAgreement"),
            Self::CapabilityInvocation => write!(f, "capabilityInvocation"),
            Self::CapabilityDelegation => write!(f, "capabilityDelegation"),
        }
    }
}

impl FromStr for KeyPurpose {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "verificationMethod" => Ok(Self::VerificationMethod),
            "authentication" => Ok(Self::Authentication),
            "assertionMethod" => Ok(Self::AssertionMethod),
            "keyAgreement" => Ok(Self::KeyAgreement),
            "capabilityInvocation" => Ok(Self::CapabilityInvocation),
            "capabilityDelegation" => Ok(Self::CapabilityDelegation),
            _ => Err(anyhow!("invalid key purpose")),
        }
    }
}

/// DID Document
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// The context of the DID document.
    #[serde(rename = "@context")]
    pub context: Vec<Kind<Value>>,

    /// The DID for a particular DID subject.
    ///
    /// The subject is defined as the entity identified by the DID and described
    /// by the DID document. Anything can be a DID subject: person, group,
    /// organization, physical thing, digital thing, logical thing, etc.
    pub id: String,

    /// A set of URIs that are other identifiers for the subject of the above
    /// DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,

    /// One or more strings that conform to the rules DID Syntax. The
    /// corresponding DID document(s) SHOULD contain verification
    /// relationships that explicitly permit the use of certain verification
    /// methods for specific purposes.
    ///
    /// Any verification methods contained in the related DID documents
    /// SHOULD be accepted as authoritative, such that proofs that satisfy those
    /// verification methods are to be considered equivalent to proofs provided
    /// by the DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<OneMany<String>>,

    /// A set of services, that express ways of communicating with the DID
    /// subject or related entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,

    /// If set, MUST be a set of verification methods for the DID subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,

    /// The `authentication` verification relationship is used to specify how
    /// the DID subject is expected to be authenticated, for purposes such
    /// as logging into a website or in any sort of challenge-response
    /// protocol.
    ///
    /// <https://www.w3.org/TR/did-core/#authentication>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Kind<VerificationMethod>>>,

    /// The `assertion_method` verification relationship is used to specify how
    /// the DID subject is expected to express claims, such as for the
    /// purposes of issuing a Verifiable Credential.
    ///
    /// <https://www.w3.org/TR/did-core/#assertion>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<Kind<VerificationMethod>>>,

    /// The `key_agreement` verification relationship is used to specify how an
    /// entity can generate encryption material in order to transmit
    /// confidential information intended for the DID subject, such as for
    /// the purposes of establishing a secure communication channel with the
    /// recipient.
    ///
    /// <https://www.w3.org/TR/did-core/#key-agreement>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_invocation` verification relationship is used to specify
    /// a verification method that might be used by the DID subject to
    /// invoke a cryptographic capability, such as the authorization to
    /// update the DID Document.
    ///
    /// <https://www.w3.org/TR/did-core/#capability-invocation>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<Kind<VerificationMethod>>>,

    /// The `capability_delegation` verification relationship is used to specify
    /// a mechanism that might be used by the DID subject to delegate a
    /// cryptographic capability to another party, such as delegating the
    /// authority to access a specific HTTP API to a subordinate.
    ///
    /// <https://www.w3.org/TR/did-core/#capability-delegation>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<Kind<VerificationMethod>>>,

    /// If resolution is successful, this MUST be metadata about the DID
    /// document. This typically does not change between invocations of the
    /// resolve and resolveRepresentation functions unless the DID document
    /// changes. If resolution is unsuccessful, this output MUST be an
    /// empty.
    ///
    /// <https://w3c.github.io/did-core/#dfn-diddocumentmetadata>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
}

impl Document {
    /// Retrieve a service by its ID.
    #[must_use]
    pub fn get_service(&self, id: &str) -> Option<&Service> {
        self.service.as_ref()?.iter().find(|s| s.id == id)
    }

    /// Retrieve a verification method by its ID.
    #[must_use]
    pub fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method.as_ref()?.iter().find(|vm| vm.id == id)
    }
}

/// Types of operation a `DocumentBuilder` can perform.
#[derive(Clone, Debug, Default)]
pub enum DocumentBuilderOperation {
    /// Create a new DID Document.
    #[default]
    Create,

    /// Update an existing DID Document.
    Update,
}

/// A builder for creating a DID Document.
#[derive(Clone, Debug, Default)]
pub struct DocumentBuilder {
    // Document under construction
    doc: Document,

    // Operation to perform
    op: DocumentBuilderOperation,
}

impl DocumentBuilder {
    /// Creates a new `DocumentBuilder` with the given DID URL.
    #[must_use]
    pub fn new(did: impl Into<String>) -> Self {
        let doc = Document {
            id: did.into(),
            ..Document::default()
        };
        Self {
            doc,
            op: DocumentBuilderOperation::Create,
        }
    }

    /// Creates a new `DocumentBuilder` from an existing `Document`.
    #[must_use]
    pub const fn from(doc: Document) -> Self {
        Self {
            doc,
            op: DocumentBuilderOperation::Update,
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
    pub fn add_controller(mut self, controller: &str) -> Self {
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

    /// Remove a controller.
    ///
    /// # Errors
    /// Will fail if the controller is not found.
    pub fn remove_controller(mut self, controller: &str) -> Result<Self> {
        match self.doc.controller {
            Some(c) => match c {
                OneMany::One(cont) => {
                    if cont == controller {
                        self.doc.controller = None;
                    } else {
                        bail!("controller not found");
                    }
                }
                OneMany::Many(mut cont) => {
                    if let Some(pos) = cont.iter().position(|c| c == controller) {
                        cont.remove(pos);
                        self.doc.controller = Some(OneMany::Many(cont));
                    } else {
                        bail!("controller not found");
                    }
                }
            },
            None => {
                bail!("controller not found");
            }
        }
        Ok(self)
    }

    /// Add a service endpoint.
    ///
    /// Chain to add multiple service endpoints.
    #[must_use]
    pub fn add_service(mut self, service: Service) -> Self {
        self.doc.service.get_or_insert(vec![]).push(service);
        self
    }

    /// Remove a service endpoint.
    ///
    /// # Errors
    /// Will fail if no service with the supplied ID is found.
    pub fn remove_service(mut self, service_id: &str) -> Result<Self> {
        if let Some(services) = &mut self.doc.service {
            if let Some(pos) = services.iter().position(|s| s.id == service_id) {
                services.remove(pos);
            } else {
                bail!("service not found");
            }
        } else {
            bail!("service not found");
        }
        Ok(self)
    }

    /// Add a context.
    ///
    /// Chain to add multiple contexts.
    #[must_use]
    pub fn add_context(mut self, context: &Kind<Value>) -> Self {
        self.doc.context.push(context.clone());
        self
    }

    /// Remove a context.
    ///
    /// # Errors
    /// Will fail if the context is not found.
    pub fn remove_context(mut self, context: &Kind<Value>) -> Result<Self> {
        if let Some(pos) = self.doc.context.iter().position(|c| c == context) {
            self.doc.context.remove(pos);
        } else {
            bail!("context not found");
        }
        Ok(self)
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
    pub fn add_verification_method(
        mut self, vm_kind: Kind<VerificationMethod>, purpose: &KeyPurpose,
    ) -> Result<Self> {
        // let vm_kind = Kind::Object(vm);

        match purpose {
            KeyPurpose::Authentication => {
                self.doc.authentication.get_or_insert(vec![]).push(vm_kind.clone());
            }
            KeyPurpose::AssertionMethod => {
                self.doc.assertion_method.get_or_insert(vec![]).push(vm_kind.clone());
            }
            KeyPurpose::KeyAgreement => match vm_kind {
                Kind::Object(_) => {
                    self.doc.key_agreement.get_or_insert(vec![]).push(vm_kind.clone());
                }
                Kind::String(_) => {
                    bail!(
                        "key agreement must be handled by the encryption method creation algorithm"
                    );
                }
            },
            KeyPurpose::CapabilityInvocation => {
                self.doc.capability_invocation.get_or_insert(vec![]).push(vm_kind.clone());
            }
            KeyPurpose::CapabilityDelegation => {
                self.doc.capability_delegation.get_or_insert(vec![]).push(vm_kind.clone());
            }
            KeyPurpose::VerificationMethod => match vm_kind {
                Kind::Object(vm) => {
                    self.doc.verification_method.get_or_insert(vec![]).push(vm);
                }
                Kind::String(_) => {
                    bail!("verification method must be a standalone verification method");
                }
            },
        }
        Ok(self)
    }

    /// Add a verification method that is a verifying key and optionally create
    /// a derived key agreement.
    ///
    /// This is a shortcut for adding a verification method that constructs the
    /// verification method from a `PublicKeyJwk` and adds it to the document,
    /// then optionally derives an `X25519` key agreement from it.
    ///
    /// # Note
    ///
    /// 1. The verification key format will be multibase encoded, derived from
    ///    the JWK passed in. This is hard-coded for this function.
    ///
    /// 2. The key identifier will be `{did}#key-0`.
    ///
    /// If you have other needs, use `add_verification_method` instead.
    ///
    /// # Errors
    /// Will fail if the JWK cannot be converted to a multibase string or if the
    /// conversion from `Ed25519` to `X25519` fails.
    pub fn add_verifying_key(mut self, jwk: &PublicKeyJwk, key_agreement: bool) -> Result<Self> {
        let vk = jwk.to_multibase()?;
        let vm = VerificationMethodBuilder::new(vk)
            .key_id(self.did(), VmKeyId::Index("key".to_string(), 0))?
            .method_type(&MethodType::Ed25519VerificationKey2020)?
            .build();
        self.doc.verification_method.get_or_insert(vec![]).push(vm.clone());
        if key_agreement {
            let ka = vm.derive_key_agreement()?;
            self.doc.key_agreement.get_or_insert(vec![]).push(Kind::Object(ka));
        }
        Ok(self)
    }

    /// Remove a verification method.
    ///
    /// # Errors
    /// Will fail if no verification method with the supplied ID is found.
    pub fn remove_verification_method(mut self, vm_id: &str) -> Result<Self> {
        let mut found = false;
        if let Some(auths) = &mut self.doc.authentication {
            if let Some(pos) = auths.iter().position(|vm| match vm {
                Kind::Object(vm) => vm.id == vm_id,
                Kind::String(id) => id == vm_id,
            }) {
                auths.remove(pos);
                found = true;
            }
        }
        if let Some(asserts) = &mut self.doc.assertion_method {
            if let Some(pos) = asserts.iter().position(|vm| match vm {
                Kind::Object(vm) => vm.id == vm_id,
                Kind::String(id) => id == vm_id,
            }) {
                asserts.remove(pos);
                found = true;
            }
        }
        if let Some(kas) = &mut self.doc.key_agreement {
            if let Some(pos) = kas.iter().position(|vm| match vm {
                Kind::Object(vm) => vm.id == vm_id,
                Kind::String(id) => id == vm_id,
            }) {
                kas.remove(pos);
                found = true;
            }
        }
        if let Some(caps) = &mut self.doc.capability_invocation {
            if let Some(pos) = caps.iter().position(|vm| match vm {
                Kind::Object(vm) => vm.id == vm_id,
                Kind::String(id) => id == vm_id,
            }) {
                caps.remove(pos);
                found = true;
            }
        }
        if let Some(caps) = &mut self.doc.capability_delegation {
            if let Some(pos) = caps.iter().position(|vm| match vm {
                Kind::Object(vm) => vm.id == vm_id,
                Kind::String(id) => id == vm_id,
            }) {
                caps.remove(pos);
                found = true;
            }
        }
        if let Some(vms) = &mut self.doc.verification_method {
            if let Some(pos) = vms.iter().position(|vm| vm.id == vm_id) {
                vms.remove(pos);
                found = true;
            }
        }
        if !found {
            bail!("verification method not found");
        }
        Ok(self)
    }

    /// Create a new `X25519` key agreement verification method from the
    /// `Ed25519` signing key.
    ///
    /// You must pass in the ID of the signing verification method that already
    /// exists in the document being built, so ensure to call
    /// `add_verification_method` with `KeyPurpose::VerificationMethod` before
    /// calling this method.
    ///
    /// NOTE: In general, a signing key should never be used for encryption,
    /// so this method should only be used where the DID method gives you no
    /// choice, such as `did:key`.
    ///
    /// TODO: Consider returning an error if not `did:key`.
    ///
    /// # Errors
    /// If the conversion from `Ed25519` to `X25519` fails, an error will be
    /// returned, including testing the assumption that the signing key is
    /// `Ed25519` in the first place. An error is also returned if there is no
    /// existing verification method with the given ID.
    pub fn derive_key_agreement(mut self, vm_id: &str) -> Result<Self> {
        let vm = self
            .doc
            .get_verification_method(vm_id)
            .ok_or_else(|| anyhow::anyhow!("verification method not found"))?;
        let ka = vm.derive_key_agreement()?;

        self.doc.key_agreement.get_or_insert(vec![]).push(Kind::Object(ka));

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
    pub fn did(&self) -> String {
        self.doc.id.clone()
    }

    /// Set metadata for the document.
    #[must_use]
    pub fn metadata(mut self, md: DocumentMetadata) -> Self {
        self.doc.did_document_metadata = Some(md);
        self
    }

    /// Update metadata with created or updated timestamp and build the DID
    /// Document.
    #[must_use]
    pub fn build(mut self) -> Document {
        let mut md = self.doc.did_document_metadata.clone().unwrap_or_default();
        match self.op {
            DocumentBuilderOperation::Create => md.created = chrono::Utc::now(),
            DocumentBuilderOperation::Update => md.updated = Some(chrono::Utc::now()),
        }
        self.doc.did_document_metadata = Some(md);
        for ctx in &BASE_CONTEXT {
            let c = Kind::String((*ctx).to_string());
            if !self.doc.context.contains(&c) {
                self.doc.context.push(c);
            }
        }
        self.doc
    }
}

/// Services are used to express ways of communicating with the DID subject or
/// associated entities.
///
/// They can be any type of service the DID subject wants
/// to advertise, including decentralized identity management services for
/// further discovery, authentication, authorization, or interaction.
///
/// Service information is often service specific. For example, a reference to
/// an encrypted messaging service can detail how to initiate the encrypted link
/// before messaging begins.
///
/// Due to privacy concerns, revealing public information through services, such
/// as social media accounts, personal websites, and email addresses, is
/// discouraged.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// A URI unique to the service.
    pub id: String,

    /// The service type. SHOULD be registered in the DID Specification
    /// Registries.
    #[serde(rename = "type")]
    pub type_: String,

    /// One or more endpoints for the service.
    #[allow(clippy::struct_field_names)]
    pub service_endpoint: OneMany<Kind<Value>>,
}

/// Service builder
#[derive(Clone, Debug, Default)]
pub struct ServiceBuilder<T, E> {
    id: String,
    service_type: T,
    endpoint: E,
}

/// Service builder does not have a type specified (can't build)
#[derive(Clone, Debug)]
pub struct WithoutType;

/// Service builder has a type specified (can build)
#[derive(Clone, Debug)]
pub struct WithType(String);

/// Service builder does not have an endpoint specified (can't build)
#[derive(Clone, Debug)]
pub struct WithoutEndpoint;

/// Service builder has at least one endpoint specified (can build)
#[derive(Clone, Debug)]
pub struct WithEndpoint(Vec<Kind<Value>>);

impl ServiceBuilder<WithoutType, WithoutEndpoint> {
    /// Creates a new `ServiceBuilder` with the given service ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            service_type: WithoutType,
            endpoint: WithoutEndpoint,
        }
    }

    /// Specify the service type.
    #[must_use]
    pub fn service_type(
        &self, service_type: impl Into<String>,
    ) -> ServiceBuilder<WithType, WithoutEndpoint> {
        ServiceBuilder {
            id: self.id.clone(),
            service_type: WithType(service_type.into()),
            endpoint: WithoutEndpoint,
        }
    }
}

impl ServiceBuilder<WithType, WithoutEndpoint> {
    /// Specify a string-based service endpoint.
    #[must_use]
    pub fn endpoint(
        &self, endpoint: impl Into<Kind<Value>>,
    ) -> ServiceBuilder<WithType, WithEndpoint> {
        let ep = endpoint.into();
        ServiceBuilder {
            id: self.id.clone(),
            service_type: self.service_type.clone(),
            endpoint: WithEndpoint(vec![ep]),
        }
    }
}

impl ServiceBuilder<WithType, WithEndpoint> {
    /// Add a string-based service endpoint.
    #[must_use]
    pub fn add_endpoint_str(mut self, endpoint: impl Into<String>) -> Self {
        let ep = Kind::String(endpoint.into());
        self.endpoint.0.push(ep);
        self
    }

    /// Add a JSON-based service endpoint.
    #[must_use]
    pub fn add_endpoint_json(mut self, endpoint: &Value) -> Self {
        let ep = Kind::Object(endpoint.clone());
        self.endpoint.0.push(ep);
        self
    }

    /// Build the service.
    #[must_use]
    pub fn build(self) -> Service {
        let ep = if self.endpoint.0.len() == 1 {
            OneMany::One(self.endpoint.0[0].clone())
        } else {
            OneMany::Many(self.endpoint.0)
        };
        Service {
            id: self.id,
            type_: self.service_type.0,
            service_endpoint: ep,
        }
    }
}

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

    /// The type of verification method. SHOULD be a registered type in the
    /// [DID Specification Registries](https://www.w3.org/TR/did-spec-registries).
    #[serde(rename = "type")]
    pub type_: MethodType,

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

    /// Create a new `X25519` key agreement verification method from the
    /// `Ed25519` signing key.
    ///
    /// # Errors
    /// If the conversion from `Ed25519` to `X25519` fails, an error will be
    /// returned, including testing the assumption that the signing key is
    /// `Ed25519` in the first place.
    pub fn derive_key_agreement(&self) -> Result<Self> {
        if self.type_ != MethodType::Ed25519VerificationKey2020 {
            bail!("verification method is not an Ed25519 public key");
        }

        let jwk = match &self.key {
            KeyFormat::Jwk { public_key_jwk } => public_key_jwk.clone(),
            KeyFormat::Multibase { public_key_multibase } => {
                PublicKeyJwk::from_multibase(public_key_multibase)?
            }
        };
        let key_bytes = Base64UrlUnpadded::decode_vec(&jwk.x)?;
        let pub_key = PublicKey::from_slice(&key_bytes)?;
        let x25519_key = derive_x25519_public(&pub_key)?;

        // base58B encode the raw key
        let mut multi_bytes = vec![];
        multi_bytes.extend_from_slice(&X25519_CODEC);
        multi_bytes.extend_from_slice(&x25519_key.to_bytes());
        let multikey = multibase::encode(Base::Base58Btc, &multi_bytes);

        let vm = VerificationMethodBuilder::new(multikey)
            .key_id(self.did(), VmKeyId::Did)?
            .method_type(&MethodType::X25519KeyAgreementKey2020)?
            .build();

        Ok(vm)
    }
}

/// A builder for creating a verification method.
#[derive(Default)]
pub struct VerificationMethodBuilder {
    vm_key: KeyFormat,
    did: String,
    kid: String,
    method: MethodType,
}

impl VerificationMethodBuilder {
    /// Creates a new `VerificationMethodBuilder` with the given public key.
    #[must_use]
    pub fn new(verifying_key: impl Into<KeyFormat>) -> Self {
        Self {
            vm_key: verifying_key.into(),
            ..Default::default()
        }
    }

    /// Specify how to construct the key ID.
    ///
    /// # Errors
    ///
    /// Will fail if the ID type requires a multibase value but construction of
    /// that value fails.
    pub fn key_id(mut self, did: impl Into<String>, id_type: VmKeyId) -> Result<Self> {
        self.did = did.into();

        match id_type {
            VmKeyId::Did => {
                self.kid.clone_from(&self.did);
            }
            VmKeyId::Authorization(auth_key) => {
                self.kid = format!("{}#{auth_key}", self.did);
            }
            VmKeyId::Verification => {
                let mb = match &self.vm_key {
                    KeyFormat::Jwk { public_key_jwk } => public_key_jwk.to_multibase()?,
                    KeyFormat::Multibase { public_key_multibase } => public_key_multibase.clone(),
                };
                self.kid = format!("{}#{mb}", self.did);
            }
            VmKeyId::Index(prefix, index) => {
                self.kid = format!("{}#{prefix}{index}", self.did);
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
    /// Will fail if required format does not match the provided key format.
    pub fn method_type(mut self, mtype: &MethodType) -> Result<Self> {
        match &self.vm_key {
            KeyFormat::Jwk { .. } => {
                if !matches!(
                    mtype,
                    MethodType::JsonWebKey2020 | MethodType::EcdsaSecp256k1VerificationKey2019
                ) {
                    bail!(
                        "JWK key format only supports JsonWebKey2020 and EcdsaSecp256k1VerificationKey2019"
                    );
                }
            }
            KeyFormat::Multibase { .. } => {
                if !matches!(
                    mtype,
                    MethodType::Multikey
                        | MethodType::Ed25519VerificationKey2020
                        | MethodType::X25519KeyAgreementKey2020
                ) {
                    bail!(
                        "Multibase key format only supports Multikey, Ed25519VerificationKey2020 and X25519KeyAgreementKey2020"
                    );
                }
            }
        }
        self.method = mtype.clone();
        Ok(self)
    }

    /// Build the verification method.
    #[must_use]
    pub fn build(self) -> VerificationMethod {
        VerificationMethod {
            id: self.kid,
            controller: self.did,
            type_: self.method,
            key: self.vm_key,
            ..VerificationMethod::default()
        }
    }
}

/// Instruction to the `VerificationMethodBuilder` on how to construct the key
/// ID.
pub enum VmKeyId {
    /// Use the DID as the identifier without any fragment.
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
    /// With prefix `key-` and index `0`, the key ID will be
    /// `did:<method>:<method-specific-identifier>#key-0`.
    Index(String, u32),
}

/// The format of the public key material.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all_fields = "camelCase")]
#[serde(untagged)]
pub enum KeyFormat {
    /// The key is encoded as a Multibase string.
    Multibase {
        /// The public key encoded as a Multibase.
        public_key_multibase: String,
    },

    /// The key is encoded as a JWK.
    Jwk {
        /// The public key encoded as a JWK.
        public_key_jwk: PublicKeyJwk,
    },
}

impl Default for KeyFormat {
    fn default() -> Self {
        Self::Multibase {
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
            Self::Jwk { public_key_jwk } => Ok(public_key_jwk.clone()),
            Self::Multibase { public_key_multibase } => {
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
            Self::Jwk { public_key_jwk } => public_key_jwk.to_multibase(),
            Self::Multibase { public_key_multibase } => Ok(public_key_multibase.clone()),
        }
    }
}

impl From<PublicKeyJwk> for KeyFormat {
    fn from(jwk: PublicKeyJwk) -> Self {
        Self::Jwk { public_key_jwk: jwk }
    }
}

impl From<String> for KeyFormat {
    fn from(multibase: String) -> Self {
        Self::Multibase {
            public_key_multibase: multibase,
        }
    }
}

/// Verification method types supported by this library. SHOULD be registered in
/// the [DID Specification Registries](https://www.w3.org/TR/did-spec-registries).
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all_fields = "camelCase")]
pub enum MethodType {
    /// Generic Multi-key format.
    #[default]
    Multikey,

    /// `ED25519` Verification key, version 2020.
    Ed25519VerificationKey2020,

    /// `X25519` Key Agreement Key, version 2020.
    X25519KeyAgreementKey2020,

    /// JSON Web Key (JWK), version 2020.
    JsonWebKey2020,

    /// Secp256k1 Verification Key, version 2019.
    EcdsaSecp256k1VerificationKey2019,
}

impl Display for MethodType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Multikey => write!(f, "Multikey"),
            Self::Ed25519VerificationKey2020 => write!(f, "Ed25519VerificationKey2020"),
            Self::X25519KeyAgreementKey2020 => write!(f, "X25519KeyAgreementKey2020"),
            Self::JsonWebKey2020 => write!(f, "JsonWebKey2020"),
            Self::EcdsaSecp256k1VerificationKey2019 => {
                write!(f, "EcdsaSecp256k1VerificationKey2019")
            }
        }
    }
}

/// DID document metadata. This typically does not change unless the DID
/// document changes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct DocumentMetadata {
    /// Timestamp of the Create operation.
    /// An XMLSCHEMA11-2 (RFC3339) e.g. 2010-01-01T19:23:24Z.
    pub created: DateTime<Utc>,

    /// Timestamp of the last Update operation. Omitted if an Update operation
    /// has never been performed. May be the same value as the `created`
    /// property when the difference between the two timestamps is less than
    /// one second. An XMLSCHEMA11-2 (RFC3339) e.g. 2010-01-01T19:23:24Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,

    /// MUST be set to true if the DID has been deactivated. Optional if the DID
    /// has not been deactivated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// May be set if the document version is not the latest. Indicates the
    /// timestamp of the next Update operation as an XMLSCHEMA11-2
    /// (RFC3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<DateTime<Utc>>,

    /// Used to indicate the version of the last Update operation. SHOULD be
    /// set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,

    /// MAY be set if the document version is not the latest. It indicates the
    /// version of the next Update operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_version_id: Option<String>,

    /// Used when a DID method needs to define different forms of a DID that are
    /// logically equivalent. For example, when a DID takes one form prior to
    /// registration in a verifiable data registry and another form after such
    /// registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub equivalent_id: Option<Vec<String>>,

    /// Identical to the `equivalent_id` property except that it is a single
    /// value AND the DID is the canonical ID for the DID subject within the
    /// containing DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,

    /// Additional metadata specified by the DID method.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub additional: Option<HashMap<String, Value>>,
}

/// Builder for DID document metadata.
#[derive(Clone, Debug, Default)]
pub struct DocumentMetadataBuilder {
    md: DocumentMetadata,
}

impl DocumentMetadataBuilder {
    /// Creates a new `DocumentMetadataBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            md: DocumentMetadata::default(),
        }
    }

    /// Creates a new `DocumentMetadataBuilder` from an existing
    /// `DocumentMetadata`.
    #[must_use]
    pub fn from(md: &DocumentMetadata) -> Self {
        Self { md: md.clone() }
    }

    /// Set the created timestamp.
    #[must_use]
    pub const fn created(mut self, created: &DateTime<Utc>) -> Self {
        self.md.created = *created;
        self
    }

    /// Set the updated timestamp.
    #[must_use]
    pub const fn updated(mut self, updated: &DateTime<Utc>) -> Self {
        self.md.updated = Some(*updated);
        self
    }

    /// Set the deactivated flag.
    #[must_use]
    pub const fn deactivated(mut self, deactivated: bool) -> Self {
        self.md.deactivated = Some(deactivated);
        self
    }

    /// Set the next update timestamp.
    #[must_use]
    pub const fn next_update(mut self, next_update: &DateTime<Utc>) -> Self {
        self.md.next_update = Some(*next_update);
        self
    }

    /// Set the version ID.
    #[must_use]
    pub fn version_id(mut self, version_id: &str) -> Self {
        self.md.version_id = Some(version_id.into());
        self
    }

    /// Set the next version ID.
    #[must_use]
    pub fn next_version_id(mut self, next_version_id: &str) -> Self {
        self.md.next_version_id = Some(next_version_id.into());
        self
    }

    /// Set the equivalent ID.
    #[must_use]
    pub fn equivalent_id(mut self, equivalent_id: &[&str]) -> Self {
        self.md.equivalent_id = Some(equivalent_id.iter().map(|s| (*s).to_string()).collect());
        self
    }

    /// Set the canonical ID.
    #[must_use]
    pub fn canonical_id(mut self, canonical_id: &str) -> Self {
        self.md.canonical_id = Some(canonical_id.into());
        self
    }

    /// Set an addition field
    #[must_use]
    pub fn additional(mut self, key: &str, value: impl Into<Value>) -> Self {
        if let Some(additional) = &mut self.md.additional {
            additional.insert(key.into(), value.into());
        } else {
            let mut additional = HashMap::new();
            additional.insert(key.into(), value.into());
            self.md.additional = Some(additional);
        }
        self
    }

    /// Build the metadata.
    #[must_use]
    pub fn build(self) -> DocumentMetadata {
        self.md
    }
}

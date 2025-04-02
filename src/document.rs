//! # DID Document
//!
//! A DID Document is a JSON-LD document that contains information related to a
//! DID.

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};

use anyhow::bail;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use credibil_infosec::jose::jwk::PublicKeyJwk;
use curve25519_dalek::edwards::CompressedEdwardsY;
use multibase::Base;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::KeyPurpose;
use crate::core::{Kind, OneMany};
use crate::error::Error;

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
        self.verification_method
            .as_ref()?
            .iter()
            .find(|vm| vm.id == id)
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
    pub key: PublicKeyFormat,
}

/// The format of the public key material.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all_fields = "camelCase")]
#[serde(untagged)]
pub enum PublicKeyFormat {
    /// The key is encoded as a Multibase string.
    PublicKeyMultibase {
        /// The public key encoded as a Multibase.
        public_key_multibase: String,
    },

    /// The key is encoded as a JWK.
    PublicKeyJwk {
        /// The public key encoded as a JWK.
        public_key_jwk: PublicKeyJwk,
    },
}

impl Default for PublicKeyFormat {
    fn default() -> Self {
        Self::PublicKeyMultibase {
            public_key_multibase: String::new(),
        }
    }
}

impl PublicKeyFormat {
    /// Return the key as a JWK
    ///
    /// # Errors
    /// Will return an error if the key is multibase encoded and cannot be
    /// decoded.
    pub fn jwk(&self) -> crate::Result<PublicKeyJwk> {
        match self {
            Self::PublicKeyJwk { public_key_jwk } => Ok(public_key_jwk.clone()),
            Self::PublicKeyMultibase { public_key_multibase } => {
                PublicKeyJwk::from_multibase(public_key_multibase)
                    .map_err(|e| Error::InvalidPublicKey(e.to_string()))
            }
        }
    }

    /// Return the key as a multibase string.
    ///
    /// # Errors
    /// Will return an error if the key is a JWK and cannot be encoded as a
    /// multibase string.
    pub fn multibase(&self) -> crate::Result<String> {
        match self {
            Self::PublicKeyJwk { public_key_jwk } => {
                public_key_jwk.to_multibase().map_err(|e| Error::InvalidPublicKey(e.to_string()))
            }
            Self::PublicKeyMultibase { public_key_multibase } => Ok(public_key_multibase.clone()),
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

// // TODO: set context based on key format:
// // - Ed25519VerificationKey2020	https://w3id.org/security/suites/ed25519-2020/v1
// // - JsonWebKey2020	https://w3id.org/security/suites/jws-2020/v1

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
}

/// Options that can be provided when creating a DID document.
// TODO: Remove this and use builders instead.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOptions {
    /// Verification method type.
    pub method_type: MethodType,

    /// Default context for the DID document. SHOULD be set to
    /// `"https://www.w3.org/ns/did/v1"`.
    pub default_context: String,

    /// Enable experimental public key types. SHOULD be set to "false".
    pub enable_experimental_public_key_types: bool,

    /// Will add a `keyAgreement` object to the DID document.
    pub enable_encryption_key_derivation: bool,

    // service_endpoints: Vec<Value>,
    // verification_methods: Vec<Value>,
    // authentication: Vec<Value>,
    /// Additional options.
    #[serde(flatten)]
    pub additional: Option<HashMap<String, String>>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            method_type: MethodType::default(),
            enable_experimental_public_key_types: false,
            default_context: "https://www.w3.org/ns/did/v1".to_string(),
            enable_encryption_key_derivation: false,
            additional: None,
        }
    }
}

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
        DocumentBuilder {
            operation: Create,
            doc,
        }
    }

    /// Creates a new `DocumentBuilder` from an existing `Document`.
    #[must_use]
    pub fn from(doc: &Document) -> DocumentBuilder<Update> {
        DocumentBuilder {
            operation: Update,
            doc: doc.clone(),
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
    pub fn remove_controller(mut self, controller: &str) -> anyhow::Result<Self> {
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
    pub fn add_service(mut self, service: &Service) -> Self {
        self.doc.service.get_or_insert(vec![]).push(service.clone());
        self
    }

    /// Remove a service endpoint.
    ///
    /// # Errors
    /// Will fail if no service with the supplied ID is found.
    pub fn remove_service(mut self, service_id: &str) -> anyhow::Result<Self> {
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
    pub fn remove_context(mut self, context: &Kind<Value>) -> anyhow::Result<Self> {
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
                    bail!(
                        "key agreement must be handled by the encryption method creation algorithm"
                    );
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
                    bail!("verification method must be a standalone verification method");
                }
            },
        }
        Ok(self)
    }

    /// Remove a verification method.
    ///
    /// # Errors
    /// Will fail if no verification method with the supplied ID is found.
    pub fn remove_verification_method(mut self, vm_id: &str) -> anyhow::Result<Self> {
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
            VmKeyId::Did => {
                self.kid.clone_from(&self.did);
            }
            VmKeyId::Authorization(auth_key) => {
                let mb = auth_key.to_multibase()?;
                self.kid = format!("{did}#{mb}");
            }
            VmKeyId::Verification => {
                let mb = self.vm_key.to_multibase()?;
                self.kid = format!("{did}#{mb}");
            }
            VmKeyId::Index(prefix, index) => {
                self.kid = format!("{did}#{prefix}{index}");
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
    /// Use the DID as the identifier without any fragment.
    Did,

    /// Use the provided authorization key and construct a multibase value from
    /// that to append to the document identifier (DID URL).
    Authorization(PublicKeyJwk),

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

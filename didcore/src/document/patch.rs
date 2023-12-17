//! Patching of DID documents. Note that the DID document specification allows for keys to be
//! referenced by ID or embedded in the purposes field. This library only supports referencing and
//! will not honour patching of embedded keys, even though the underlying data structure is fully
//! compatible with the spec. If your implementation uses embedded keys then you will need to
//! implement your own patching.

use std::{collections::HashMap, fmt::Display};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    document::{DidDocument, KeyPurpose, Service, VerificationMethod, VmRelationship},
    error::Err,
    tracerr, Result,
};

/// Implementation to apply patches to a DID document and look up a key.
impl DidDocument {
    /// Apply patches to a DID document.
    pub fn apply_patches(&mut self, patches: &[Patch]) {
        for p in patches.iter() {
            match p.action {
                PatchAction::Replace => {
                    self.apply_replace(p);
                    // Only honour a single replace patch
                    break;
                }
                PatchAction::AddPublicKeys => {
                    self.apply_add_keys(p);
                }
                PatchAction::RemovePublicKeys => {
                    self.apply_remove_keys(p);
                }
                PatchAction::AddServices => {
                    if let Some(services) = &p.services {
                        if let Some(mut s) = self.service.clone() {
                            s.extend(services.clone());
                            self.service = Some(s);
                        } else {
                            self.service = Some(services.clone());
                        }
                    }
                }
                PatchAction::RemoveServices => {
                    if let Some(services) = &p.ids {
                        if let Some(mut s) = self.service.clone() {
                            for k in services {
                                s.retain(|t| t.id != *k);
                            }
                            self.service = Some(s);
                        }
                    }
                }
            }
        }
    }

    // Reload document verification method realationships from a VmRelationshipSet struct after
    // updating
    fn reload_vm_relationships(&mut self, p: &VmRelationshipSet) {
        self.authentication = (!p.authentication.is_empty()).then_some(p.authentication.clone());
        self.assertion_method =
            (!p.assertion_method.is_empty()).then_some(p.assertion_method.clone());
        self.key_agreement = (!p.key_agreement.is_empty()).then_some(p.key_agreement.clone());
        self.capability_delegation =
            (!p.capability_delegation.is_empty()).then_some(p.capability_delegation.clone());
        self.capability_invocation =
            (!p.capability_invocation.is_empty()).then_some(p.capability_invocation.clone());
    }

    // Apply a document replacement patch
    fn apply_replace(&mut self, patch: &Patch) {
        let Some(pdoc) = &patch.document else {
            return;
        };
        if let Some(keys) = &pdoc.public_keys {
            let mut vm = Vec::new();
            let mut my_purp = VmRelationshipSet::default();
            for k in keys.iter() {
                vm.push(k.verification_method.clone());
                let vm_ref = VmRelationship::from(&k.verification_method);
                if let Some(purposes) = &k.purposes {
                    for p in purposes {
                        my_purp.push(p.clone(), &vm_ref.clone());
                    }
                }
            }
            self.verification_method = Some(vm);
            self.reload_vm_relationships(&my_purp);
        }
        if let Some(services) = &pdoc.services {
            self.service = Some(services.clone());
        }
    }

    // Apply patch to add public keys
    fn apply_add_keys(&mut self, patch: &Patch) {
        let Some(keys) = &patch.public_keys else {
            return;
        };
        let mut my_vm = self.verification_method.clone().unwrap_or_default();
        let mut my_purp = VmRelationshipSet::from(self.clone());
        for k in keys.iter() {
            let vm_ref = VmRelationship::from(&k.verification_method);
            my_vm.push(k.verification_method.clone());
            if let Some(purposes) = &k.purposes {
                for p in purposes {
                    my_purp.push(p.clone(), &vm_ref.clone());
                }
            }
        }
        self.verification_method = if my_vm.is_empty() { None } else { Some(my_vm) };
        self.reload_vm_relationships(&my_purp);
    }

    // Apply patch to remove public keys. The patch must be given as a set of IDs.
    fn apply_remove_keys(&mut self, patch: &Patch) {
        if let Some(ids) = &patch.ids {
            let mut my_purp = VmRelationshipSet::from(self.clone());
            if let Some(mut vms) = self.verification_method.clone() {
                for id in ids {
                    vms.retain(|v| v.id != *id);
                }
                self.verification_method = Some(vms);
            }

            for id in ids.iter() {
                let vm_ref = VmRelationship {
                    key_id: Some(id.clone()),
                    verification_method: None,
                };
                my_purp.remove(&vm_ref);
            }
            self.reload_vm_relationships(&my_purp);
        }
    }
}

/// Types of patches (updates) that can be applied to a DID document.
#[derive(Clone, Default, Deserialize, Serialize)]
pub enum PatchAction {
    /// Create a new DID document or replace an entire DID document.
    #[default]
    #[serde(rename = "replace")]
    Replace,
    /// Add one or more public keys to the DID document.
    #[serde(rename = "add-public-keys")]
    AddPublicKeys,
    /// Remove one or more public keys from the DID document.
    #[serde(rename = "remove-public-keys")]
    RemovePublicKeys,
    /// Add one or more services to the DID document.
    #[serde(rename = "add-services")]
    AddServices,
    /// Remove one or more services from the DID document.
    #[serde(rename = "remove-services")]
    RemoveServices,
}

impl Display for PatchAction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            PatchAction::Replace => write!(f, "replace"),
            PatchAction::AddPublicKeys => write!(f, "add-public-keys"),
            PatchAction::RemovePublicKeys => write!(f, "remove-public-keys"),
            PatchAction::AddServices => write!(f, "add-services"),
            PatchAction::RemoveServices => write!(f, "remove-services"),
        }
    }
}

impl PartialEq for PatchAction {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (PatchAction::Replace, PatchAction::Replace)
                | (PatchAction::AddPublicKeys, PatchAction::AddPublicKeys)
                | (PatchAction::RemovePublicKeys, PatchAction::RemovePublicKeys)
                | (PatchAction::AddServices, PatchAction::AddServices)
                | (PatchAction::RemoveServices, PatchAction::RemoveServices)
        )
    }
}
impl Eq for PatchAction {}

/// DID document patch for creation or replacement of keys and services.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PatchDocument {
    /// Public keys to add or remove.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<VerificationMethodPatch>>,
    /// Services to add or remove.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
}

/// Create a PatchDocument from a DID document (for use in a DID create or replace)
impl From<&DidDocument> for PatchDocument {
    fn from(doc: &DidDocument) -> Self {
        let mut pdoc = PatchDocument {
            services: doc.service.clone(),
            ..Default::default()
        };
        if doc.verification_method.is_some() {
            let mut public_keys = Vec::new();
            for k in doc.verification_method.as_ref().unwrap().iter() {
                let vmr = VmRelationship::from(k);
                let vmp = VerificationMethodPatch {
                    verification_method: k.clone(),
                    ..Default::default()
                };
                let mut purposes = Vec::new();
                if let Some(auth) = &doc.authentication {
                    if auth.contains(&vmr) {
                        purposes.push(KeyPurpose::Authentication);
                    }
                }
                if let Some(assert) = &doc.assertion_method {
                    if assert.contains(&vmr) {
                        purposes.push(KeyPurpose::AssertionMethod);
                    }
                }
                if let Some(key) = &doc.key_agreement {
                    if key.contains(&vmr) {
                        purposes.push(KeyPurpose::KeyAgreement);
                    }
                }
                if let Some(cap) = &doc.capability_delegation {
                    if cap.contains(&vmr) {
                        purposes.push(KeyPurpose::CapabilityDelegation);
                    }
                }
                if let Some(cap) = &doc.capability_invocation {
                    if cap.contains(&vmr) {
                        purposes.push(KeyPurpose::CapabilityInvocation);
                    }
                }
                public_keys.push(vmp);
            }
            pdoc.public_keys = if public_keys.is_empty() {
                None
            } else {
                Some(public_keys)
            };
        }
        pdoc
    }
}

/// Patch information for updating a DID.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Patch {
    /// The type of patch to apply.
    pub action: PatchAction,
    /// A set of keys and services to construct a whole DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<PatchDocument>,
    /// A set of services to add. Only use this field for adding services. To remove services use
    /// the `ids` field instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
    /// A set of key IDs or service IDs to remove. This is the preferred way to reference keys and
    /// services and implement removals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// A set of public keys to add and the purposes they should be applied to. Only use this field
    /// for adding keys. To remove keys use the `ids` field instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<VerificationMethodPatch>>,
}

impl Patch {
    /// Construct a new patch using a PatchBuilder
    pub fn builder(action: PatchAction) -> PatchBuilder {
        PatchBuilder::new(action)
    }
}

/// Build and validate a patch.
#[derive(Default)]
pub struct PatchBuilder {
    action: PatchAction,
    document: Option<PatchDocument>,
    services: Vec<Service>,
    ids: Vec<String>,
    public_keys: Vec<VerificationMethodPatch>,
}

impl PatchBuilder {
    /// Initiate the build of a patch by supplying the intended action. This will drive what
    /// subsequent functions will validate and the final validation on build.
    pub fn new(action: PatchAction) -> PatchBuilder {
        PatchBuilder {
            action,
            document: None,
            services: Vec::new(),
            ids: Vec::new(),
            public_keys: Vec::new(),
        }
    }

    /// Adds a PatchDocument to the patch. This is only valid for a replace action.
    pub fn document(&mut self, document: &PatchDocument) -> Result<&PatchBuilder> {
        if self.action != PatchAction::Replace {
            tracerr!(
                Err::InvalidPatch,
                "A document can only be added to a replace patch"
            );
        }
        self.document = Some(document.clone());
        Ok(self)
    }

    /// Adds a service to the patch. This is only valid for an add services action.
    pub fn service(&mut self, service: &Service) -> Result<&PatchBuilder> {
        if self.action != PatchAction::AddServices {
            tracerr!(
                Err::InvalidPatch,
                "A service can only be added to an add-services patch"
            );
        }
        self.services.push(service.clone());
        Ok(self)
    }

    /// Adds a public key to the patch. Only valid for an add keys action.
    pub fn public_key(&mut self, key: &VerificationMethodPatch) -> Result<&PatchBuilder> {
        if self.action != PatchAction::AddPublicKeys {
            tracerr!(
                Err::InvalidPatch,
                "A public key can only be added to an add-public-keys patch"
            );
        }
        // Check the key ID looks OK
        self.check_id(&key.verification_method.id)?;
        // Check the purposes don't contain duplicates
        if let Some(purposes) = &key.purposes {
            let mut purpose_map = HashMap::new();
            for p in purposes {
                if purpose_map.contains_key(p) {
                    tracerr!(Err::InvalidInput, "Duplicate key purpose: {}", p);
                }
                purpose_map.insert(p.clone(), true);
            }
        }
        // Make sure the key ID is not already on the patch
        for k in self.public_keys.iter() {
            if k.verification_method.id == key.verification_method.id {
                tracerr!(
                    Err::InvalidPatch,
                    "Duplicate key ID: {}",
                    key.verification_method.id
                );
            }
        }
        self.public_keys.push(key.clone());
        Ok(self)
    }

    /// Adds an ID to the patch. This is only valid for remove keys or remove services actions.
    pub fn id(&mut self, id: &str) -> Result<&PatchBuilder> {
        self.check_id(id)?;
        if self.action != PatchAction::RemovePublicKeys
            && self.action != PatchAction::RemoveServices
        {
            tracerr!(
                Err::InvalidPatch,
                "An ID can only be added to a remove-public-keys or remove-services patch"
            );
        }
        // No duplicates
        for i in self.ids.iter() {
            if i == id {
                tracerr!(Err::InvalidPatch, "Duplicate ID: {}", id);
            }
        }
        self.ids.push(id.to_string());
        Ok(self)
    }

    /// Build the patch. Returns an error if the patch components have not been provided properly.
    pub fn build(&self) -> Result<Patch> {
        match self.action {
            PatchAction::Replace => {
                if self.document.is_none() {
                    tracerr!(
                        Err::InvalidPatch,
                        "A replace patch must contain a patch document"
                    );
                }
                Ok(Patch {
                    action: self.action.clone(),
                    document: self.document.clone(),
                    ..Default::default()
                })
            }
            PatchAction::AddPublicKeys => {
                if self.public_keys.is_empty() {
                    tracerr!(
                        Err::InvalidPatch,
                        "An add-public-keys patch must contain at least one key"
                    );
                }
                Ok(Patch {
                    action: self.action.clone(),
                    public_keys: Some(self.public_keys.clone()),
                    ..Default::default()
                })
            }
            PatchAction::RemovePublicKeys => {
                if self.ids.is_empty() {
                    tracerr!(
                        Err::InvalidPatch,
                        "A remove-public-keys patch must contain at least one ID"
                    );
                }
                Ok(Patch {
                    action: self.action.clone(),
                    ids: Some(self.ids.clone()),
                    ..Default::default()
                })
            }
            PatchAction::AddServices => {
                if self.services.is_empty() {
                    tracerr!(
                        Err::InvalidPatch,
                        "An add-services patch must contain at least one service"
                    );
                }
                Ok(Patch {
                    action: self.action.clone(),
                    services: Some(self.services.clone()),
                    ..Default::default()
                })
            }
            PatchAction::RemoveServices => {
                if self.ids.is_empty() {
                    tracerr!(
                        Err::InvalidPatch,
                        "A remove-services patch must contain at least one ID"
                    );
                }
                Ok(Patch {
                    action: self.action.clone(),
                    ids: Some(self.ids.clone()),
                    ..Default::default()
                })
            }
        }
    }

    // Check an ID is the correct length and a valid base64url characters or key ID part delimiters.
    // This is *not* a full check for a valid DID URL.
    // TODO: Find or build a DID URL checker.
    fn check_id(&self, id: &str) -> Result<()> {
        // if id.len() > 50 {
        //     tracerr!(Err::InvalidPatch, "ID exceeds limit of 50: {}", id.len());
        // }
        let re = Regex::new(r"^[a-zA-Z0-9_\-\?#:/=&\+%]*$")?;
        if !re.is_match(id) {
            tracerr!(
                Err::InvalidPatch,
                "ID contains invalid characters for a key. Must be a DID URL or path fragment: {}",
                id
            );
        }
        Ok(())
    }
}

/// Verification method with purpose information attached. Used for patching.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VerificationMethodPatch {
    /// The verification method.
    #[serde(flatten)]
    pub verification_method: VerificationMethod,
    /// The purposes for which this verification method is used.
    //// authentication, assertionMethod, capabilityInvocation, capabilityDelegation, keyAgreement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Vec<KeyPurpose>>,
}

// Struct for managing verification method relationahip patching due to the awkward DID spec. (Note
// that a hashmap indexed by KeyPurpose was explored but rejected in favour of explicit fields for
// code clarity and ease of use, especially in the case of removals).
#[derive(Default)]
struct VmRelationshipSet {
    authentication: Vec<VmRelationship>,
    assertion_method: Vec<VmRelationship>,
    key_agreement: Vec<VmRelationship>,
    capability_delegation: Vec<VmRelationship>,
    capability_invocation: Vec<VmRelationship>,
}

impl From<DidDocument> for VmRelationshipSet {
    fn from(doc: DidDocument) -> Self {
        let mut p = VmRelationshipSet::default();
        if let Some(auth) = doc.authentication {
            p.authentication = auth;
        }
        if let Some(assert) = doc.assertion_method {
            p.assertion_method = assert;
        }
        if let Some(key) = doc.key_agreement {
            p.key_agreement = key;
        }
        if let Some(cap) = doc.capability_delegation {
            p.capability_delegation = cap;
        }
        if let Some(cap) = doc.capability_invocation {
            p.capability_invocation = cap;
        }
        p
    }
}

impl VmRelationshipSet {
    fn push(&mut self, purpose: KeyPurpose, vm_ref: &VmRelationship) {
        match purpose {
            KeyPurpose::Authentication => self.authentication.push(vm_ref.clone()),
            KeyPurpose::AssertionMethod => self.assertion_method.push(vm_ref.clone()),
            KeyPurpose::KeyAgreement => self.key_agreement.push(vm_ref.clone()),
            KeyPurpose::CapabilityDelegation => self.capability_delegation.push(vm_ref.clone()),
            KeyPurpose::CapabilityInvocation => self.capability_invocation.push(vm_ref.clone()),
        }
    }

    fn remove(&mut self, vm_ref: &VmRelationship) {
        self.authentication.retain(|a| a != vm_ref);
        self.assertion_method.retain(|a| a != vm_ref);
        self.key_agreement.retain(|a| a != vm_ref);
        self.capability_delegation.retain(|a| a != vm_ref);
        self.capability_invocation.retain(|a| a != vm_ref);
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::document::{context, service::ServiceEndpoint, Context, VerificationMethod};
    use crate::keys::Jwk;

    fn public_key() -> Jwk {
        Jwk {
            kty: "EC".to_string(),
            crv: Some("secp256k1".to_string()),
            x: Some("smmFWI4qLfWztIzwurLCvjjw7guNZvN99ai2oTXGUtc".to_string()),
            y: Some("rxp_kiiXHitxLHe545cePsF0y_Mdv_dy6zY4ov_0q9g".to_string()),
            ..Default::default()
        }
    }

    fn default_service() -> Service {
        Service {
            id: "service1".to_string(),
            type_: vec!["service1type".to_string()],
            service_endpoint: vec![ServiceEndpoint {
                url: Some("https://service1.example.com/".to_string()),
                url_map: None,
            }],
        }
    }

    fn default_doc() -> DidDocument {
        DidDocument {
            id: "did:ion:EiAscM5K0lfATv8GEqlR_RAVId0alzdcOgIRs-fBLXBWFA".to_string(),
            context: vec![Context {
                url: Some(context::DID_CONTEXT.to_string()),
                url_map: None,
            }],
            controller: Some(vec![
                "did:ion:EiAscM5K0lfATv8GEqlR_RAVId0alzdcOgIRs-fBLXBWFA".to_string(),
            ]),
            also_known_as: None,
            verification_method: Some(vec![VerificationMethod {
                id: "371544b48d7d60d430c9c8b4af3745fa".to_string(),
                controller: "did:ion:EiAscM5K0lfATv8GEqlR_RAVId0alzdcOgIRs-fBLXBWFA".to_string(),
                type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
                public_key_jwk: Some(public_key()),
                public_key_multibase: None,
            }]),
            authentication: Some(vec![VmRelationship {
                key_id: Some("371544b48d7d60d430c9c8b4af3745fa".to_string()),
                verification_method: None,
            }]),
            assertion_method: Some(vec![VmRelationship {
                key_id: Some("371544b48d7d60d430c9c8b4af3745fa".to_string()),
                verification_method: None,
            }]),
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            service: Some(vec![default_service()]),
        }
    }

    #[test]
    fn patch_replace() {
        let mut doc = default_doc();
        let replacement = PatchDocument {
            public_keys: Some(vec![VerificationMethodPatch {
                verification_method: VerificationMethod {
                    id: "key2".to_string(),
                    type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
                    controller: "https://example.com".to_string(),
                    public_key_jwk: Some(Jwk {
                        kty: "EC".to_string(),
                        crv: Some("secp256k1".to_string()),
                        x: Some("QJZEHYfuTyjhIywIPKW_VLj9KQHUjLYCZJXJaNo2JQ4".to_string()),
                        y: Some("p_j1EtkaHqnuporRvK1Y0iyQ3orNmj5EzFVErdkGOFg".to_string()),
                        ..Default::default()
                    }),
                    public_key_multibase: None,
                },
                purposes: Some(vec![KeyPurpose::Authentication, KeyPurpose::KeyAgreement]),
            }]),
            services: Some(vec![Service {
                id: "service2".to_string(),
                type_: vec!["service2type".to_string()],
                service_endpoint: vec![ServiceEndpoint {
                    url: Some("https://service2.example.com/".to_string()),
                    url_map: None,
                }],
            }]),
        };

        let patch =
            Patch::builder(PatchAction::Replace).document(&replacement).unwrap().build().unwrap();
        doc.apply_patches(&[patch]);

        assert_eq!(doc.verification_method.clone().unwrap().len(), 1);
        assert_eq!(doc.verification_method.clone().unwrap()[0].id, "key2");
        assert_eq!(doc.service.clone().unwrap().len(), 1);
        assert_eq!(doc.service.clone().unwrap()[0].id, "service2");
        assert!(doc.assertion_method.is_none());
        assert_eq!(doc.authentication.clone().unwrap().len(), 1);
        assert_eq!(
            doc.authentication.clone().unwrap()[0].key_id.clone().unwrap(),
            "key2"
        );
        assert_eq!(doc.key_agreement.clone().unwrap().len(), 1);
        assert_eq!(
            doc.key_agreement.clone().unwrap()[0].key_id.clone().unwrap(),
            "key2"
        );
    }

    #[test]
    fn patch_add_key() {
        let mut doc = default_doc();
        let patch = Patch::builder(PatchAction::AddPublicKeys)
            .public_key(&VerificationMethodPatch {
                verification_method: VerificationMethod {
                    id: "key2".to_string(),
                    type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
                    controller: "https://example.com".to_string(),
                    public_key_jwk: Some(Jwk {
                        kty: "EC".to_string(),
                        crv: Some("secp256k1".to_string()),
                        x: Some("QJZEHYfuTyjhIywIPKW_VLj9KQHUjLYCZJXJaNo2JQ4".to_string()),
                        y: Some("p_j1EtkaHqnuporRvK1Y0iyQ3orNmj5EzFVErdkGOFg".to_string()),
                        ..Default::default()
                    }),
                    public_key_multibase: None,
                },
                purposes: Some(vec![KeyPurpose::Authentication, KeyPurpose::KeyAgreement]),
            })
            .unwrap()
            .build()
            .unwrap();

        doc.apply_patches(&[patch]);

        assert_eq!(doc.verification_method.clone().unwrap().len(), 2);
        assert_eq!(doc.verification_method.clone().unwrap()[1].id, "key2");
        assert_eq!(doc.service.clone().unwrap().len(), 1);
        assert_eq!(doc.authentication.clone().unwrap().len(), 2);
        assert_eq!(
            doc.authentication.clone().unwrap()[1].key_id.clone().unwrap(),
            "key2"
        );
        assert_eq!(doc.assertion_method.clone().unwrap().len(), 1);
        assert_eq!(doc.key_agreement.clone().unwrap().len(), 1);
        assert_eq!(
            doc.key_agreement.clone().unwrap()[0].key_id.clone().unwrap(),
            "key2"
        );
    }

    #[test]
    fn patch_remove_key() {
        let mut doc = default_doc();

        let key1 = doc.verification_method.clone().unwrap()[0].id.clone();

        // Add a second key and remove the first

        let patch_add = Patch::builder(PatchAction::AddPublicKeys)
            .public_key(&VerificationMethodPatch {
                verification_method: VerificationMethod {
                    id: "key2".to_string(),
                    type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
                    controller: "https://example.com".to_string(),
                    public_key_jwk: Some(Jwk {
                        kty: "EC".to_string(),
                        crv: Some("secp256k1".to_string()),
                        x: Some("QJZEHYfuTyjhIywIPKW_VLj9KQHUjLYCZJXJaNo2JQ4".to_string()),
                        y: Some("p_j1EtkaHqnuporRvK1Y0iyQ3orNmj5EzFVErdkGOFg".to_string()),
                        ..Default::default()
                    }),
                    public_key_multibase: None,
                },
                purposes: Some(vec![KeyPurpose::Authentication, KeyPurpose::KeyAgreement]),
            })
            .unwrap()
            .build()
            .unwrap();

        let patch_remove =
            Patch::builder(PatchAction::RemovePublicKeys).id(&key1).unwrap().build().unwrap();

        doc.apply_patches(&[patch_add, patch_remove]);

        assert_eq!(doc.verification_method.clone().unwrap().len(), 1);
        assert_eq!(doc.service.clone().unwrap().len(), 1);
        assert_eq!(doc.authentication.clone().unwrap().len(), 1);
        assert_eq!(
            doc.authentication.clone().unwrap()[0].key_id.clone().unwrap(),
            "key2"
        );
        assert!(doc.assertion_method.is_none());
        assert_eq!(doc.key_agreement.clone().unwrap().len(), 1);
        assert_eq!(
            doc.key_agreement.clone().unwrap()[0].key_id.clone().unwrap(),
            "key2"
        );
    }

    #[test]
    fn patch_add_service() {
        let mut doc = default_doc();
        let patch = Patch::builder(PatchAction::AddServices)
            .service(&Service {
                id: "service2".to_string(),
                type_: vec!["service2type".to_string()],
                service_endpoint: vec![ServiceEndpoint {
                    url: Some("https://service2.example.com/".to_string()),
                    url_map: None,
                }],
            })
            .unwrap()
            .build()
            .unwrap();

        doc.apply_patches(&[patch]);

        assert_eq!(doc.verification_method.clone().unwrap().len(), 1);
        assert_eq!(doc.service.clone().unwrap().len(), 2);
        assert_eq!(doc.service.clone().unwrap()[1].id, "service2");
    }

    #[test]
    fn patch_remove_service() {
        let mut doc = default_doc();

        let svc = doc.service.clone().unwrap()[0].id.clone();

        let patch_add = Patch::builder(PatchAction::AddServices)
            .service(&Service {
                id: "service2".to_string(),
                type_: vec!["service2type".to_string()],
                service_endpoint: vec![ServiceEndpoint {
                    url: Some("https://service2.example.com/".to_string()),
                    url_map: None,
                }],
            })
            .unwrap()
            .build()
            .unwrap();
        let patch_remove =
            Patch::builder(PatchAction::RemoveServices).id(&svc).unwrap().build().unwrap();
        doc.apply_patches(&[patch_add, patch_remove]);

        assert_eq!(doc.verification_method.clone().unwrap().len(), 1);
        assert_eq!(doc.service.clone().unwrap().len(), 1);
        assert_eq!(doc.service.clone().unwrap()[0].id, "service2");
    }
}

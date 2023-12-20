//! DID Document and its component data structures. Includes DID document patching and some
//! simple input verifications.

use serde::{Deserialize, Serialize};

use crate::document::{
    context::{context_serialization, Context},
    service::Service,
    verification_method::{KeyPurpose, VerificationMethod, VmRelationship},
};
use crate::error::Err;
use crate::serde::{option_flexvec, option_flexvec_or_single};
use crate::{tracerr, Result};

pub mod context;
pub mod patch;
pub mod service;
pub mod verification_method;

// ----------------------------------------------------------------------------
// DID Document
// ----------------------------------------------------------------------------

/// A DID is associated with a DID document that can be serialized into a representation of the DID.
/// https://www.w3.org/TR/did-core/
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DidDocument {
    /// The DID document's unique identifier. It is a URI scheme conformant with RFC3986. The syntax
    /// conforms to the that of the DID method implementation: "did:{method}:{uri}", where the URI
    /// portion can be used by a resolver of the DID method to retrieve the DID document.
    pub id: String,
    /// The JSON-LD Context is either a string or a list containing any combination of strings
    /// and/or ordered maps.
    #[serde(rename = "@context", with = "context_serialization")]
    pub context: Vec<Context>,
    /// A DID controller is an entity that is authorized to make changes to a DID document. It is a
    /// DID or list of DIDs and is optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_flexvec_or_single")]
    pub controller: Option<Vec<String>>,
    /// A DID subject can have multiple identifiers for different purposes, or at different times.
    /// The assertion that two or more DIDs (or other types of URI) refer to the same DID subject
    /// can be made using the alsoKnownAs property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    /// A set of parameters that can be used together with a process to independently verify a
    /// proof. For example, a cryptographic public key can be used as a verification method with
    /// respect to a digital signature; in such usage, it verifies that the signer possessed the
    /// associated cryptographic private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,
    /// Authentication methods - maps to one or more verification methods by ID or contains embedded
    /// verification methods. Specifies how the DID subject is authenticated for purposes such as
    /// logging into a website or engaging in challenge-response interactions.
    #[serde(skip_serializing_if = "Option::is_none", with = "option_flexvec")]
    pub authentication: Option<Vec<VmRelationship>>,
    /// Assertion methods - maps to one or more verification methods by ID or contains embedded
    /// verification methods. Specifies how the DID subject is expected to express claims such as
    /// for the purposes of issuing verifiable credentials, or for a verifier to determine the
    /// authenticity of the DID subject.
    #[serde(skip_serializing_if = "Option::is_none", with = "option_flexvec")]
    pub assertion_method: Option<Vec<VmRelationship>>,
    /// Key agreement methods - maps to one or more verification methods by ID or contains embedded
    /// verification methods. Specifies how an entity can generate encryption material to transmit
    /// confidential messages to the DID subject.
    #[serde(skip_serializing_if = "Option::is_none", with = "option_flexvec")]
    pub key_agreement: Option<Vec<VmRelationship>>,
    /// Capability invocation methods - maps to one or more verification methods by ID or contains
    /// embedded verification methods. Specifies how the DID subject can invoke a crypotgraphic
    /// capability, such as to authorize an update to the DID document.
    #[serde(skip_serializing_if = "Option::is_none", with = "option_flexvec")]
    pub capability_invocation: Option<Vec<VmRelationship>>,
    /// Capability delegation methods - maps to one or more verification methods by ID or contains
    /// embedded verification methods. Specifies how the DID subject can delegate a crypotgraphic
    /// capability to another party. For example, delegating the authority to access an online
    /// resource like an HTTP API.
    #[serde(skip_serializing_if = "Option::is_none", with = "option_flexvec")]
    pub capability_delegation: Option<Vec<VmRelationship>>,
    /// Services are used to express ways of communicating with the DID subject or associated
    /// entities. Can be any type of service the DID subject wants to advertise, including
    /// decentralized identity management services for further discovery, authentication,
    /// authorization, or interaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
}

/// Utility methods for looking up DID document components.
impl DidDocument {
    // Get a verfication method from a verification method reference, either by looking up the ID
    // or returning the embedded verification method. If the ref contains an ID that doesn't resolve
    // or an embedded verification method doesn't exist, None is returned.
    fn vm_from_ref(&self, vm_ref: &VmRelationship) -> Option<VerificationMethod> {
        if let Some(id) = &vm_ref.key_id {
            if let Some(vms) = &self.verification_method {
                for vm in vms {
                    if &vm.id == id {
                        return Some(vm.clone());
                    }
                }
            }
        } else if let Some(vm) = &vm_ref.verification_method {
            return Some(vm.clone());
        }
        None
    }

    /// Get a key from the document by purpose. If the key is not found, returns an error.
    pub fn get_key(&self, purpose: KeyPurpose) -> Result<VerificationMethod> {
        let mut vm = Option::<VerificationMethod>::None;
        match purpose {
            KeyPurpose::Authentication => {
                if let Some(auth) = &self.authentication {
                    for a in auth {
                        vm = self.vm_from_ref(a);
                        if vm.is_some() {
                            break;
                        }
                    }
                }
            }
            KeyPurpose::AssertionMethod => {
                if let Some(assert) = &self.assertion_method {
                    for a in assert {
                        vm = self.vm_from_ref(a);
                        if vm.is_some() {
                            break;
                        }
                    }
                }
            }
            KeyPurpose::KeyAgreement => {
                if let Some(key) = &self.key_agreement {
                    for k in key {
                        vm = self.vm_from_ref(k);
                        if vm.is_some() {
                            break;
                        }
                    }
                }
            }
            KeyPurpose::CapabilityDelegation => {
                if let Some(cap) = &self.capability_delegation {
                    for c in cap {
                        vm = self.vm_from_ref(c);
                        if vm.is_some() {
                            break;
                        }
                    }
                }
            }
            KeyPurpose::CapabilityInvocation => {
                if let Some(cap) = &self.capability_invocation {
                    for c in cap {
                        vm = self.vm_from_ref(c);
                        if vm.is_some() {
                            break;
                        }
                    }
                }
            }
        };

        match vm {
            Some(v) => Ok(v),
            None => tracerr!(Err::KeyNotFound, "No key found for purpose"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs::File, path::PathBuf, vec};

    use olpc_cjson::CanonicalFormatter;

    use super::*;
    use crate::document::service::ServiceEndpoint;
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
                ..Default::default()
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
    fn default_doc_is_empty() {
        let doc = DidDocument::default();
        assert_eq!(doc.id, "");
        assert!(doc.context.is_empty());
        assert!(doc.controller.is_none());
        assert!(doc.also_known_as.is_none());
        assert!(doc.verification_method.is_none());
        assert!(doc.authentication.is_none());
        assert!(doc.assertion_method.is_none());
        assert!(doc.key_agreement.is_none());
        assert!(doc.capability_invocation.is_none());
        assert!(doc.capability_delegation.is_none());
        assert!(doc.service.is_none());
    }

    #[test]
    fn serialize_constructed_doc() {
        let doc = default_doc();
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let s = String::from_utf8(buf).expect("failed to convert bytes to string");
        insta::assert_yaml_snapshot!(s);
    }

    #[test]
    fn deserialize_embedded_keys() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/did_doc_embedded_keys.json");
        let file = File::open(d.as_path()).expect("failed to open test file");
        let doc: DidDocument = serde_json::from_reader(file).expect("failed to deserialize");
        insta::with_settings!(
            { sort_maps => true },
            {
                insta::assert_yaml_snapshot!(doc);
            }
        );
    }

    #[test]
    fn serialize_embedded_keys() {
        let doc = DidDocument {
            context: vec![
                Context {
                    url: Some("https://www.w3.org/ns/did/v1".to_string()),
                    url_map: None,
                },
                Context {
                    url: Some("https://w3id.org/security/suites/ed25519-2020/v1".to_string()),
                    url_map: None,
                },
            ],
            id: "did:example:123".to_string(),
            authentication: Some(vec![VmRelationship {
                key_id: None,
                verification_method: Some(VerificationMethod {
                    id: "did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3"
                        .to_string(),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: "did:example:123".to_string(),
                    public_key_multibase: Some(
                        "zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf".to_string(),
                    ),
                    ..Default::default()
                }),
            }]),
            capability_invocation: Some(vec![VmRelationship {
                key_id: None,
                verification_method: Some(VerificationMethod {
                    id: "did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k"
                        .to_string(),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: "did:example:123".to_string(),
                    public_key_multibase: Some(
                        "z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN".to_string(),
                    ),
                    ..Default::default()
                }),
            }]),
            capability_delegation: Some(vec![VmRelationship {
                key_id: None,
                verification_method: Some(VerificationMethod {
                    id: "did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi"
                        .to_string(),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: "did:example:123".to_string(),
                    public_key_multibase: Some(
                        "zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL".to_string(),
                    ),
                    ..Default::default()
                }),
            }]),
            assertion_method: Some(vec![VmRelationship {
                key_id: None,
                verification_method: Some(VerificationMethod {
                    id: "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY"
                        .to_string(),
                    type_: "Ed25519VerificationKey2020".to_string(),
                    controller: "did:example:123".to_string(),
                    public_key_multibase: Some(
                        "z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA".to_string(),
                    ),
                    ..Default::default()
                }),
            }]),
            ..Default::default()
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let s = String::from_utf8(buf).expect("failed to convert bytes to string");
        insta::assert_yaml_snapshot!(s);
    }

    #[test]
    fn deserialized_referenced_keys() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/did_doc_keys_services.json");
        let file = File::open(d.as_path()).expect("failed to open test file");
        let doc: DidDocument = serde_json::from_reader(file).expect("failed to deserialize");
        insta::with_settings!(
            { sort_maps => true },
            {
                insta::assert_yaml_snapshot!(doc);
            }
        );
    }

    #[test]
    fn serialize_referenced_keys() {
        let doc = DidDocument {
            context: vec![
                Context {
                    url: Some("https://www.w3.org/ns/did/v1".to_string()),
                    url_map: None,
                },
                Context {
                    url: Some("https://w3id.org/security/suites/ed25519-2020/v1".to_string()),
                    url_map: None,
                },
            ],
            id: "did:example:123".to_string(),
            verification_method: Some(vec![VerificationMethod {
                id: "did:example:123#key-0".to_string(),
                type_: "JsonWebKey2020".to_string(),
                controller: "did:example:123".to_string(),
                public_key_jwk: Some(Jwk {
                    kty: "OKP".to_string(),
                    crv: Some("Ed25519".to_string()),
                    x: Some("VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            service: Some(vec![
                Service {
                    id: "did:example:123#vcs".to_string(),
                    type_: vec!["VerifiableCredentialService".to_string()],
                    service_endpoint: vec![ServiceEndpoint {
                        url: Some("https://example.com/vc/".to_string()),
                        url_map: None,
                    }],
                },
                Service {
                    id: "did:example:123#wibble".to_string(),
                    type_: vec!["WibbleService".to_string()],
                    service_endpoint: vec![
                        ServiceEndpoint {
                            url: Some("https://example.com/wibbleThing/".to_string()),
                            url_map: None,
                        },
                        ServiceEndpoint {
                            url: None,
                            url_map: Some(HashMap::from_iter(vec![(
                                "mappyThing".to_string(),
                                vec!["https://example.com/mappyThing/".to_string()],
                            )])),
                        },
                    ],
                },
            ]),
            ..Default::default()
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let s = String::from_utf8(buf).expect("failed to convert bytes to string");
        insta::assert_yaml_snapshot!(s);
    }

    #[test]
    fn get_key() {
        let doc = default_doc();
        let key = doc
            .get_key(KeyPurpose::Authentication)
            .expect("failed to extract expected authentication key");
        assert_eq!(key.id, "371544b48d7d60d430c9c8b4af3745fa");
        let key = doc
            .get_key(KeyPurpose::AssertionMethod)
            .expect("failed to extract expected assertion method key");
        assert_eq!(
            key.controller,
            "did:ion:EiAscM5K0lfATv8GEqlR_RAVId0alzdcOgIRs-fBLXBWFA"
        );
    }
}

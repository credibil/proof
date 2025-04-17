//! Tests being able to dereference a resource from a `did:web` document.

use std::str::FromStr;

use credibil_did::{
    core::Kind, document_resource, web, DocumentBuilder, KeyPurpose, MethodType, PublicKeyFormat, Resource, ServiceBuilder, Url, VerificationMethod, VerificationMethodBuilder, VmKeyId
};
use kms::Keyring;

// Create a new `did:web` document and dereference a resource from it.
#[tokio::test]
async fn create_then_deref() {
    let domain_and_path = "https://credibil.io/issuers/example";
    let did = web::default_did(domain_and_path).expect("should get default DID");
    assert_eq!(did, "did:web:credibil.io:issuers:example");

    let mut signer = Keyring::new();
    let vk = signer.jwk("signing").expect("should get signing key");
    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyJwk { public_key_jwk: vk.clone() })
        .key_id(&did, VmKeyId::Index("key".to_string(), 0))
        .expect("should apply key ID")
        .method_type(&MethodType::JsonWebKey2020)
        .expect("should apply method type")
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    let service = ServiceBuilder::new(&format!("{did}#whois"))
        .service_type(&"LinkedVerifiablePresentation")
        .endpoint_str(&"https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let url = Url::from_str(&vm.id).expect("should parse DID");

    let deref_vm = document_resource(&url, &doc).expect("should dereference VM");
    let Resource::VerificationMethod(deref_vm) = deref_vm else {
        panic!("should be a verification method");
    };

    let PublicKeyFormat::PublicKeyJwk{ public_key_jwk } = deref_vm.key else {
        panic!("should be a JWK");
    };
    assert_eq!(public_key_jwk.x, vk.x);
}

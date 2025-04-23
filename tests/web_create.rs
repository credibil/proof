//! Tests for the creation of a new `did:web` document.

use credibil_identity::{core::Kind, web, DocumentBuilder, KeyPurpose, MethodType, PublicKeyFormat, ServiceBuilder, VerificationMethod, VerificationMethodBuilder, VmKeyId};
use kms::Keyring;

// Test the happy path of creating a new `did:web` document. Should just work
// without errors.
#[tokio::test]
async fn create_success() {
    let domain_and_path = "https://credibil.io/issuers/example";
    let did = web::default_did(domain_and_path).expect("should get default DID");
    assert_eq!(did, "did:web:credibil.io:issuers:example");

    let mut signer = Keyring::new();
    let vk = signer.jwk("signing").expect("should get signing key");
    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyJwk { public_key_jwk: vk })
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
    let json_doc = serde_json::to_string_pretty(&doc).expect("should serialize document");
    print!("{json_doc}");
}

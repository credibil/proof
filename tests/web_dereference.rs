//! Tests being able to dereference a resource from a `did:web` document.

use std::str::FromStr;

use credibil_ecc::{Curve, Keyring, Signer};
use credibil_identity::did::{
    self, DocumentBuilder, KeyFormat, KeyId, Resource, ServiceBuilder, Url,
    VerificationMethodBuilder, web,
};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Create a new `did:web` document and dereference a resource from it.
#[tokio::test]
async fn create_then_deref() {
    const DID_URL: &str = "https://credibil.io/issuers/example";
    let did = web::default_did(DID_URL).expect("should create DID");
    assert_eq!(did, "did:web:credibil.io:issuers:example");

    let signer =
        Keyring::generate(&Vault, "wd", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");

    let vm = VerificationMethodBuilder::new(jwk.clone()).key_id(KeyId::Index("key-0".to_string()));

    let service = ServiceBuilder::new(format!("{did}#whois"))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois")
        .build();
    let doc = DocumentBuilder::new(did)
        .verification_method(vm)
        .add_service(service)
        .build()
        .expect("should build document");

    // verify
    let Some(vm_list) = &doc.verification_method else {
        panic!("should have a verification method");
    };
    let vm_url = &vm_list.first().expect("should have at least one VM").id;
    let url = Url::from_str(vm_url).expect("should parse DID");

    let deref_vm = did::document_resource(&url, &doc).expect("should dereference VM");
    let Resource::VerificationMethod(deref_vm) = deref_vm else {
        panic!("should be a verification method");
    };

    let KeyFormat::JsonWebKey { public_key_jwk } = deref_vm.key else {
        panic!("should be a JWK");
    };
    assert_eq!(public_key_jwk.x, jwk.x);
}

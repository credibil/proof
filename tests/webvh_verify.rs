//! Tests to verify log entries.

use credibil_did::{
    core::Kind, document::{
        DocumentBuilder, MethodType, ServiceBuilder, VerificationMethod, VerificationMethodBuilder,
        VmKeyId,
    }, key::url::did_from_jwk, webvh::{default_did, verify_proofs, CreateBuilder, Witness, WitnessWeight, SCID_PLACEHOLDER}, KeyPurpose, PublicKeyFormat
};
use credibil_infosec::Signer;
use kms::Keyring;

// Create a minimal document and then verify the proof. Should verify without
// errors.
#[tokio::test]
async fn simple_proof() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new();
    let update_multi = signer.multibase("signing").expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_multi = signer.multibase("id").expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyMultibase {
        public_key_multibase: update_multi,
    })
    .key_id(&did, VmKeyId::Authorization(id_multi))
    .expect("should apply key ID")
    .method_type(&MethodType::Ed25519VerificationKey2020)
    .expect("should apply method type")
    .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .build();

    let result = CreateBuilder::new()
        .document(&doc)
        .expect("should apply document")
        .update_keys(&update_keys)
        .expect("should apply update keys")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    println!("result log[0]: {:?}", result.log[0]);
    verify_proofs(&result.log[0]).await.expect("should verify proof");
}

// Create a document with more options and then verify the proof. Should verify
// without errors.
#[tokio::test]
async fn complex_proof() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new();
    let update_multi = signer.multibase("signing").expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_multi = signer.multibase("id").expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyMultibase {
        public_key_multibase: update_multi,
    })
    .key_id(&did, VmKeyId::Authorization(id_multi))
    .expect("should apply key ID")
    .method_type(&MethodType::Ed25519VerificationKey2020)
    .expect("should apply method type")
    .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    let service = ServiceBuilder::new(&format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER))
        .service_type(&"LinkedVerifiablePresentation")
        .endpoint_str(&"https://example.com/.well-known/whois")
        .build();

        let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi = signer.next_multibase("signing").expect("should get next key");

    let witness_keyring1 = Keyring::new();
    let vk1 = witness_keyring1.verifying_key().await.expect("should get verifying key");
    let witness_keyring2 = Keyring::new();
    let vk2 = witness_keyring2.verifying_key().await.expect("should get verifying key");
    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: did_from_jwk(&vk1).expect("should get verifying key as did:key"),
                weight: 50,
            },
            WitnessWeight {
                id: did_from_jwk(&vk2).expect("should get verifying key as did:key"),
                weight: 40,
            },
        ],
    };

    let result = CreateBuilder::new()
        .document(&doc)
        .expect("should apply document")
        .update_keys(&update_keys)
        .expect("should apply update keys")
        .next_key(&next_multi)
        .portable(false)
        .witness(&witnesses)
        .expect("witness information should be applied")
        .ttl(60)
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    verify_proofs(&result.log[0]).await.expect("should verify proof");
}

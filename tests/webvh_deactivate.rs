//! Tests for the deactivation of a `did:webvh` document and associated log
//! entries.
//! 

use credibil_did::{core::{Kind, OneMany}, document::{MethodType, Service, VerificationMethod}, operation::document::{Create, DocumentBuilder, Update, VerificationMethodBuilder, VmKeyId}, webvh::{create::CreateBuilder, deactivate::DeactivateBuilder, update::UpdateBuilder, url::default_did, Witness, WitnessWeight, SCID_PLACEHOLDER}, KeyPurpose};
use kms::new_keyring;
use serde_json::Value;

// Test the happy path of creating then deactivating a `did:webvh` document and
// log entries. Should just work without errors.
#[tokio::test]
async fn create_then_deactivate() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = new_keyring();
    let update_multi = signer.verifying_key_multibase().await.expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    signer.add_key("id");
    let id_jwk = signer.get_key("id").expect("should get key");
    signer.add_key("vm");
    let vm_jwk = signer.get_key("vm").expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&vm_jwk)
        .key_id(&did, VmKeyId::Authorization(id_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    let service = Service {
        id: format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER),
        type_: "LinkedVerifiablePresentation".to_string(),
        service_endpoint: OneMany::<Kind<Value>>::One(Kind::String(
            "https://example.com/.well-known/whois".to_string(),
        )),
    };
    let doc = DocumentBuilder::<Create>::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_key = signer.next_key_jwk().expect("should get next key");
    let next_multi = next_key.to_multibase().expect("should convert to multibase");

    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: new_keyring().did().to_string(),
                weight: 50,
            },
            WitnessWeight {
                id: new_keyring().did().to_string(),
                weight: 40,
            },
        ],
    };

    let create_result = CreateBuilder::new(&update_keys, &doc)
        .expect("should create builder")
        .next_key(&next_multi)
        .portable(false)
        .witness(&witnesses)
        .expect("witness information should be applied")
        .ttl(60)
        .build(&signer)
        .await
        .expect("should build document");

    let deactivate_result = DeactivateBuilder::new(&create_result.log)
        .expect("should create builder")
        .build(&signer)
        .await
        .expect("should build deactivated document");

    let logs = serde_json::to_string(&deactivate_result.log).expect("should serialize log entries");
    println!("{logs}");

    // Should have 3 log entries: create, nullify next keys, deactivate.
    assert_eq!(deactivate_result.log.len(), 3);
}

// Test the happy path of updating then deactivating a `did:webvh` document and
// log entries. Should just work without errors.
#[tokio::test]
async fn update_then_deactivate() {
    // --- Create --------------------------------------------------------------

    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = new_keyring();
    let update_multi = signer.verifying_key_multibase().await.expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    signer.add_key("id");
    let id_jwk = signer.get_key("id").expect("should get key");
    signer.add_key("vm");
    let vm_jwk = signer.get_key("vm").expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&vm_jwk)
        .key_id(&did, VmKeyId::Authorization(id_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    let service = Service {
        id: format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER),
        type_: "LinkedVerifiablePresentation".to_string(),
        service_endpoint: OneMany::<Kind<Value>>::One(Kind::String(
            "https://example.com/.well-known/whois".to_string(),
        )),
    };
    let doc = DocumentBuilder::<Create>::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_key = signer.next_key_jwk().expect("should get next key");
    let next_multi = next_key.to_multibase().expect("should convert to multibase");

    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: new_keyring().did().to_string(),
                weight: 50,
            },
            WitnessWeight {
                id: new_keyring().did().to_string(),
                weight: 40,
            },
        ],
    };

    let create_result = CreateBuilder::new(&update_keys, &doc)
        .expect("should create builder")
        .next_key(&next_multi)
        .portable(false)
        .witness(&witnesses)
        .expect("witness information should be applied")
        .ttl(60)
        .build(&signer)
        .await
        .expect("should build document");

    // --- Update --------------------------------------------------------------

    let doc = create_result.document.clone();

    // Rotate the signing key.
    signer.rotate().expect("should rotate keys on signer");
    let new_update = signer.verifying_key_multibase().await.expect("should get multibase key");
    let new_update_keys = vec![new_update.clone()];
    let new_update_keys: Vec<&str> = new_update_keys.iter().map(|s| s.as_str()).collect();
    let new_next = signer.next_key_jwk().expect("should get next key");
    let new_next_keys = vec![new_next.to_multibase().expect("should convert to multibase")];
    let new_next_keys: Vec<&str> = new_next_keys.iter().map(|s| s.as_str()).collect();

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let vm = vm_list.first().expect("should get first verification method");
    let auth_vm = Kind::<VerificationMethod>::String(vm.id.clone());

    // Construct a new document from the existing one.
    let doc = DocumentBuilder::<Update>::from(&doc)
        .add_verification_method(&auth_vm, &KeyPurpose::Authentication)
        .expect("should add verification method")
        .update();

    // Create an update log entry and skip witness verification of existing log.
    let update_result = UpdateBuilder::new(create_result.log.as_slice(), None, &doc, &signer)
        .await
        .expect("should create builder")
        .rotate_keys(&new_update_keys, &new_next_keys)
        .expect("should rotate keys on builder")
        .build(&signer)
        .await
        .expect("should build document");

    // --- Deactivate ----------------------------------------------------------

    signer.rotate().expect("should rotate keys on signer");
    let new_update = signer.verifying_key_multibase().await.expect("should get multibase key");
    let new_update_keys = vec![new_update.clone()];
    let new_update_keys: Vec<&str> = new_update_keys.iter().map(|s| s.as_str()).collect();
    let new_next = signer.next_key_jwk().expect("should get next key");
    let new_next_keys = vec![new_next.to_multibase().expect("should convert to multibase")];
    let new_next_keys: Vec<&str> = new_next_keys.iter().map(|s| s.as_str()).collect();
    let deactivate_result = DeactivateBuilder::new(&update_result.log)
        .expect("should create builder")
        .rotate_keys(&new_update_keys, &new_next_keys)
        .expect("should rotate keys on builder")
        .build(&signer)
        .await
        .expect("should build deactivated document");

    let logs = serde_json::to_string(&deactivate_result.log).expect("should serialize log entries");
    println!("{logs}");

    // Should have 4 log entries: create, update, nullify next keys, deactivate.
    assert_eq!(deactivate_result.log.len(), 4);
}

//! Tests for the update of an existing `did:webvh` document and associated log
//! entry.

use credibil_identity::core::Kind;
use credibil_identity::did::{
    DocumentBuilder, KeyPurpose, MethodType, PublicKeyFormat, ServiceBuilder, VerificationMethod,
    VerificationMethodBuilder, VmKeyId,
    webvh::{CreateBuilder, SCID_PLACEHOLDER, UpdateBuilder, Witness, WitnessWeight, default_did},
};
use credibil_identity::{VerifyBy, Signature};
use kms::Keyring;

// Test the happy path of creating then updating a `did:webvh` document and log
// entries. Should just work without errors.
#[tokio::test]
async fn update_success() {
    // --- Create --------------------------------------------------------------

    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new("webvh_update_success").await.expect("should create keyring");
    let update_multi = signer.multibase("signing").await.expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_multi = signer.multibase("id").await.expect("should get key");

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
        .service_type("LinkedVerifiablePresentation")
        .endpoint_str("https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi = signer.next_multibase("signing").await.expect("should get next key");

    let witness_keyring1 = Keyring::new("webvh_update_success_witness1").await.expect("should create keyring");
    let VerifyBy::KeyId(key_id1) =
        witness_keyring1.verification_method().await.expect("should get key id for witness1")
    else {
        panic!("should get key id");
    };
    let witness_keyring2 = Keyring::new("webvh_update_success_witness2").await.expect("should create keyring");
    let VerifyBy::KeyId(key_id2) =
        witness_keyring2.verification_method().await.expect("should get key id for witness2")
    else {
        panic!("should get key id");
    };
    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: key_id1,
                weight: 50,
            },
            WitnessWeight {
                id: key_id2,
                weight: 40,
            },
        ],
    };

    let create_result = CreateBuilder::new()
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

    // --- Update --------------------------------------------------------------

    let doc = create_result.document.clone();

    // Rotate the signing key.
    signer.rotate().await.expect("should rotate keys on signer");
    let new_update_multi = signer.multibase("signing").await.expect("should get multibase key");
    let new_update_keys = vec![new_update_multi.clone()];
    let new_update_keys: Vec<&str> = new_update_keys.iter().map(|s| s.as_str()).collect();

    let new_next_multi = signer.next_multibase("signing").await.expect("should get next key");
    let new_next_keys = vec![new_next_multi.clone()];
    let new_next_keys: Vec<&str> = new_next_keys.iter().map(|s| s.as_str()).collect();
    let id_multi = signer.multibase("id").await.expect("should get key");

    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyMultibase {
        public_key_multibase: new_update_multi,
    })
    .key_id(&did, VmKeyId::Authorization(id_multi))
    .expect("should apply key ID")
    .method_type(&MethodType::Ed25519VerificationKey2020)
    .expect("should apply method type")
    .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let vm = vm_list.first().expect("should get first verification method");
    let auth_vm = Kind::<VerificationMethod>::String(vm.id.clone());

    // Construct a new document from the existing one.
    let doc = DocumentBuilder::from(&doc)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_verification_method(&auth_vm, &KeyPurpose::Authentication)
        .expect("should add verification method")
        .build();

    // Create an update log entry and skip witness verification.
    let result = UpdateBuilder::from(create_result.log.as_slice(), None)
        .await
        .expect("should create builder")
        .document(&doc)
        .expect("should apply document")
        .rotate_keys(&new_update_keys, &new_next_keys)
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    let logs = serde_json::to_string(&result.log).expect("should serialize log entries");
    println!("{logs}");
}

//! Tests for resolving a `did:webvh` log into a DID document.

use credibil_identity::core::Kind;
use credibil_identity::did::{
    DocumentBuilder, KeyPurpose, MethodType, PublicKeyFormat, ServiceBuilder, VerificationMethod,
    VerificationMethodBuilder, VmKeyId,
    webvh::{
        CreateBuilder, DeactivateBuilder, SCID_PLACEHOLDER, UpdateBuilder, Witness, WitnessEntry,
        WitnessWeight, default_did, resolve_log,
    },
};
use credibil_identity::{Key, Signature};
use kms::Keyring;

// Construct a log with a single entry and make sure it resolves to a DID document.
#[tokio::test]
async fn resolve_single() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new("webvh_resolve_single").await.expect("should create keyring");
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
        .service_type(&"LinkedVerifiablePresentation")
        .endpoint_str(&"https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi = signer.next_multibase("signing").await.expect("should get next key");

    let witness_keyring1 =
        Keyring::new("webvh_resolve_single_witness1").await.expect("should create keyring");
    let Key::KeyId(key_id1) =
        witness_keyring1.verification_method().await.expect("should get key id for witness1")
    else {
        panic!("should get key id");
    };
    let witness_keyring2 =
        Keyring::new("webvh_resolve_single_witness2").await.expect("should create keyring");
    let Key::KeyId(key_id2) =
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

    let witness_proof1 =
        result.log[0].proof(&witness_keyring1).await.expect("should get witness proof");
    let witness_proof2 =
        result.log[0].proof(&witness_keyring2).await.expect("should get witness proof");
    let witness_proofs = vec![WitnessEntry {
        version_id: result.log[0].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    }];

    let resolved_doc =
        resolve_log(&result.log, Some(&witness_proofs), None).await.expect("should resolve log");

    // The resolved document should *almost* match the result of the update
    // except for some of the metadata. So remove the metadata from each and
    // then compare.
    let mut result_doc = result.document.clone();
    result_doc.did_document_metadata = None;
    let mut resolved_doc = resolved_doc.clone();
    resolved_doc.did_document_metadata = None;

    assert_eq!(result_doc, resolved_doc);
}

// Construct a log with multiple entries and make sure it resolves to a DID document.
#[tokio::test]
async fn resolve_multiple() {
    // --- Create --------------------------------------------------------------

    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new("webvh_resolve_multiple").await.expect("should create keyring");
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
        .service_type(&"LinkedVerifiablePresentation")
        .endpoint_str(&"https://example.com/.well-known/whois")
        .build();
    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi = signer.next_multibase("signing").await.expect("should get next key");

    let witness_keyring1 =
        Keyring::new("webvh_resolve_multiple_witness1").await.expect("should create keyring");
    let Key::KeyId(key_id1) =
        witness_keyring1.verification_method().await.expect("should get key id for witness1")
    else {
        panic!("should get key id");
    };
    let witness_keyring2 =
        Keyring::new("webvh_resolve_multiple_witness2").await.expect("should create keyring");
    let Key::KeyId(key_id2) =
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
        .expect("should add verification method")
        .add_verification_method(&auth_vm, &KeyPurpose::Authentication)
        .expect("should add verification method")
        .build();

    // Create an update log entry and skip witness verification of existing log.
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

    let witness_proof1 =
        result.log[0].proof(&witness_keyring1).await.expect("should get witness proof");
    let witness_proof2 =
        result.log[0].proof(&witness_keyring2).await.expect("should get witness proof");
    let mut witness_proofs = vec![WitnessEntry {
        version_id: result.log[0].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    }];
    let witness_proof1 =
        result.log[1].proof(&witness_keyring1).await.expect("should get witness proof");
    let witness_proof2 =
        result.log[1].proof(&witness_keyring2).await.expect("should get witness proof");
    witness_proofs.push(WitnessEntry {
        version_id: result.log[1].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    });

    let resolved_doc =
        resolve_log(&result.log, Some(&witness_proofs), None).await.expect("should resolve log");

    // The resolved document should *almost* match the result of the update
    // except for some of the metadata. So remove the metadata from each and
    // then compare.
    let mut result_doc = result.document.clone();
    result_doc.did_document_metadata = None;
    let mut resolved_doc = resolved_doc.clone();
    resolved_doc.did_document_metadata = None;

    assert_eq!(result_doc, resolved_doc);
}

// Test resolving a deactivated document.
#[tokio::test]
async fn resolve_deactivated() {
    // --- Create --------------------------------------------------------------

    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer =
        Keyring::new("webvh_resolve_deactivated").await.expect("should create keyring");
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
        .service_type(&"LinkedVerifiablePresentation")
        .endpoint_str(&"https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi = signer.next_multibase("signing").await.expect("should get next key");

    let witness_keyring1 =
        Keyring::new("webvh_resolve_deactivated_witness1").await.expect("should create keyring");
    let Key::KeyId(key_id1) =
        witness_keyring1.verification_method().await.expect("should get key id for witness1")
    else {
        panic!("should get key id");
    };
    let witness_keyring2 =
        Keyring::new("webvh_resolve_deactivated_witness2").await.expect("should create keyring");
    let Key::KeyId(key_id2) =
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

    // Create an update log entry and skip witness verification of existing log.
    let update_result = UpdateBuilder::from(create_result.log.as_slice(), None)
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

    // --- Deactivate ----------------------------------------------------------

    signer.rotate().await.expect("should rotate keys on signer");

    let new_update_multi = signer.multibase("signing").await.expect("should get multibase key");
    let new_update_keys = vec![new_update_multi.clone()];
    let new_update_keys: Vec<&str> = new_update_keys.iter().map(|s| s.as_str()).collect();

    let new_next_multi = signer.next_multibase("signing").await.expect("should get next key");
    let new_next_keys = vec![new_next_multi.clone()];
    let new_next_keys: Vec<&str> = new_next_keys.iter().map(|s| s.as_str()).collect();

    let deactivate_result = DeactivateBuilder::from(&update_result.log)
        .expect("should create builder")
        .rotate_keys(&new_update_keys, &new_next_keys)
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build deactivated document");

    let logs = serde_json::to_string(&deactivate_result.log).expect("should serialize log entries");
    println!("{logs}");

    let resolved_doc =
        resolve_log(&deactivate_result.log, None, None).await.expect("should resolve log");
    assert!(
        resolved_doc
            .did_document_metadata
            .expect("should get metadata")
            .deactivated
            .expect("should get deactivated")
    );
}

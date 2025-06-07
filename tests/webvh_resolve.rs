//! Tests for resolving a `did:webvh` log into a DID document.

use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_identity::did::webvh::{
    self, CreateBuilder, DeactivateBuilder, SCID_PLACEHOLDER, UpdateBuilder, Witness, WitnessEntry,
    WitnessWeight,
};
use credibil_identity::did::{DocumentBuilder, KeyId, ServiceBuilder, VerificationMethodBuilder};
use credibil_identity::{Signature, VerifyBy};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Construct a log with a single entry and make sure it resolves to a DID document.
#[tokio::test]
async fn resolve_single() {
    const DID_URL: &str = "https://credibil.io/issuers/example";

    // let mut signer = Keyring::new("wrs").await.expect("should create keyring");
    // let update_multi = signer.multibase("signing").await.expect("should get multibase key");
    let signer =
        Keyring::generate(&Vault, "wrs", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wrs", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = webvh::default_did(DID_URL).expect("should create DID");

    let vm = VerificationMethodBuilder::new(update_multi.clone())
        .did(&did)
        .key_id(KeyId::Authorization(id_multi))
        .build()
        .expect("should build");

    let service = ServiceBuilder::new(format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(did)
        .verification_method(vm)
        .add_service(service)
        .build()
        .expect("should build document");

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let next_multi = jwk.to_multibase().expect("should get multibase");

    let witness_1 =
        Keyring::generate(&Vault, "w1", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id1) =
        witness_1.verification_method().await.expect("should get key id")
    else {
        panic!("should get key id");
    };
    let witness_2 =
        Keyring::generate(&Vault, "w2", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id2) =
        witness_2.verification_method().await.expect("should get key id for witness2")
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
        .document(doc)
        .expect("should apply document")
        .update_keys(vec![update_multi])
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

    let witness_proof1 = result.log[0].proof(&witness_1).await.expect("should get witness proof");
    let witness_proof2 = result.log[0].proof(&witness_2).await.expect("should get witness proof");
    let witness_proofs = vec![WitnessEntry {
        version_id: result.log[0].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    }];

    let resolved_doc = webvh::resolve_log(&result.log, Some(&witness_proofs), None)
        .await
        .expect("should resolve log");

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

    const DID_URL: &str = "https://credibil.io/issuers/example";

    let signer =
        Keyring::generate(&Vault, "wrm", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wrm", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = webvh::default_did(DID_URL).expect("should create DID");

    let vm = VerificationMethodBuilder::new(update_multi.clone())
        .did(&did)
        .key_id(KeyId::Authorization(id_multi))
        .build()
        .expect("should build");

    let service = ServiceBuilder::new(format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois")
        .build();
    let doc = DocumentBuilder::new(&did)
        .verification_method(vm.clone())
        .add_service(service)
        .build()
        .expect("should build document");

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let next_multi = jwk.to_multibase().expect("should get multibase");

    let witness_1 =
        Keyring::generate(&Vault, "w1", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id1) =
        witness_1.verification_method().await.expect("should get key id")
    else {
        panic!("should get key id");
    };
    let witness_2 =
        Keyring::generate(&Vault, "w2", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id2) =
        witness_2.verification_method().await.expect("should get key id for witness2")
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
        .document(doc)
        .expect("should apply document")
        .update_keys(vec![update_multi])
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
    let signer = Keyring::rotate(&Vault, signer).await.expect("should rotate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let new_update_multi = jwk.to_multibase().expect("should get multibase");

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let new_next_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethodBuilder::new(new_update_multi.clone())
        .did(did)
        .key_id(KeyId::Authorization(id_multi))
        .build()
        .expect("should build");

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let auth_vm = vm_list.first().expect("should get first verification method");

    // Construct a new document from the existing one.
    let doc = DocumentBuilder::from(doc)
        .verification_method(vm.clone())
        .authentication(auth_vm.id.clone())
        .build()
        .expect("should build document");

    // Create an update log entry and skip witness verification of existing log.
    let result = UpdateBuilder::from(create_result.log.as_slice(), None)
        .await
        .expect("should create builder")
        .document(&doc)
        .expect("should apply document")
        .rotate_keys(vec![new_update_multi], &vec![new_next_multi])
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    let witness_proof1 = result.log[0].proof(&witness_1).await.expect("should get witness proof");
    let witness_proof2 = result.log[0].proof(&witness_2).await.expect("should get witness proof");
    let mut witness_proofs = vec![WitnessEntry {
        version_id: result.log[0].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    }];
    let witness_proof1 = result.log[1].proof(&witness_1).await.expect("should get witness proof");
    let witness_proof2 = result.log[1].proof(&witness_2).await.expect("should get witness proof");
    witness_proofs.push(WitnessEntry {
        version_id: result.log[1].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    });

    let resolved_doc = webvh::resolve_log(&result.log, Some(&witness_proofs), None)
        .await
        .expect("should resolve log");

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

    const DID_URL: &str = "https://credibil.io/issuers/example";

    let signer =
        Keyring::generate(&Vault, "wrd", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = webvh::default_did(DID_URL).expect("should get DID");

    let vm = VerificationMethodBuilder::new(update_multi.clone())
        .did(&did)
        .key_id(KeyId::Authorization(id_multi))
        .build()
        .expect("should build");

    let service = ServiceBuilder::new(format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(&did)
        .verification_method(vm.clone())
        .add_service(service)
        .build()
        .expect("should build document");

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let next_multi = jwk.to_multibase().expect("should get multibase");

    let witness_1 =
        Keyring::generate(&Vault, "w1", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id1) =
        witness_1.verification_method().await.expect("should get key id")
    else {
        panic!("should get key id");
    };
    let witness_2 =
        Keyring::generate(&Vault, "w2", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id2) =
        witness_2.verification_method().await.expect("should get key id for witness2")
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
        .document(doc)
        .expect("should apply document")
        .update_keys(vec![update_multi])
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
    let signer = Keyring::rotate(&Vault, signer).await.expect("should rotate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let new_update_multi = jwk.to_multibase().expect("should get multibase");

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let new_next_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethodBuilder::new(new_update_multi.clone())
        .did(did)
        .key_id(KeyId::Authorization(id_multi))
        .build()
        .expect("should build");

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let auth_vm = vm_list.first().expect("should get first verification method");

    // Construct a new document from the existing one.
    let doc = DocumentBuilder::from(doc)
        .verification_method(vm.clone())
        .authentication(auth_vm.id.clone())
        .build()
        .expect("should build document");

    // Create an update log entry and skip witness verification of existing log.
    let update_result = UpdateBuilder::from(create_result.log.as_slice(), None)
        .await
        .expect("should create builder")
        .document(&doc)
        .expect("should apply document")
        .rotate_keys(vec![new_update_multi], &vec![new_next_multi])
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    // --- Deactivate ----------------------------------------------------------

    let signer = Keyring::rotate(&Vault, signer).await.expect("should rotate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let new_update_multi = jwk.to_multibase().expect("should get multibase");

    let new_update_keys = vec![new_update_multi.clone()];
    let new_update_keys: Vec<&str> = new_update_keys.iter().map(|s| s.as_str()).collect();

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let new_next_multi = jwk.to_multibase().expect("should get multibase");

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
        webvh::resolve_log(&deactivate_result.log, None, None).await.expect("should resolve log");
    assert!(
        resolved_doc
            .did_document_metadata
            .expect("should get metadata")
            .deactivated
            .expect("should get deactivated")
    );
}

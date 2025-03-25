//! Tests for resolving a `did:webvh` log into a DID document.

use credibil_did::{
    KeyPurpose,
    core::{Kind, OneMany},
    document::{MethodType, Service, VerificationMethod},
    operation::document::{Create, DocumentBuilder, VerificationMethodBuilder, VmKeyId},
    webvh::{
        SCID_PLACEHOLDER, Witness, WitnessEntry, WitnessWeight, create::CreateBuilder,
        resolve::resolve_log, url::default_did,
    },
};
use kms::new_keyring;
use serde_json::Value;

// Construct a log with a single entry and make sure it resolves to a DID document.
#[tokio::test]
async fn resolve_single() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let signer = new_keyring();
    let auth_jwk = signer.verifying_key_jwk().await.expect("should get JWK key");
    let update_multi = signer.verifying_key_multibase().await.expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let did = default_did(domain_and_path).expect("should get default DID");
    let db = DocumentBuilder::<Create>::new(&did);

    let vm_jwk = new_keyring().verifying_key_jwk().await.expect("should get JWK key");
    let vm = VerificationMethodBuilder::new(&vm_jwk)
        .key_id(db.did(), VmKeyId::Authorization(auth_jwk))
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
    let db = db
        .verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .service(&service);

    let doc = db.build();

    let next_multi =
        new_keyring().verifying_key_multibase().await.expect("should get multibase key");
    let witness_keyring1 = new_keyring();
    let witness1 = WitnessWeight {
        id: witness_keyring1.did_key(),
        weight: 50,
    };
    let witness_keyring2 = new_keyring();
    let witness2 = WitnessWeight {
        id: witness_keyring2.did_key(),
        weight: 40,
    };

    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![witness1, witness2],
    };

    let result = CreateBuilder::new(&update_keys, &doc)
        .expect("should create builder")
        .next_key(&next_multi)
        .portable(false)
        .ttl(60)
        .witness(&witnesses)
        .expect("witness information should be applied")
        .build(&signer)
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

    let resolved_doc = resolve_log(&result.log, Some(&witness_proofs), None, &signer)
        .await
        .expect("should resolve log");
    assert_eq!(result.document, resolved_doc);
}

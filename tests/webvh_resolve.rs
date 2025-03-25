//! Tests for resolving a `did:webvh` log into a DID document.

use credibil_did::{
    KeyPurpose,
    core::{Kind, OneMany},
    document::{MethodType, Service, VerificationMethod},
    operation::document::{VerificationMethodBuilder, VmKeyId},
    webvh::{
        SCID_PLACEHOLDER, Witness, WitnessEntry, WitnessWeight,
        create::{
            CreateBuilder, WithUpdateKeys, WithUrl, WithoutUpdateKeys, WithoutUrl,
            WithoutVerificationMethods,
        },
        resolve_log,
    },
};
use kms::new_keyring;
use multibase::Base;
use serde_json::Value;
use sha2::Digest;

// Construct a log with a single entry and make sure it resolves to a DID document.
#[tokio::test]
async fn resolve_single() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let signer = new_keyring();
    let auth_jwk = signer.verifying_key_jwk().await.expect("should get JWK key");
    let update_multi =
        signer.verifying_key_multibase().await.expect("should get multibase key");

    let doc_builder: CreateBuilder<WithUrl, WithUpdateKeys, WithoutVerificationMethods> =
        CreateBuilder::<WithoutUrl, WithoutUpdateKeys, WithoutVerificationMethods>::new()
            .url(domain_and_path)
            .expect("should apply URL")
            .update_keys(vec![update_multi])
            .expect("should apply update keys");

    let vm_jwk = new_keyring().verifying_key_jwk().await.expect("should get JWK key");
    let vm = VerificationMethodBuilder::new(&vm_jwk)
        .key_id(doc_builder.did(), VmKeyId::Authorization(auth_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();

    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    let doc_builder = doc_builder
        .verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .portable(false);

    let next_multi =
        new_keyring().verifying_key_multibase().await.expect("should get multibase key");
    let next_digest = sha2::Sha256::digest(next_multi.as_bytes());
    let next_hash = multibase::encode(Base::Base58Btc, next_digest.as_slice());

    let doc_builder = doc_builder.next_key_hash(next_hash);

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
    let doc_builder =
        doc_builder.witness(&witnesses).expect("witness information should be applied").ttl(60);

    let service = Service {
        id: format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER),
        type_: "LinkedVerifiablePresentation".to_string(),
        service_endpoint: OneMany::<Kind<Value>>::One(Kind::String(
            "https://example.com/.well-known/whois".to_string(),
        )),
    };

    let doc_builder = doc_builder.service(&service);

    let create_result = doc_builder.build(&signer).await.expect("should build document");

    let witness_proof1 =
        create_result.log[0].proof(&witness_keyring1).await.expect("should get witness proof");
    let witness_proof2 =
        create_result.log[0].proof(&witness_keyring2).await.expect("should get witness proof");
    let witness_proofs = vec![WitnessEntry {
        version_id: create_result.log[0].version_id.clone(),
        proof: vec![witness_proof1, witness_proof2],
    }];

    let resolved_doc = resolve_log(&create_result.log, Some(&witness_proofs), None, &signer)
        .await
        .expect("should resolve log");
    assert_eq!(create_result.document, resolved_doc);
}

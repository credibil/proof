use olpc_cjson::CanonicalFormatter;
use serde::Serialize;
use vercre_didcore::{
    error::Err,
    hashing::{check, hash_commitment, hash_data, rand_hex},
    tracerr, Action, DidDocument, Document, Jwk, KeyOperation, KeyPurpose, KeyRing, OperationType,
    Patch, Registrar, Result, Service, Signer, VerificationMethod, VmWithPurpose,
};

use crate::ion::{Delta, Registrar as IonRegistrar, Request};

/// DID Registrar implementation for the ION method.
#[allow(async_fn_in_trait)]
impl<K> Registrar for IonRegistrar<K>
where
    K: KeyRing + Signer + Send + Sync,
{
    // Construct a DID creation request for the specified DID document.
    async fn create(&self, services: Option<&[Service]>) -> Result<DidDocument> {
        let signing_key = self.keyring.next_key(&KeyOperation::Sign).await?;
        let algorithm = match signing_key.check(&self.keyring.supported_algorithms()) {
            Ok(a) => a,
            Err(e) => tracerr!(e, "Signing key error"),
        };

        let mut doc = DidDocument::default();
        let vm = VmWithPurpose {
            verification_method: VerificationMethod {
                id: rand_hex(8),
                controller: self.controller.clone().unwrap_or_default(),
                type_: algorithm.cryptosuite().to_string(),
                public_key_jwk: Some(signing_key.clone()),
                ..Default::default()
            },
            purposes: Some(vec![
                KeyPurpose::Authentication,
                KeyPurpose::AssertionMethod,
            ]),
        };
        let patch_key = Patch::builder(Action::AddPublicKeys).public_key(&vm)?.build()?;
        doc.apply_patches(&[patch_key]);

        if let Some(svcs) = services {
            let mut patch_service_builder = Patch::builder(Action::AddServices);
            for s in svcs {
                patch_service_builder.service(s)?;
            }
            let patch_service = patch_service_builder.build()?;
            doc.apply_patches(&[patch_service]);
        }

        let next_update_key = self.keyring.next_key(&KeyOperation::Update).await?;
        match next_update_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Next update key error"),
        };
        let update_commitment = hash_commitment(&next_update_key)?;

        let next_recover_key = self.keyring.next_key(&KeyOperation::Recover).await?;
        match next_recover_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Next recovery key error"),
        }
        let recovery_commitment = hash_commitment(&next_recover_key)?;

        let req =
            IonRegistrar::<K>::create_request(&recovery_commitment, &update_commitment, &doc)?;

        if self.anchor {
            self.submit(&req).await?;
        }

        // If the key ring needs to commit newly created keys, let it do so now.
        self.keyring.commit().await?;

        let did = self.short_did(&req)?;
        doc.id = did.clone();
        Ok(doc)
    }

    /// Construct a DID update request for the specified patches.
    ///
    /// # Arguments
    ///
    /// * `doc` - The current-state DID document to update.
    /// * `patches` - The patches to apply to the DID document.
    ///
    /// # Returns
    ///
    /// The updated DID document.
    ///
    /// # Errors
    ///
    /// * Underlying Azure Key Vault client errors.
    /// * Validation errors.
    /// * Serialization errors.
    /// * Hashing and signing errors.
    /// * Error if failing to successfully call the anchoring API.
    /// * Error if failing to commit the key ring key rotations.
    async fn update(&self, doc: &DidDocument, patches: &[Patch]) -> Result<DidDocument> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            update_key: Jwk,
            delta_hash: String,
        }
        let update_key = self.keyring.active_key(&KeyOperation::Update).await?;
        match update_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Active update key error"),
        }

        let next_update_key = self.keyring.next_key(&KeyOperation::Update).await?;
        match next_update_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Next update key error"),
        }

        let (_, suffix) = doc.id.rsplit_once(':').unwrap_or((&doc.id, ""));
        check(suffix)?;

        let update_commitment = hash_commitment(&next_update_key)?;

        let delta = Delta {
            patches: patches.to_vec(),
            update_commitment: update_commitment.clone(),
        };
        let delta_hash = hash_data(&delta)?;

        let data = Data {
            update_key: update_key.clone(),
            delta_hash,
        };
        let data_bytes = serde_json::to_vec(&data)?;
        let alg = update_key.infer_algorithm()?;
        let (signed_bytes, _kid) =
            self.keyring.try_sign_op(&data_bytes, &KeyOperation::Update, Some(alg)).await?;

        let signed_data = String::from_utf8(signed_bytes)?;
        let reveal_value = hash_data(&update_key.clone())?;

        let req = Request {
            type_: OperationType::Update,
            did_suffix: Some(suffix.to_string()),
            reveal_value: Some(reveal_value),
            delta: Some(delta),
            signed_data: Some(signed_data),
            ..Default::default()
        };

        if self.anchor {
            self.submit(&req).await?;
        }

        // If the key ring needs to commit newly created keys, let it do so now.
        self.keyring.commit().await?;

        // Construct the new DID document
        let mut updated_doc = doc.clone();
        updated_doc.apply_patches(patches);

        Ok(updated_doc)
    }

    /// Construct a DID deactivation request.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to deactivate.
    ///  
    /// # Errors
    ///
    /// * Underlying Azure Key Vault client errors.
    /// * Validation errors.
    /// * Serialization errors.
    /// * Hashing and signing errors.
    /// * Error if failing to successfully call the anchoring API.
    /// * Error if failing to commit the key ring key rotations.
    async fn deactivate(&self, did: &str) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            did_suffix: String,
            recovery_key: Jwk,
        }

        let recovery_key = self.keyring.active_key(&KeyOperation::Recover).await?;
        match recovery_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Active recovery key error"),
        }

        let (_, suffix) = did.rsplit_once(':').unwrap_or((&did, ""));
        check(suffix)?;

        let data = Data {
            did_suffix: suffix.to_string(),
            recovery_key: recovery_key.clone(),
        };
        let data_bytes = serde_json::to_vec(&data)?;
        let alg = recovery_key.infer_algorithm()?;
        let (signed_bytes, _kid) =
            self.keyring.try_sign_op(&data_bytes, &KeyOperation::Recover, Some(alg)).await?;
        let signed_data = String::from_utf8(signed_bytes)?;
        let reveal_value = hash_data(&recovery_key.clone())?;

        let req = Request {
            type_: OperationType::Deactivate,
            did_suffix: Some(suffix.to_string()),
            reveal_value: Some(reveal_value),
            signed_data: Some(signed_data),
            ..Default::default()
        };

        if self.anchor {
            self.submit(&req).await?;
        }
        self.keyring.commit().await
    }

    /// Construct a DID recovery request.
    ///
    /// # Errors
    ///
    /// * Underlying Azure Key Vault client errors.
    /// * Validation errors.
    /// * Serialization errors.
    /// * Hashing and signing errors.
    async fn recover(&self, doc: &DidDocument) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            recovery_commitment: String,
            recovery_key: Jwk,
            delta_hash: String,
        }

        let recovery_key = self.keyring.active_key(&KeyOperation::Recover).await?;
        match recovery_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Active recovery key error"),
        }

        let next_update_key = self.keyring.next_key(&KeyOperation::Update).await?;
        match next_update_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Next update key error"),
        }

        let next_recovery_key = self.keyring.next_key(&KeyOperation::Recover).await?;
        match next_recovery_key.check(&self.keyring.supported_algorithms()) {
            Ok(_) => (),
            Err(e) => tracerr!(e, "Next recovery key error"),
        };

        let (_, suffix) = doc.id.rsplit_once(':').unwrap_or((&doc.id, ""));
        check(suffix)?;

        let update_commitment = hash_commitment(&next_update_key)?;
        let delta = Delta {
            patches: vec![Patch {
                action: Action::Replace,
                document: Some(Document::from(doc)),
                ..Default::default()
            }],
            update_commitment: update_commitment.clone(),
        };
        check_delta(&delta)?;
        let delta_hash = hash_data(&delta)?;

        let recovery_commitment = hash_commitment(&next_recovery_key)?;

        let data = Data {
            recovery_commitment: recovery_commitment.clone(),
            recovery_key: recovery_key.clone(),
            delta_hash,
        };
        let data_bytes = serde_json::to_vec(&data)?;
        let alg = next_recovery_key.infer_algorithm()?;
        let (signed_bytes, _kid) =
            self.keyring.try_sign_op(&data_bytes, &KeyOperation::Recover, Some(alg)).await?;
        let signed_data = String::from_utf8(signed_bytes)?;
        let reveal_value = hash_data(&recovery_key.clone())?;

        let req = Request {
            type_: OperationType::Recover,
            did_suffix: Some(suffix.to_string()),
            reveal_value: Some(reveal_value),
            delta: Some(delta),
            signed_data: Some(signed_data),
            ..Default::default()
        };

        if self.anchor {
            self.submit(&req).await?;
        }
        self.keyring.commit().await?;

        Ok(())
    }

    /// Declare the DID method for this registrar.
    fn method(&self) -> &str {
        "ion"
    }
}

/// Check the delta can be marshalled to canonical JSON that is no more than 1000 bytes long.
///
/// # Errors
///
/// * `Err::InvalidFormat` if the delta is too long.
/// * serialization error if the delta cannot be serialised.
pub fn check_delta(delta: &Delta) -> Result<()> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    delta.serialize(&mut ser)?;
    if buf.len() > 1000 {
        tracerr!(
            Err::InvalidFormat,
            "Delta longer than 1000 bytes: {}",
            buf.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use vercre_didcore::{
        test_utils::TestKeyRingSigner, Endpoint, KeyPurpose, Registrar, Service, VerificationMethod,
    };

    use super::*;

    fn test_registrar() -> IonRegistrar<TestKeyRingSigner> {
        IonRegistrar::new(
            &std::env::var("AZURE_ION_CHALLENGE_URL").expect("AZURE_ION_CHALLENGE_URL not set"),
            &std::env::var("AZURE_ION_SOLUTION_URL").expect("AZURE_ION_SOLUTION_URL not set"),
            &std::env::var("AZURE_ION_RESOLUTION_URL").expect("AZURE_ION_RESOLUTION_URL not set"),
            TestKeyRingSigner::default(),
            false,
            None,
            None,
        )
    }

    #[tokio::test]
    async fn create_request() {
        let reg = test_registrar();

        let service = vec![Service {
            id: "service1Id".to_string(),
            type_: vec!["service1Type".to_string()],
            service_endpoint: vec![Endpoint {
                url: Some("http://www.service1.com".to_string()),
                url_map: None,
            }],
        }];

        let doc = reg.create(Some(&service)).await.expect("failed to create DID document");

        // The create process will include a random verification method ID so we will get a new
        // DID every time because the suffix data will be different. So we just do some basic
        // format testing here and rely on unit tests deeper in the process.
        assert!(doc.id.starts_with("did:ion:"));
        let (_, suffix) = doc.id.rsplit_once(':').expect("no suffix");
        assert_eq!(suffix.len(), 46);
        assert!(doc.verification_method.is_some_and(|vm| vm.len() == 1));
        assert!(doc.service.is_some_and(|s| s.len() == 1));
    }

    #[tokio::test]
    async fn update_request() {
        let pk = Jwk {
            kty: "EC".to_string(),
            crv: Some("secp256k1".to_string()),
            x: Some("smmFWI4qLfWztIzwurLCvjjw7guNZvN99ai2oTXGUtc".to_string()),
            y: Some("rxp_kiiXHitxLHe545cePsF0y_Mdv_dy6zY4ov_0q9g".to_string()),
            ..Default::default()
        };

        let patch = Patch::builder(Action::AddPublicKeys)
            .public_key(&VmWithPurpose {
                verification_method: VerificationMethod {
                    id: "keyId2".to_string(),
                    type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
                    public_key_jwk: Some(pk),
                    ..Default::default()
                },
                purposes: Some(vec![KeyPurpose::Authentication, KeyPurpose::KeyAgreement]),
            })
            .expect("failed to add public key to patch")
            .build()
            .expect("failed to build patch");

        let reg = test_registrar();
        let doc = reg
            .create(Some(&[Service {
                id: "service1Id".to_string(),
                type_: vec!["service1Type".to_string()],
                service_endpoint: vec![Endpoint {
                    url: Some("http://www.service1.com".to_string()),
                    url_map: None,
                }],
            }]))
            .await
            .expect("failed to create DID document");

        let updated_doc = match reg.update(&doc, &[patch]).await {
            Ok(r) => r,
            Err(e) => panic!("Update request error: {}", e),
        };

        // Check did hasn't changed
        assert_eq!(updated_doc.id, doc.id);

        // Check new key has been added and purposes updated.
        assert!(updated_doc.verification_method.clone().is_some_and(|vm| vm.len() == 2));
        assert!(updated_doc.authentication.clone().is_some_and(|a| a.len() == 2));
        assert!(updated_doc.key_agreement.clone().is_some_and(|a| a.len() == 1));

        let patch = Patch::builder(Action::RemovePublicKeys)
            .id("keyId2")
            .expect("failed to add id to patch")
            .build()
            .expect("failed to build patch");
        let updated_doc2 = match reg.update(&updated_doc, &[patch]).await {
            Ok(r) => r,
            Err(e) => panic!("Update request error: {}", e),
        };

        assert_eq!(updated_doc2.id, doc.id);
        assert!(updated_doc2.verification_method.clone().is_some_and(|vm| vm.len() == 1));
        assert!(updated_doc2.authentication.clone().is_some_and(|a| a.len() == 1));
        assert!(updated_doc2.key_agreement.clone().is_none());

        let patch = Patch::builder(Action::AddServices)
            .service(&Service {
                id: "service2Id".to_string(),
                type_: vec!["service2Type".to_string()],
                service_endpoint: vec![Endpoint {
                    url: Some("http://www.service2.com".to_string()),
                    url_map: None,
                }],
            })
            .expect("failed to add service to patch")
            .build()
            .expect("failed to build patch");
        let updated_doc3 = match reg.update(&updated_doc2, &[patch]).await {
            Ok(r) => r,
            Err(e) => panic!("Update request error: {}", e),
        };

        assert_eq!(updated_doc3.id, doc.id);
        assert!(updated_doc3.service.clone().is_some_and(|s| s.len() == 2));

        let patch = Patch::builder(Action::RemoveServices)
            .id("service2Id")
            .expect("failed to add ID to patch")
            .build()
            .expect("failed to build patch");
        let updated_doc4 = match reg.update(&updated_doc3, &[patch]).await {
            Ok(r) => r,
            Err(e) => panic!("Update request error: {}", e),
        };

        assert_eq!(updated_doc4.id, doc.id);
        assert!(updated_doc4.service.clone().is_some_and(|s| s.len() == 1));
    }

    #[tokio::test]
    async fn recover_request() {
        let reg = test_registrar();
        let doc = reg
            .create(Some(&[Service {
                id: "service1Id".to_string(),
                type_: vec!["service1Type".to_string()],
                service_endpoint: vec![Endpoint {
                    url: Some("http://www.service1.com".to_string()),
                    url_map: None,
                }],
            }]))
            .await
            .expect("failed to create DID document");

        let mut doc2 = reg
            .create(Some(&[Service {
                id: "service2Id".to_string(),
                type_: vec!["service1Type".to_string()],
                service_endpoint: vec![Endpoint {
                    url: Some("http://www.service2.com".to_string()),
                    url_map: None,
                }],
            }]))
            .await
            .expect("failed to create DID document");
        doc2.id = doc.id.clone();

        match reg.recover(&doc2).await {
            Ok(_) => (),
            Err(e) => panic!("Recover request error: {}", e),
        };

        assert_eq!(doc.id, doc2.id);
    }

    #[tokio::test]
    async fn deactive_request() {
        let did = "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg";

        let reg = test_registrar();
        match reg.deactivate(did).await {
            Ok(r) => r,
            Err(e) => panic!("Deactivate request error: {}", e),
        };
    }
}

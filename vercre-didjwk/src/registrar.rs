use base64ct::{Base64UrlUnpadded, Encoding};
use vercre_didcore::{
    error::Err, tracerr, Action, Context, DidDocument, KeyOperation, KeyPurpose, KeyRing, Patch,
    Registrar, Result, Service, VerificationMethod, VmWithPurpose, DID_CONTEXT,
};
use vercre_ephemeral_keyring::KeyPair;

use crate::jwk::Registrar as JwkRegistrar;

/// DID Registrar implementation for the JWK method.
#[allow(async_fn_in_trait)]
impl<K> Registrar for JwkRegistrar<K>
where
    K: KeyPair + Send + Sync,
{
    /// Create a DID document.
    ///
    /// For the JWK method, this will create a DID document with a single verification method. The
    /// services are not supported by this method and will return an error if specified.
    ///
    /// # Arguments
    ///
    /// * `services` - Must be None for this DID method.
    ///
    /// # Returns
    ///
    /// * The DID document. The ID of the document will be the DID.
    ///
    /// # Errors
    ///
    /// * If the services argument is not None.
    /// * If the keyring does not have a key for signing. This will happen if the Registrar's `new`
    /// function has not been called.
    /// * Other errors may be returned by the keyring if it is unable to generate a key.
    async fn create(&self, services: Option<&[Service]>) -> Result<DidDocument> {
        if services.is_some() {
            tracerr!(
                Err::NotSupported,
                "services are not supported by the JWK method"
            );
        }
        let signing_key = self.keyring.next_key(&KeyOperation::Sign).await?;
        let serialized = serde_json::to_vec(&signing_key)?;
        let encoded = Base64UrlUnpadded::encode_string(&serialized);
        let did = format!("did:{}:{}", Self::method(), encoded);

        let mut doc = DidDocument {
            context: vec![Context {
                url: Some(DID_CONTEXT.to_string()),
                ..Default::default()
            }],
            id: did.clone(),
            ..Default::default()
        };

        let mut vm = VmWithPurpose {
            verification_method: VerificationMethod {
                id: format!("{}#0", did.clone()),
                controller: did.clone(),
                type_: K::key_type().cryptosuite(),
                public_key_jwk: Some(signing_key.clone()),
                ..Default::default()
            },
            purposes: Some(vec![
                KeyPurpose::Authentication,
                KeyPurpose::AssertionMethod,
                KeyPurpose::CapabilityDelegation,
                KeyPurpose::CapabilityInvocation,
            ]),
        };
        if signing_key.use_ != Some("sig".to_string()) {
            if let Some(purposes) = vm.purposes.as_mut() {
                purposes.push(KeyPurpose::KeyAgreement);
            } else {
                vm.purposes = Some(vec![KeyPurpose::KeyAgreement]);
            }
        }
        let patch_key = Patch::builder(Action::AddPublicKeys).public_key(&vm)?.build()?;
        doc.apply_patches(&[patch_key]);

        Ok(doc)
    }

    /// The update operation is not supported for the JWK method.
    async fn update(&self, _: &DidDocument, _: &[Patch]) -> Result<DidDocument> {
        tracerr!(Err::NotSupported)
    }

    /// The deactivate operation is not supported for the JWK method.
    async fn deactivate(&self, _: &str) -> Result<()> {
        tracerr!(Err::NotSupported)
    }

    /// The recover operation is not supported for the JWK method.
    async fn recover(&self, _: &DidDocument) -> Result<()> {
        tracerr!(Err::NotSupported)
    }

    /// The method name for the JWK method.
    fn method() -> String {
        "jwk".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vercre_ephemeral_keyring::{EphemeralKeyRing, Secp256k1KeyPair};

    #[tokio::test]
    async fn create() {
        let keyring = EphemeralKeyRing::<Secp256k1KeyPair>::new();
        let registrar = JwkRegistrar::new(keyring);
        let doc = registrar.create(None).await.unwrap();
        insta::with_settings!( {sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }
}

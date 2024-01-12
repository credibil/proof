use base64ct::{Base64UrlUnpadded, Encoding};
use vercre_didcore::{
    error::Err, tracerr, DidDocument, KeyOperation, KeyRing, Patch, Registrar, Result, Service,
};
use vercre_ephemeral_keyring::KeyPair;

use crate::jwk::{document_from_jwk, Registrar as JwkRegistrar};

/// DID Registrar implementation for the JWK method.
#[allow(async_fn_in_trait)]
impl<'a, K> Registrar for JwkRegistrar<'a, K>
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
        self.keyring.commit().await?;
        let serialized = serde_json::to_vec(&signing_key)?;
        let encoded = Base64UrlUnpadded::encode_string(&serialized);
        let did = format!("did:{}:{}", Self::method(), encoded);

        document_from_jwk(&signing_key, &K::key_type().cryptosuite(), &did)
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
    use vercre_didcore::{KeyOperation, KeyRing, Registrar};
    use vercre_ephemeral_keyring::{EphemeralKeyRing, Secp256k1KeyPair};

    use crate::jwk::Registrar as JwkRegistrar;

    #[tokio::test]
    async fn create_secp256k1() {
        let keyring = EphemeralKeyRing::<Secp256k1KeyPair>::new();
        let registrar = JwkRegistrar::new(&keyring);
        let doc = registrar.create(None).await.unwrap();
        let key = keyring.active_key(&KeyOperation::Sign).await.unwrap();
        // Because every time this is run a new key is generated, we can't test the exact DID so we
        // just check the verification method exists as expected.
        assert!(doc.id.starts_with("did:jwk:"));
        let vm = doc.verification_method.unwrap().clone();
        assert!(vm.len() == 1);
        assert_eq!(vm[0].clone().public_key_jwk.unwrap(), key);
        assert!(vm[0].clone().id.starts_with(&doc.id));

        println!("DID: {}", doc.id);
    }
}

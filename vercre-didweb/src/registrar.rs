use vercre_didcore::{
    error::Err, hash::rand_hex, tracerr, Context, DidDocument, KeyOperation, KeyPurpose, KeyRing,
    Patch, PatchAction, Registrar, Result, Service, Signer, VerificationMethod,
    VerificationMethodPatch, DID_CONTEXT,
};

use crate::web::WebRegistrar;

/// DID Registrar implementation for the Web method.
#[allow(async_fn_in_trait)]
impl<K> Registrar for WebRegistrar<K>
where
    K: KeyRing + Signer + Send + Sync,
{
    /// There is intentionally no HTTP API specified for did:web method operations leaving
    /// programmatic registrations and management to be defined by each implementation, or based on
    /// their own requirements in their web environment.
    ///
    /// This function will construct a DID document for the specified services and create a
    /// verification method for use in authentication and assertion, thus being useful for
    /// verifiable credential issuance.
    ///
    /// The returned document will have no ID, so it is up to the caller to assign one and host it.
    async fn create(&self, services: Option<&[Service]>) -> Result<DidDocument> {
        let signing_key = self.keyring.next_key(KeyOperation::Sign).await?;
        let algorithm = match signing_key.check(self.keyring.supported_algorithms()) {
            Ok(a) => a,
            Err(e) => tracerr!(e, "Signing key error"),
        };

        let mut doc = DidDocument::default();
        doc.context = vec![Context {
            url: Some(DID_CONTEXT.to_string()),
            ..Default::default()
        }];
        let vm = VerificationMethodPatch {
            verification_method: VerificationMethod {
                id: rand_hex(8),
                controller: self.controller.clone().unwrap_or_default(),
                type_: algorithm.cryptosuite().to_string(),
                public_key_jwk: Some(signing_key.clone()),
                public_key_multibase: None,
            },
            purposes: Some(vec![
                KeyPurpose::Authentication,
                KeyPurpose::AssertionMethod,
            ]),
        };
        let patch_key = Patch::builder(PatchAction::AddPublicKeys).public_key(&vm)?.build()?;
        doc.apply_patches(&[patch_key]);

        if let Some(svcs) = services {
            let mut patch_service_builder = Patch::builder(PatchAction::AddServices);
            for s in svcs.iter() {
                patch_service_builder.service(s)?;
            }
            let patch_service = patch_service_builder.build()?;
            doc.apply_patches(&[patch_service]);
        }

        Ok(doc)
    }

    /// Construct a new DID document by applying patches to an existing document.
    async fn update(&self, doc: &DidDocument, patches: &[Patch]) -> Result<DidDocument> {
        let mut new_doc = doc.clone();
        new_doc.apply_patches(patches);
        Ok(new_doc)
    }

    /// This function is not supported for the Web method. Deactivation is done by removing the
    /// document from the hosting environment.
    async fn deactivate(&self, _did: &str) -> Result<()> {
        tracerr!(Err::NotSupported)
    }

    /// This function is not supported for the Web method. Recovery is done by re-hosting a document
    /// that had previously been removed..
    async fn recover(&self, _doc: &DidDocument) -> Result<()> {
        tracerr!(Err::NotSupported)
    }

    /// Declare the DID method for this registrar.
    fn method(&self) -> &str {
        "web"
    }
}

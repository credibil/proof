//! https://identity.foundation/did-registration/

use serde::{Deserialize, Serialize};

use crate::{
    document::{patch::Patch, service::Service, DidDocument},
    Result,
};

/// Type of DID operation.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationType {
    /// Create a new DID.
    #[default]
    Create,
    /// Update an existing DID.
    Update,
    /// Deactivate a DID.
    Deactivate,
    /// Recover a deactivated DID.
    Recover,
}

/// Display implementation for DID operation type.
impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            OperationType::Create => write!(f, "create"),
            OperationType::Update => write!(f, "update"),
            OperationType::Deactivate => write!(f, "deactivate"),
            OperationType::Recover => write!(f, "recover"),
        }
    }
}

/// A registrar is a service that supports the operations of a DID method, including (optionally)
/// anchoring the DID on a public ledger.
#[allow(async_fn_in_trait)]
pub trait Registrar {
    /// Given a DID document construct a DID.
    ///
    /// # Arguments
    ///
    /// * `services` - The services the DID document should contain.
    ///
    /// # Returns
    ///
    /// The DID document. The ID field will contain the DID.
    async fn create(&self, services: Option<&[Service]>) -> Result<DidDocument>;

    /// Construct an updated DID for the document.
    ///
    /// # Arguments
    ///
    /// * `doc` - The original document that needs to have the patches applied. The output document
    /// will reflect the changes, including the ID updated with the new DID.
    /// * `patches` - The patches to be applied to the document.
    ///
    /// # Returns
    ///
    /// The updated DID document.
    ///
    /// # Note
    ///
    /// The implementer is responsible for applying the patches to the document inside this
    /// function. You can use functions in the [document] module for this or construct your own
    /// document according to your implementation requirements.
    async fn update(&self, doc: &DidDocument, patches: &[Patch]) -> Result<DidDocument>;

    /// Deactivate a DID. A deactivated DID is no longer valid and cannot be resolved.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to deactivate.
    async fn deactivate(&self, did: &str) -> Result<()>;

    /// Recover a DID. This may not be relevant for all DID methods so there is a no-op default
    /// implementation. DID recovery means resetting the state of a DID to the supplied document.
    /// Any previous state changes can be lost.
    ///
    /// # Arguments
    ///
    /// * `doc` - The DID document to replace any existing DID state with.
    async fn recover(&self, _doc: &DidDocument) -> Result<()> {
        Ok(())
    }

    /// Declare the DID method for this registrar.
    fn method(&self) -> &str;
}

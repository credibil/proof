use anyhow::Result;
use credibil_did::web::{CreateBuilder, create_did};
use credibil_did::{DocumentBuilder, FromScratch};

use crate::provider::{Proof, Provider};

/// Create a new `did:web` document and save.
///
/// # Errors
///
/// Returns an error if the DID URL is invalid, if the document cannot be
/// built, or saved to the docstore.
pub async fn create(
    url: &str, builder: DocumentBuilder<FromScratch>, provider: &impl Provider,
) -> Result<()> {
    let document = CreateBuilder::new(url).document(builder).build()?;

    // save to docstore
    let did = create_did(url)?;
    Proof::put(provider, &did, &document).await?;

    Ok(())
}

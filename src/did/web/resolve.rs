//! Resolve a DID URL to a DID Document for the `did:web` method.

use crate::{Identity, IdentityResolver, did::{Document, Url}};

impl Url {
    /// Convert a `did:web` URL to an HTTP URL pointing to the location of the
    /// DID document.
    #[must_use]
    pub fn to_web_http(&self) -> String {
        // 1. Replace ":" with "/" in the method specific identifier to obtain the fully
        //    qualified domain name and optional path.
        let domain = self.id.replace(':', "/");

        // 2. If the domain contains a port percent decode the colon.
        let domain = domain.replace("%3A", ":");

        // 3. Generate an HTTPS URL to the expected location of the DID document by
        //    prepending https://.
        let mut url = format!("https://{domain}");

        // 4. If no path has been specified in the URL, append /.well-known.
        if !self.id.contains(':') {
            url = format!("{url}/.well-known");
        }

        // 5. Append /did.json to complete the URL.
        format!("{url}/did.json")
    }
}

/// Convert the structured URL to HTTP format and use the provided resolver to
/// fetch a DID document.
/// 
/// # Errors
/// If the URL cannot be converted to an HTTP format or if the resolver fails an
/// error is returned.
pub async fn resolve(url: &Url, resolver: &impl IdentityResolver) -> anyhow::Result<Document> {
    let http_url = url.to_web_http();
    let id = resolver.resolve(&http_url).await?;
    match id {
        Identity::DidDocument(doc) => Ok(doc),
    }
}

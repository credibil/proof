//! Resolve a DID URL to a DID Document for the `did:web` method.

use crate::Url;

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

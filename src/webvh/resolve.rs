//! # DID Web with Verifiable History Resolver
//!
//! Resolution of a DID for the `did:webvh` method.
//!
//! See: <https://identity.foundation/didwebvh/next/>

use std::sync::LazyLock;

use regex::Regex;
use serde_json::json;

use super::DidLogEntry;
use crate::{
    ContentType, DidResolver, Error, Metadata,
    operation::resolve::{Options, Resolved},
};

static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:webvh:(?<identifier>[a-zA-Z0-9.\\-:\\%]+)$").expect("should compile")
});

/// Resolve a `did:webvh` DID URL to a DID document.
///
/// The first step of the resolution is to retrieve and parse the DID list
/// document. See further functions in this implementation to help with
/// resolution steps.
///
/// # Errors
///
/// Will fail if the DID URL is invalid or the DID list document cannot be
/// found.
pub async fn resolve(
    did: &str, options: Option<Options>, resolver: impl DidResolver,
) -> crate::Result<Resolved> {
    // Steps 1-7. Generate the URL to fetch the DID list document.
    let url = http_url(did, None)?;

    // 8. The content type for the did.jsonl file SHOULD be text/jsonl.
    if let Some(opts) = options {
        if let Some(content_type) = opts.accept {
            if content_type != ContentType::JsonL {
                return Err(Error::RepresentationNotSupported(
                    "Content type must be text/json".to_string(),
                ));
            }
        }
    }

    // Perform an HTTP GET request to the URL using an agent that can
    // successfully negotiate a secure HTTPS connection.
    // The URL
    let document = resolver.resolve(&url).await.map_err(Error::Other)?;

    Ok(Resolved {
        context: "https://w3id.org/did-resolution/v1".into(),
        metadata: Metadata {
            content_type: ContentType::DidLdJson,
            additional: Some(json!({
                "pattern": "^did:webvh:(?<identifier>[a-zA-Z0-9.\\-:\\%]+)$",
                "did": {
                    "didString": did,
                    "methodSpecificId": did[8..],
                    "method": "webvh"
                }
            })),
            ..Metadata::default()
        },
        document: Some(document),
        ..Resolved::default()
    })
}

/// Convert a `did:webvh` URL to an HTTP URL pointing to the location of the
/// DID list document (default) or another location where the root path is
/// a conversion from the DID to an HTTP URL.
///
/// # Errors
///
/// Will fail if the DID URL is invalid.
///
/// <https://identity.foundation/didwebvh/#the-did-to-https-transformation>
///
fn http_url(did: &str, file_path: Option<&str>) -> crate::Result<String> {
    let Some(caps) = DID_REGEX.captures(did) else {
        return Err(Error::InvalidDid("DID is not a valid did:webvh".to_string()));
    };
    // 1. Remove the literal `did:webvh:` prefix from the DID URL.
    let scid_and_fqdn = &caps["identifier"];

    // 2. Remove the `SCID` by removing the text up to and including the
    // first `:` character.
    let Some(fqdn) = scid_and_fqdn.split_once(':').map(|x| x.1) else {
        return Err(Error::InvalidDid("DID is not a valid did:webvh - no SCID".to_string()));
    };

    // 3. Replace `:` with `/` in the domain part of the identifier to obtain
    // the fully qualified domain name and optional path.
    let mut domain = fqdn.replace(':', "/");

    // 4. If there is no optional path, append `/.well-known` to the URL.
    if !fqdn.contains(':') {
        domain.push_str("/.well-known");
    }

    // 5. If the domain contains a port, percent-decode the colon.
    let domain = domain.replace("%3A", ":");

    // 6. Prepend `https://` to the domain to generate the URL.
    let url = format!("https://{domain}");

    // 7. Append `/did.jsonl` (default) or the specified file sub-path to
    // the URL to complete it.
    let fp = file_path.unwrap_or("/did.jsonl");
    let url = format!("{url}{fp}");

    Ok(url)
}

/// Primary verification of the contents of the `did.jsonl` file.
///
/// To use this function, read the contents of the `did.jsonl` file into a
/// vector of `DidLogEntry` structs and pass to this function.
///
/// # Errors
///
/// Will fail if the log entries are invalid.
///
pub fn verify_log(_log: Vec<DidLogEntry>) -> crate::Result<()> {
    todo!()
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use insta::assert_json_snapshot as assert_snapshot;

    use crate::{Document, dereference};

    use super::*;

    #[derive(Clone)]
    struct MockResolver;
    impl DidResolver for MockResolver {
        async fn resolve(&self, _url: &str) -> anyhow::Result<Document> {
            serde_json::from_slice(include_bytes!("./did-v3.json"))
                .map_err(|e| anyhow!("issue deserializing document: {e}"))
        }
    }

    #[tokio::test]
    async fn deref_webvh() {
        const DID_URL: &str = "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv";

        let dereferenced =
            dereference(DID_URL, None, MockResolver).await.expect("should dereference");
        assert_snapshot!("deref_webvh", dereferenced);
    }

    #[test]
    fn should_construct_default_url() {
        let did =
            "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:domain.with-hyphens.computer";
        let url = http_url(did, None).unwrap();
        assert_eq!(url, "https://domain.with-hyphens.computer/.well-known/did.jsonl");
    }

    #[test]
    fn should_construct_path_url() {
        let did = "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:domain.with-hyphens.computer:dids:issuer";
        let url = http_url(did, None).unwrap();
        assert_eq!(url, "https://domain.with-hyphens.computer/dids/issuer/did.jsonl");
    }

    #[test]
    fn should_construct_port_url() {
        let did = "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:domain.with-hyphens.computer%3A8080";
        let url = http_url(did, None).unwrap();
        assert_eq!(url, "https://domain.with-hyphens.computer:8080/.well-known/did.jsonl");
    }
}

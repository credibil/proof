//! # DID Web with Verifiable History Resolver
//!
//! Resolution of a DID for the `did:webvh` method.
//!
//! See: <https://identity.foundation/didwebvh/next/>

use std::{sync::LazyLock, vec};

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use multibase::Base;
use regex::Regex;
use serde_json::json;

use super::{
    DidLogEntry, WitnessEntry,
    verify::{verify_proofs, verify_witness},
};
use crate::operation::resolve::{ContentType, Metadata, Options, Parameters, Resolved};
use crate::{DidResolver, Document, Error, webvh::SCID_PLACEHOLDER};

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
    // Generate the URL to fetch the DID list document.
    let url = http_url(did, None)?;

    // The content type for the did.jsonl file SHOULD be text/jsonl.
    if let Some(opts) = options {
        if let Some(content_type) = opts.accept {
            match content_type {
                ContentType::JsonL => {}
                ContentType::DidLdJson => {
                    return Err(Error::RepresentationNotSupported(
                        "Content type must be text/json".to_string(),
                    ));
                }
            }
        }
    }

    // Perform an HTTP GET request to the URL for the DID log document. The
    // client can use helper methods to unpack the `JSONL` file and extract the
    // DID document.
    // TODO: The resolver needs to honour the content type.
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
pub async fn resolve_log(
    log: &[DidLogEntry], witnesses: Option<&[WitnessEntry]>, parameters: Option<Parameters>,
    resolver: &impl DidResolver,
) -> crate::Result<Document> {
    let mut prev_index = 0;
    let mut prev_version = SCID_PLACEHOLDER.to_string();
    let mut prev_time = DateTime::<Utc>::MIN_UTC;
    let mut doc = Document::default();
    let mut prev_next_key_hashes: Option<Vec<String>> = None;
    for i in 0..log.len() {
        // 1. Update current parameters with parameters from the entry being
        // processed.

        // 2. Verify controller proofs.
        if let Err(error) = verify_proofs(&log[i], resolver).await {
            return Err(Error::Other(error));
        }

        // 3.1. Verify the version number is incremented by one for each entry.
        // 3.2. Verify the version number and entry hash is separated by `-`.
        let version_parts = log[i].version_id.split('-').collect::<Vec<&str>>();
        if version_parts.len() != 2 {
            return Err(Error::Other(anyhow!("log entry version id has an unexpected format")));
        }
        let index = version_parts[0].parse::<u64>().map_err(|e| Error::Other(e.into()))?;
        if index != prev_index + 1 {
            return Err(Error::Other(anyhow!("log entries are not sequential")));
        }

        // 3.3. Verify the entry hash.
        log[i].verify_hash(&prev_version).map_err(Error::Other)?;

        // 4. The version time must be in the past and monotonically increasing.
        if log[i].version_time > Utc::now() {
            return Err(Error::Other(anyhow!("log entry time is in the future")));
        }
        if log[i].version_time <= prev_time {
            return Err(Error::Other(anyhow!("log entry times are not monotonically increasing")));
        }

        // 5. If the entry is the first one, verify the SCID.
        if i == 0 {
            let mut initial_log_entry = log[i].clone();
            initial_log_entry.version_id = SCID_PLACEHOLDER.to_string();
            initial_log_entry.proof = vec![];
            let hash = initial_log_entry.hash().map_err(Error::Other)?;
            if hash != log[i].parameters.scid {
                return Err(Error::Other(anyhow!(
                    "first log entry SCID does not match calculated hash"
                )));
            }
        }

        // 6. Record the state as the document to return (if everything else is
        // successful).
        doc = log[i].state.clone();

        // 7. If key pre-rotation is enabled, check the update keys match the
        // previous entry's next-key hashes.
        if let Some(next_key_hashes) = &prev_next_key_hashes {
            for key in &log[i].parameters.update_keys {
                let key_hash = multibase::encode(Base::Base58Btc, key.as_bytes());
                if !next_key_hashes.contains(&key_hash) {
                    return Err(Error::Other(anyhow!(
                        "update key not found in pre-rotation hashes"
                    )));
                }
            }
        }

        // 8. Increment.
        prev_index = index;
        prev_version.clone_from(&log[i].version_id);
        prev_time.clone_from(&log[i].version_time);
        prev_next_key_hashes.clone_from(&log[i].parameters.next_key_hashes);

        // 9. Check witness proofs.
        if log[i].parameters.witness.is_some() {
            if let Some(witness_entries) = witnesses {
                if let Err(error) = verify_witness(&log[i], witness_entries, resolver).await {
                    return Err(Error::Other(error));
                }
            } else {
                return Err(Error::Other(anyhow!(
                    "witness proofs must be provided for a log entry with witnesses"
                )));
            }
        }

        // Check for explicit version ID or version time request. (Otherwise
        // the latest version is returned.)
        if let Some(params) = &parameters {
            if let Some(version_id) = &params.version_id {
                if *version_id == log[i].version_id {
                    break;
                }
            }
            if let Some(version_time) = &params.version_time {
                let version_time =
                    version_time.parse::<DateTime<Utc>>().map_err(|e| Error::Other(e.into()))?;
                if version_time >= log[i].version_time {
                    if i < log.len() - 1 {
                        if version_time <= log[i + 1].version_time {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use insta::assert_json_snapshot as assert_snapshot;

    use crate::{Document, operation::resolve::dereference};

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

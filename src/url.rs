//! Destructure DID URLs into strongly typed components.
//!
//! A DID URL is of the form
//!
//! `did:<method>:<method-specific-id>[/<path>][?<query>][#<fragment>]`.

use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

use super::Method;
use crate::error::Error;

/// Structure of a DID URL.
#[derive(Clone, Debug)]
pub struct Url {
    /// DID method.
    ///
    /// Specification calls for a string. In our case this must be a method
    /// supported by this crate so we map to an enum.
    pub method: Method,

    /// Method-specific ID.
    ///
    /// This may include any information that is needed by a DID method to
    /// address a specific DID document.
    pub id: String,

    /// Path.
    ///
    /// If present, a DID path is identical to a generic URI path. It is up to
    /// the method to define how to interpret the path in order to resolve a
    /// specific DID document.
    pub path: Option<Vec<String>>,

    /// Query.
    ///
    /// If present, the query parameters refine the resolution of the specific
    /// instance (eg. version) of a DID document or other resource defined by a
    /// DID document (for example, a service endpoint).
    pub query: Option<QueryParams>,

    /// Fragment.
    ///
    /// If present, the fragment is a string that corresponds to a specific
    /// resource identifier within a DID document. Typically a serice or a
    /// verification method.
    pub fragment: Option<String>,
}

impl Display for Url {
    /// Format the URL as a specification-compliant string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)?;
        if let Some(path) = &self.path {
            write!(f, "/{}", path.join("/"))?;
        }
        if let Some(query) = &self.query {
            write!(f, "?")?;
            let mut first = true;
            if let Some(service) = &query.service {
                write!(f, "service={service}")?;
                first = false;
            }
            if let Some(relative_ref) = &query.relative_ref {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "relativeRef={relative_ref}")?;
                first = false;
            }
            if let Some(version_id) = &query.version_id {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "versionId={version_id}")?;
                first = false;
            }
            if let Some(version_time) = &query.version_time {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "versionTime={version_time}")?;
                first = false;
            }
            if let Some(hashlink) = &query.hashlink {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "hl={hashlink}")?;
            }
        }
        if let Some(fragment) = &self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

impl FromStr for Url {
    type Err = super::Error;

    /// Parse a string if possible into a strongly typed DID URL struct.
    ///
    /// Expecting a format:
    /// `did:<method>:<method-specific-id>[/<path>][?<query>][#<fragment>]`.
    ///
    /// # Errors:
    /// If the string is not a valid format or portions of the string cannot be
    /// de-serialized into the expected types, an error is returned.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.splitn(3, ':').collect::<Vec<_>>();
        println!("parts: {parts:?}");
        if parts.len() < 3 {
            return Err(super::Error::InvalidDidUrl(s.to_string()));
        }
        if parts[0] != "did" {
            return Err(super::Error::InvalidDidUrl(format!("{s} does not start with 'did'")));
        }
        let method = Method::from_str(parts[1])?;

        // Get some help from standard URL parsing by converting the DID URL to
        // an HTTP one.
        let fake_url = format!("https://{}", parts[2]);
        let url = url::Url::parse(&fake_url)
            .map_err(|e| Error::InvalidDidUrl(format!("issue parsing URL: {e}")))?;
        let id = url
            .host_str()
            .ok_or_else(|| Error::InvalidDidUrl(format!("missing method-specific id: {s}")))?;
        let id = id.to_string();
        let mut path: Option<Vec<&str>> = url.path_segments().map(std::iter::Iterator::collect);
        if let Some(p) = &path {
            if p.is_empty() {
                path = None;
            } else if p.len() == 1 {
                if p[0].is_empty() {
                    path = None;
                }
            }
            else {
                path = Some(p.clone());
            }
        }
        let path: Option<Vec<String>> =
            path.map(|p| p.into_iter().map(std::string::ToString::to_string).collect());

        let query = match url.query() {
            Some(q) => {
                match serde_querystring::from_str::<QueryParams>(
                    q,
                    serde_querystring::ParseMode::UrlEncoded,
                ) {
                    Ok(qp) => Some(qp),
                    Err(e) => {
                        return Err(Error::InvalidDidUrl(format!("issue parsing query: {e}")));
                    }
                }
            }
            None => None,
        };
        let fragment = url.fragment().map(std::string::ToString::to_string);

        Ok(Self {
            method,
            id,
            path,
            query,
            fragment,
        })
    }
}

impl Url {
    /// Get the internal resource identifier from the DID URL.
    ///
    /// This is in the form of `did:<method>:<method-specific-id>#<fragment>`
    /// and is used to dereference a service or verification method that is
    /// internal to the DID document.
    ///
    /// Note this is unreliable as an ID if there is no fragment on the URL.
    #[must_use]
    pub fn resource_id(&self) -> String {
        let mut id = format!("did:{}:{}", self.method, self.id);
        if let Some(ref fragment) = self.fragment {
            id.push_str(&format!("#{fragment}"));
        }
        id
    }

    /// Get the DID part of the URL.
    /// 
    /// This is in the form of `did:<method>:<method-specific-id>`.
    #[must_use]
    pub fn did(&self) -> String {
        format!("did:{}:{}", self.method, self.id)
    }
}

/// The DID URL syntax supports parameters in the URL query component. Adding a
/// DID parameter to a DID URL means the parameter becomes part of the
/// identifier for a resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QueryParams {
    /// Identifies a service from the DID document by service's ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// A relative URI reference that identifies a resource at a service
    /// endpoint, which is selected from a DID document by using the service
    /// parameter. MUST use URL encoding if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "relative-ref")]
    pub relative_ref: Option<String>,

    /// Identifies a specific version of a DID document to be resolved (the
    /// version ID could be sequential, or a UUID, or method-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,

    /// Identifies a version timestamp of a DID document to be resolved. That
    /// is, the DID document that was valid for a DID at a certain time.
    /// An XML datetime value [XMLSCHEMA11-2] normalized to UTC 00:00:00 without
    /// sub-second decimal precision. For example: 2020-12-20T19:17:47Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<String>,

    /// A resource hash of the DID document to add integrity protection, as
    /// specified in [HASHLINK]. This parameter is non-normative.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hl")]
    pub hashlink: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_url() {
        let url = Url::from_str("did:key:123456789abcdefghi#key-1").unwrap();
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(url.path, None);
        assert_eq!(url.query, None);
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(url.to_string(), "did:key:123456789abcdefghi#key-1");
    }

    #[test]
    fn url_with_path() {
        let url = Url::from_str("did:key:123456789abcdefghi/path/to/resource#key-1").unwrap();
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(url.path, Some(vec!["path".to_string(), "to".to_string(), "resource".to_string()]));
        assert_eq!(url.query, None);
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(url.to_string(), "did:key:123456789abcdefghi/path/to/resource#key-1");
    }

    #[test]
    fn url_with_query() {
        let url = Url::from_str("did:key:123456789abcdefghi?service=example#key-1").unwrap();
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(url.path, None);
        assert_eq!(url.query, Some(QueryParams { service: Some("example".to_string()), ..Default::default() }));
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(url.to_string(), "did:key:123456789abcdefghi?service=example#key-1");
    }

    #[test]
    fn url_with_the_works() {
        let url = Url::from_str("did:key:123456789abcdefghi/path/to/resource?service=example&hl=hashlink#key-1").unwrap();
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(url.path, Some(vec!["path".to_string(), "to".to_string(), "resource".to_string()]));
        assert_eq!(url.query, Some(QueryParams { service: Some("example".to_string()), hashlink: Some("hashlink".to_string()), ..Default::default() }));
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(url.to_string(), "did:key:123456789abcdefghi/path/to/resource?service=example&hl=hashlink#key-1");
    }
}

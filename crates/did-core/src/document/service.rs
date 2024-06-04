//! Services are used to express ways of communicating with the DID subject or associated entities.
//! Can be any type of service the DID subject wants to advertise, including decentralized identity
//! management services for further discovery, authentication, authorization, or interaction.

use std::collections::HashMap;
use std::convert::Infallible;
use std::str::FromStr;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

use crate::error::Err;
use crate::serde::flexvec_or_single;
use crate::{tracerr, Result};

/// Service description.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Service {
    /// Identifier for the service. Should be unique for services within the DID document.
    pub id: String,
    /// The type of service.
    #[serde(rename = "type")]
    #[serde(with = "flexvec_or_single")]
    pub type_: Vec<String>,
    /// Location(s) of the service.
    #[serde(with = "endpoint_serialization")]
    pub service_endpoint: Vec<Endpoint>,
}

/// A service endpoint can be a string, a map or a set composed of one or more strings and/or maps.
/// All string values must be valid URIs.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Endpoint {
    /// Location of the service endpoint, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Map of endpoint names to locations, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_map: Option<HashMap<String, Vec<String>>>,
}

/// Required by serde to deserialise a service endpoint using [`crate::serde::flexvec`].
impl FromStr for Endpoint {
    type Err = Infallible;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            url: Some(url.to_string()),
            url_map: None,
        })
    }
}

/// Serialize a service endpoint to a string or map. If only the `url` field is set, serialize to a
/// string, otherwise serialize to a map.
impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match (&self.url, &self.url_map) {
            (Some(url), None) => serializer.serialize_str(url),
            (None, Some(map)) => {
                let mut m = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
            _ => Err(serde::ser::Error::custom("Service endpoint must be a string or map")),
        }
    }
}

/// Check the services in a set conform to format constraints.
///
/// # Errors
///
/// - [`Err::InvalidInput`] if a service ID is duplicated
/// - [`Err::InvalidFormat`] if a service type exceeds the limit of 30 characters
/// - URL parsing error if a service endpoint is not a valid URL
pub fn check_services(services: &[Service]) -> Result<()> {
    let mut map = HashMap::new();
    for s in services {
        // Check duplicate
        if map.contains_key(&s.id) {
            tracerr!(Err::InvalidInput, "Duplicate service ID: {}", s.id);
        }
        map.insert(s.id.clone(), true);

        // Check length
        if s.type_.len() > 30 {
            tracerr!(Err::InvalidFormat, "Service type exceeds limit of 30: {}", s.type_.len());
        }

        // Check all endpoint representations are valid URLs
        for ep in &s.service_endpoint {
            if let Some(url) = &ep.url {
                let _ = url::Url::parse(url)?;
            }
            if let Some(map) = &ep.url_map {
                for v in map.values() {
                    for url in v {
                        let _ = url::Url::parse(url)?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) mod endpoint_serialization {
    use std::collections::HashMap;
    use std::fmt;
    use std::marker::PhantomData;
    use std::str::FromStr;

    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    use serde::ser::{SerializeSeq, Serializer};

    use super::{Endpoint, Result};

    pub(crate) fn serialize<S>(value: &[Endpoint], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.len() == 1 {
            serializer.serialize_some(&value[0])
        } else {
            let mut seq = serializer.serialize_seq(Some(value.len()))?;
            for e in value {
                seq.serialize_element(e)?;
            }
            seq.end()
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Endpoint>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct StringOrMap<T>(PhantomData<fn() -> Vec<T>>);

        impl<'de> Visitor<'de> for StringOrMap<Vec<Endpoint>> {
            type Value = Vec<Endpoint>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "ServiceEndpoint as a single string or map or a set of strings and/or maps",
                )
            }

            // If a string is found, deserialize it to a single entry Vec<ServiceEndpoint> using
            // ServiceEndpoint::from_str
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match Endpoint::from_str(value) {
                    Ok(res) => Ok(vec![res]),
                    Err(_) => Err(de::Error::invalid_type(de::Unexpected::Str(value), &self)),
                }
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut deser: HashMap<String, Vec<String>> = HashMap::new();
                while let Some((k, v)) = access.next_entry::<String, serde_json::Value>()? {
                    match v {
                        serde_json::Value::String(s) => {
                            deser.insert(k, vec![s]);
                        }
                        serde_json::Value::Array(a) => {
                            let mut vec: Vec<String> = Vec::new();
                            for e in a {
                                match e {
                                    serde_json::Value::String(s) => {
                                        vec.push(s);
                                    }
                                    _ => {
                                        return Err(de::Error::invalid_type(
                                            de::Unexpected::Map,
                                            &self,
                                        ));
                                    }
                                }
                            }
                            deser.insert(k, vec);
                        }
                        _ => {
                            return Err(de::Error::invalid_type(de::Unexpected::Map, &self));
                        }
                    }
                }

                Ok(vec![Endpoint {
                    url: None,
                    url_map: Some(deser),
                }])
            }

            // Deserialize a sequence to Vec<Context>
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // could be mixed array of strings and objects
                let mut deser: Vec<Endpoint> = Vec::new();
                while let Some(curr) = seq.next_element::<serde_json::Value>()? {
                    match curr {
                        serde_json::Value::String(s) => {
                            let Ok(res) = Endpoint::from_str(&s) else {
                                return Err(de::Error::invalid_type(
                                    de::Unexpected::Str(&s),
                                    &self,
                                ));
                            };
                            deser.push(res);
                        }
                        serde_json::Value::Object(o) => {
                            // Try to deserialize as a map of strings
                            let map_of_vecs = match serde_json::from_value::<HashMap<String, String>>(
                                serde_json::Value::Object(o.clone()),
                            ) {
                                Ok(res) => {
                                    // Convert to map of strings to map of vec of strings
                                    let mut map: HashMap<String, Vec<String>> = HashMap::new();
                                    for (k, v) in res {
                                        map.insert(k, vec![v]);
                                    }
                                    map
                                }
                                Err(_) => {
                                    // Try again with a map of vec of strings directly
                                    match serde_json::from_value::<HashMap<String, Vec<String>>>(
                                        serde_json::Value::Object(o.clone()),
                                    ) {
                                        Ok(res) => res,
                                        Err(_) => {
                                            return Err(de::Error::invalid_type(
                                                de::Unexpected::Map,
                                                &self,
                                            ));
                                        }
                                    }
                                }
                            };
                            let se = Endpoint {
                                url: None,
                                url_map: Some(map_of_vecs),
                            };
                            deser.push(se);
                        }
                        _ => {
                            return Err(de::Error::custom(
                                "invalid type: cannot deserialize array element",
                            ));
                        }
                    }
                }
                Ok(deser)
            }
        }

        deserializer.deserialize_any(StringOrMap(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use olpc_cjson::CanonicalFormatter;

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Doc {
        pub service: Vec<Service>,
    }

    #[test]
    fn deserialize_single_string() {
        let input = r#"{
            "service": [
                {
                    "id": "did:example:123456789abcdefghi#openid",
                    "type": ["OpenIdConnectVersion1.0Service"],
                    "serviceEndpoint": "https://openid.example.com/"
                }
            ]
        }"#;
        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!( {sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn deserialize_single_map() {
        let input = r#"{
            "service": [
                {
                    "id": "did:example:123456789abcdefghi#openid",
                    "type": [ "OpenIdConnectVersion1.0Service" ],
                    "serviceEndpoint": { "origin": "https://openid.example.com/" }
                }
            ]
        }"#;
        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!( {sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn deserialize_strings() {
        let input = r#"{
            "service": [
                {
                    "id": "did:example:123456789abcdefghi#openid",
                    "type": ["OpenIdConnectVersion1.0Service"],
                    "serviceEndpoint": ["https://openid.example.com/", "https://auth.example.com/"]
                }
            ]
        }"#;
        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!( {sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn deserialize_maps() {
        let input = r#"{
            "service": [
                {
                    "id": "did:example:123456789abcdefghi#openid",
                    "type": ["OpenIdConnectVersion1.0Service"],
                    "serviceEndpoint": [
                        { "origin": "https://openid.example.com/" },
                        { "alt": ["https://auth.example.com/"] }
                    ]
                }
            ]
        }"#;
        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!( {sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn deserialize_mix() {
        let input = r#"{
            "service": [
                {
                    "id": "did:example:123456789abcdefghi#openid",
                    "type": ["OpenIdConnectVersion1.0Service"],
                    "serviceEndpoint": [
                        "https://openid.example.com/",
                        { "alt": ["https://auth.example.com/"], "origin": ["https://openid.example.com/"] }
                    ]
                }
            ]
        }"#;
        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!( {sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn serialize_single_string() {
        let doc = Doc {
            service: vec![Service {
                id: "did:example:123456789abcdefghi#openid".to_string(),
                type_: vec!["OpenIdConnectVersion1.0Service".to_string()],
                service_endpoint: vec![Endpoint {
                    url: Some("https://openid.example.com/".to_string()),
                    url_map: None,
                }],
            }],
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let json = String::from_utf8(buf).expect("failed to convert bytes to string");
        assert_eq!(
            json,
            r#"{"service":[{"id":"did:example:123456789abcdefghi#openid","serviceEndpoint":"https://openid.example.com/","type":"OpenIdConnectVersion1.0Service"}]}"#
        );
    }

    #[test]
    fn serialize_single_map() {
        let doc = Doc {
            service: vec![Service {
                id: "did:example:123456789abcdefghi#openid".to_string(),
                type_: vec!["OpenIdConnectVersion1.0Service".to_string()],
                service_endpoint: vec![Endpoint {
                    url: None,
                    url_map: Some(HashMap::from([(
                        "origin".to_string(),
                        vec!["https://openid.example.com/".to_string()],
                    )])),
                }],
            }],
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let json = String::from_utf8(buf).expect("failed to convert bytes to string");
        assert_eq!(
            json,
            r#"{"service":[{"id":"did:example:123456789abcdefghi#openid","serviceEndpoint":{"origin":["https://openid.example.com/"]},"type":"OpenIdConnectVersion1.0Service"}]}"#
        );
    }

    #[test]
    fn serialize_mix() {
        let doc = Doc {
            service: vec![Service {
                id: "did:example:123456789abcdefghi#openid".to_string(),
                type_: vec!["OpenIdConnectVersion1.0Service".to_string()],
                service_endpoint: vec![
                    Endpoint {
                        url: Some("https://openid.example.com/".to_string()),
                        url_map: None,
                    },
                    Endpoint {
                        url: None,
                        url_map: Some(HashMap::from([(
                            "alt".to_string(),
                            vec!["https://auth.example.com/".to_string()],
                        )])),
                    },
                ],
            }],
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let json = String::from_utf8(buf).expect("failed to convert bytes to string");
        assert_eq!(
            json,
            r#"{"service":[{"id":"did:example:123456789abcdefghi#openid","serviceEndpoint":["https://openid.example.com/",{"alt":["https://auth.example.com/"]}],"type":"OpenIdConnectVersion1.0Service"}]}"#
        );
    }
}

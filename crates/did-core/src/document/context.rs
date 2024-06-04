//! Context is a JSON-LD context that describes a DID Document schema.

use std::collections::HashMap;
use std::convert::Infallible;
use std::str::FromStr;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

/// The default context for a DID document. <https://www.w3.org/TR/did-core/#context>
pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// Context uses JSON-LD, a JSON-based format used to serialize Linked Data. This section defines
/// the production and consumption rules for the JSON-LD representation.
///
/// The JSON-LD representation defines the following representation-specific entries:
///
/// @context
/// The JSON-LD Context is either a string or a list containing any combination of strings and/or
/// ordered maps.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Context {
    /// A single JSON-LD term.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A map of JSON-LD terms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_map: Option<HashMap<String, String>>,
}

/// `FromStr` implementation for `Context`. Needed for deserializer.
impl FromStr for Context {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            url: Some(s.to_string()),
            url_map: None,
        })
    }
}

/// Serialize a context to a string or map. If only the `term` field is set, serialize to a string,
/// otherwise serialize to a map.
impl Serialize for Context {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match (&self.url, &self.url_map) {
            (Some(u), None) => serializer.serialize_str(u),
            (None, Some(map)) => {
                let mut m = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
            _ => Err(serde::ser::Error::custom("Context must be a string or map")),
        }
    }
}

pub(crate) mod context_serialization {
    use std::collections::HashMap;
    use std::fmt;
    use std::marker::PhantomData;
    use std::str::FromStr;

    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::{SerializeSeq, Serializer};

    use super::Context;

    pub(crate) fn serialize<S>(value: &[Context], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.len() == 1 && value[0].url.is_some() && value[0].url_map.is_none() {
            serializer.serialize_some(&value[0])
        } else {
            let mut seq = serializer.serialize_seq(Some(value.len()))?;
            for e in value {
                seq.serialize_element(e)?;
            }
            seq.end()
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Context>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct StringOrMap<T>(PhantomData<fn() -> Vec<T>>);

        impl<'de> Visitor<'de> for StringOrMap<Vec<Context>> {
            type Value = Vec<Context>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Context as a single string or a set of strings and/or maps")
            }

            // If a string is found, deserialize it to a single entry Vec<Context> using Context::from_str
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match Context::from_str(value) {
                    Ok(res) => Ok(vec![res]),
                    Err(_) => Err(de::Error::invalid_type(de::Unexpected::Str(value), &self)),
                }
            }

            // Deserialize a sequence to Vec<Context>
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // could be mixed array of strings and objects
                let mut deser: Vec<Context> = Vec::new();
                while let Some(curr) = seq.next_element::<serde_json::Value>()? {
                    match curr {
                        serde_json::Value::String(s) => {
                            let Ok(res) = Context::from_str(&s) else {
                                return Err(de::Error::invalid_type(
                                    de::Unexpected::Str(&s),
                                    &self,
                                ));
                            };
                            deser.push(res);
                        }
                        serde_json::Value::Object(o) => {
                            let Ok(res) = serde_json::from_value::<HashMap<String, String>>(
                                serde_json::Value::Object(o),
                            ) else {
                                return Err(de::Error::invalid_type(de::Unexpected::Map, &self));
                            };
                            let ctx = Context {
                                url: None,
                                url_map: Some(res),
                            };
                            deser.push(ctx);
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
        #[serde(with = "context_serialization", rename = "@context")]
        pub context: Vec<Context>,
    }

    #[test]
    fn deserialize_single() {
        let input = r#"{
            "@context": "https://www.w3.org/ns/did/v1"
        }"#;

        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!({sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn deserialize_strings() {
        let input = r#"{
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ]
        }"#;

        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!({sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn deserialize_maps() {
        let input = r#"{
            "@context": [
                { "@base": "https://example.com/keys/" }
            ]
        }"#;

        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!({sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        });
    }

    #[test]
    fn deserialize_mix() {
        let input = r#"{
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                { "@base": "https://example.com/keys/" }
            ]
        }"#;
        let doc: Doc = serde_json::from_str(input).expect("failed to deserialize");
        insta::with_settings!({sort_maps => true}, {
            insta::assert_yaml_snapshot!(doc);
        })
    }

    #[test]
    fn serialize_single() {
        let doc = Doc {
            context: vec![Context {
                url: Some("https://www.w3.org/ns/did/v1".to_string()),
                url_map: None,
            }],
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let json = String::from_utf8(buf).expect("failed to convert bytes to string");
        assert_eq!(json, r#"{"@context":"https://www.w3.org/ns/did/v1"}"#);
    }

    #[test]
    fn serialize_maps() {
        let doc = Doc {
            context: vec![Context {
                url: None,
                url_map: Some(
                    vec![("@base".to_string(), "https://example.com/keys/".to_string())]
                        .into_iter()
                        .collect(),
                ),
            }],
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let json = String::from_utf8(buf).expect("failed to convert bytes to string");
        assert_eq!(json, r#"{"@context":[{"@base":"https://example.com/keys/"}]}"#);
    }

    #[test]
    fn serialize_mix() {
        let doc = Doc {
            context: vec![
                Context {
                    url: Some("https://www.w3.org/ns/did/v1".to_string()),
                    url_map: None,
                },
                Context {
                    url: Some("https://w3id.org/security/suites/jws-2020/v1".to_string()),
                    url_map: None,
                },
                Context {
                    url: None,
                    url_map: Some(
                        vec![
                            ("@base".to_string(), "https://example.com/keys/".to_string()),
                            ("other".to_string(), "value".to_string()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                },
                Context {
                    url: None,
                    url_map: Some(HashMap::from([(
                        "api".to_string(),
                        "https://example.com/api/".to_string(),
                    )])),
                },
            ],
        };
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        doc.serialize(&mut ser).expect("failed to serialize");
        let json = String::from_utf8(buf).expect("failed to convert bytes to string");
        assert_eq!(
            json,
            r#"{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1",{"@base":"https://example.com/keys/","other":"value"},{"api":"https://example.com/api/"}]}"#
        );
    }
}

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de;
use serde::de::{DeserializeOwned, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};

pub fn serialize<T, S>(value: &Option<Vec<T>>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    // serialize None as empty array
    if value.is_none() {
        return serializer.serialize_none();
    }

    let some_val = value.as_ref().expect("expected value but got none");

    let mut seq = serializer.serialize_seq(Some(some_val.len()))?;
    for e in some_val {
        seq.serialize_element(e)?;
    }
    seq.end()
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    T: DeserializeOwned + FromStr,
    D: Deserializer<'de>,
{
    struct VisitorImpl<T>(PhantomData<fn() -> Vec<T>>);

    impl<'de, T> Visitor<'de> for VisitorImpl<T>
    where
        T: DeserializeOwned + FromStr,
    {
        type Value = Option<Vec<T>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("Option<Vec<<T>>")
        }

        // deserialize array to Vec<T>
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // could be mixed array of strings and objects
            let mut deser: Vec<T> = Vec::new();
            while let Some(curr) = seq.next_element::<serde_json::Value>()? {
                match curr {
                    serde_json::Value::String(s) => {
                        let Ok(res) = T::from_str(&s) else {
                            return Err(de::Error::invalid_type(de::Unexpected::Str(&s), &self));
                        };
                        deser.push(res);
                    }
                    serde_json::Value::Object(o) => {
                        let Ok(res) = serde_json::from_value::<T>(serde_json::Value::Object(o))
                        else {
                            return Err(de::Error::invalid_type(de::Unexpected::Map, &self));
                        };
                        deser.push(res);
                    }
                    _ => {
                        return Err(de::Error::custom(
                            "invalid type: cannot deserialize array element",
                        ));
                    }
                }
            }
            Ok(Some(deser))
        }
    }

    deserializer.deserialize_any(VisitorImpl(PhantomData))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::anyhow;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use crate::serde::option_flexvec;

    #[derive(Clone, Debug, Default, Deserialize, Serialize)]
    #[serde(default)]
    struct TestData {
        #[serde(with = "option_flexvec")]
        object_array: Option<Vec<Nested>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "option_flexvec")]
        array: Option<Vec<String>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "option_flexvec")]
        none: Option<Vec<String>>,
    }

    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
    struct Nested {
        n: String,
    }

    impl FromStr for Nested {
        type Err = anyhow::Error;

        fn from_str(_: &str) -> Result<Self, Self::Err> {
            Err(anyhow!("unimplemented"))
        }
    }

    #[test]
    fn option_flexvec() {
        let test_data = TestData {
            object_array: Some(vec![
                Nested {
                    n: "object1".to_string(),
                },
                Nested {
                    n: "object2".to_string(),
                },
            ]),
            array: Some(vec!["item1".to_string(), "item2".to_string()]),
            none: Default::default(),
        };

        // serialize
        let test_json = serde_json::to_value(&test_data).expect("failed to serialize");
        assert_eq!(
            *test_json.get("object_array").expect("expected value but got none"),
            json!([{"n": "object1"}, {"n": "object2"}])
        );
        assert_eq!(
            *test_json.get("array").expect("expected value but got none"),
            json!(["item1", "item2"]),
        );
        assert_eq!(test_json.get("none"), None);

        // deserialize
        let test_de: TestData = serde_json::from_value(test_json).expect("failed to deserialize");
        assert_eq!(test_de.object_array, test_data.object_array);
        assert_eq!(test_de.array, test_data.array);
        assert_eq!(test_de.none, test_data.none);
    }
}

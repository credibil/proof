//! # Core

use serde::{Deserialize, Serialize};

/// `Kind` allows serde to serialize/deserialize a string or an object.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kind<T> {
    /// Simple string value
    String(String),

    /// Complex object value
    Object(T),
}

impl<T: Default> Default for Kind<T> {
    fn default() -> Self {
        Self::String(String::new())
    }
}

impl<T: Default> Kind<T> {
    /// Returns `true` if the `OneMany` is a single object.
    pub const fn is_string(&self) -> bool {
        match self {
            Self::String(_) => true,
            Self::Object(_) => false,
        }
    }

    /// Returns `true` if the `OneMany` contains an array of objects.
    pub const fn is_object(&self) -> bool {
        match self {
            Self::String(_) => false,
            Self::Object(_) => true,
        }
    }
}

impl<T> From<String> for Kind<T> {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

// impl<T> From<T> for Kind<T> {
//     fn from(value: T) -> Self {
//         Self::Object(value)
//     }
// }

/// `OneMany` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneMany<T> {
    /// Single object
    One(T),

    /// Set of objects
    Many(Vec<T>),
}

impl<T: Default> Default for OneMany<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

impl<T: Clone + Default + PartialEq> OneMany<T> {
    /// Returns `true` if the `OneMany` is a single object.
    pub const fn is_one(&self) -> bool {
        match self {
            Self::One(_) => true,
            Self::Many(_) => false,
        }
    }

    /// Returns `true` if the `OneMany` contains an array of objects.
    pub const fn is_many(&self) -> bool {
        match self {
            Self::One(_) => false,
            Self::Many(_) => true,
        }
    }

    /// Adds an object to the `OneMany`. If the `OneMany` is a single object, it is
    /// converted to a set of objects.
    pub fn add(&mut self, item: T) {
        match self {
            Self::One(one) => {
                *self = Self::Many(vec![one.clone(), item]);
            }
            Self::Many(many) => {
                many.push(item);
            }
        }
    }

    /// Returns the length of the `OneMany`.
    pub const fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(many) => many.len(),
        }
    }

    /// Returns `true` if the `OneMany` is an empty `Many`.
    pub const fn is_empty(&self) -> bool {
        match self {
            Self::One(_) => false,
            Self::Many(many) => many.is_empty(),
        }
    }
}

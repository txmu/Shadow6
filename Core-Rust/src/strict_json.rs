//! Bounded JSON parsing that rejects duplicate map keys before deserialization.
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

struct CheckedValue(usize);

impl<'de> DeserializeSeed<'de> for CheckedValue {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.0 > 64 {
            return Err(de::Error::custom("JSON nesting exceeds 64 levels"));
        }
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for CheckedValue {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("bounded JSON with unique object keys")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> { Ok(Value::Bool(value)) }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> { Ok(Value::Number(value.into())) }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> { Ok(Value::Number(value.into())) }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("nonfinite JSON number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> { Ok(Value::String(value.into())) }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> { Ok(Value::String(value)) }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(CheckedValue(self.0 + 1))? { values.push(value); }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) { return Err(de::Error::custom("duplicate JSON field")); }
            values.insert(key, object.next_value_seed(CheckedValue(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
}

pub fn from_str<T: DeserializeOwned>(data: &str) -> Result<T, serde_json::Error> {
    from_slice(data.as_bytes())
}

pub fn from_slice<T: DeserializeOwned>(data: &[u8]) -> Result<T, serde_json::Error> {
    if data.len() > 1_048_576 {
        return Err(<serde_json::Error as de::Error>::custom("JSON exceeds 1 MiB"));
    }
    let mut decoder = serde_json::Deserializer::from_slice(data);
    let value = CheckedValue(0).deserialize(&mut decoder)?;
    decoder.end()?;
    serde_json::from_value(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_or_unbounded_json() {
        for input in [r#"{"x":1,"x":2}"#, r#"{"map":{"a":1,"\u0061":2}}"#,
                      r#"{"x":"\ud800"}"#, "{} {}"] {
            assert!(from_str::<Value>(input).is_err(), "{input}");
        }
        assert!(from_str::<Value>(&format!("{}0{}", "[".repeat(65), "]".repeat(65))).is_err());
        assert!(from_str::<Value>(r#"{"x":"你好","items":[1,true,null]}"#).is_ok());
    }
}

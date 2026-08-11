// SPDX-License-Identifier: Apache-2.0
// Conversions between prost well-known Struct/Value types and serde_json values.

use prost_types::{ListValue, Struct, Value as ProstValue, value::Kind};
use serde_json::Value as JsonValue;

/// Convert a `prost_types::Struct` to a `serde_json::Value`.
#[must_use]
pub fn struct_to_json(s: &Struct) -> JsonValue {
    let map = s
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), prost_value_to_json(v)))
        .collect();
    JsonValue::Object(map)
}

/// Convert a `prost_types::Value` to a `serde_json::Value`.
#[must_use]
pub fn prost_value_to_json(v: &ProstValue) -> JsonValue {
    match &v.kind {
        Some(Kind::NullValue(_)) | None => JsonValue::Null,
        Some(Kind::BoolValue(b)) => JsonValue::Bool(*b),
        Some(Kind::NumberValue(n)) => {
            // prost_types encodes all proto numeric types as f64. Emit integers
            // for whole-number values so digests computed from our patches
            // (which emit integers) match digests re-derived from the gateway's
            // Struct at VALIDATE time.
            let f = *n;
            if f.is_finite()
                && f.fract().to_bits() == 0
                && let Ok(i) = format!("{f:.0}").parse::<i64>()
            {
                return JsonValue::Number(serde_json::Number::from(i));
            }
            serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number)
        }
        Some(Kind::StringValue(s)) => JsonValue::String(s.clone()),
        Some(Kind::ListValue(l)) => {
            JsonValue::Array(l.values.iter().map(prost_value_to_json).collect())
        }
        Some(Kind::StructValue(s)) => struct_to_json(s),
    }
}

/// Convert a `serde_json::Value` to a `prost_types::Value`.
pub fn json_to_proto_value(value: &JsonValue) -> Result<ProstValue, String> {
    let kind = match value {
        JsonValue::Null => Kind::NullValue(0),
        JsonValue::Bool(b) => Kind::BoolValue(*b),
        JsonValue::Number(n) => {
            let f = n
                .as_f64()
                .ok_or_else(|| "number out of f64 range".to_string())?;
            Kind::NumberValue(f)
        }
        JsonValue::String(s) => Kind::StringValue(s.clone()),
        JsonValue::Array(arr) => {
            let values = arr
                .iter()
                .map(json_to_proto_value)
                .collect::<Result<Vec<_>, _>>()?;
            Kind::ListValue(ListValue { values })
        }
        JsonValue::Object(obj) => {
            let fields = obj
                .iter()
                .map(|(k, v)| json_to_proto_value(v).map(|pv| (k.clone(), pv)))
                .collect::<Result<_, _>>()?;
            Kind::StructValue(Struct { fields })
        }
    };
    Ok(ProstValue { kind: Some(kind) })
}

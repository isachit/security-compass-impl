//! Conversion utilities between `MontyObject` and `serde_json::Value`.
//!
//! These functions bridge the VM's object representation and the JSON format
//! used by the interpreter's public API and SQRT policy evaluation.

use security_compass_vm::{DictPairs, MontyObject};

use crate::error::InterpreterError;

/// Maximum recursion depth for nested object conversion to prevent stack overflow.
const MAX_DEPTH: usize = 100;

/// Converts a `MontyObject` to a `serde_json::Value`.
///
/// # Mapping
/// - `None` → `Null`
/// - `Bool(b)` → `Bool(b)`
/// - `Int(i)` → `Number(i)`
/// - `Float(f)` → `Number(f)` (NaN/Inf → `Null`)
/// - `BigInt(n)` → `String(n.to_string())` (precision loss prevention)
/// - `String(s)` → `String(s)`
/// - `Bytes(b)` → `Array[Number]` (each byte as a number)
/// - `List/Tuple/Set/FrozenSet` → `Array` (recursively converted)
/// - `Dict` → `Object` (keys via `Display`, values recursively converted)
/// - `NamedTuple` → `Object` (field names as keys)
/// - `Dataclass` → `Object` (field names as keys, from attrs)
/// - `Exception` → `Object { "$exception": { "type": ..., "message": ... } }`
/// - `Repr/Path/Type` → `String`
/// - `Ellipsis/Cycle` → `Null`
/// - `BuiltinFunction` → `ConversionError`
///
/// # Errors
/// Returns `InterpreterError::ConversionError` if:
/// - The object contains a `BuiltinFunction` (not serializable)
/// - Nesting exceeds `MAX_DEPTH` (100 levels)
pub fn monty_to_json(obj: &MontyObject) -> Result<serde_json::Value, InterpreterError> {
    monty_to_json_inner(obj, 0)
}

fn monty_to_json_inner(obj: &MontyObject, depth: usize) -> Result<serde_json::Value, InterpreterError> {
    if depth > MAX_DEPTH {
        return Err(InterpreterError::ConversionError {
            message: format!("nesting depth exceeds maximum of {MAX_DEPTH}"),
        });
    }

    match obj {
        MontyObject::None => Ok(serde_json::Value::Null),
        MontyObject::Ellipsis => Ok(serde_json::Value::Null),
        MontyObject::Bool(b) => Ok(serde_json::Value::Bool(*b)),

        MontyObject::Int(i) => Ok(serde_json::Value::Number(
            serde_json::Number::from(*i),
        )),

        MontyObject::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                Ok(serde_json::Value::Null)
            } else {
                serde_json::Number::from_f64(*f)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| InterpreterError::ConversionError {
                        message: format!("cannot represent float {f} as JSON number"),
                    })
            }
        }

        MontyObject::BigInt(n) => {
            // BigInt may exceed JSON number range; serialize as string
            Ok(serde_json::Value::String(n.to_string()))
        }

        MontyObject::String(s) => Ok(serde_json::Value::String(s.clone())),

        MontyObject::Bytes(bytes) => {
            let arr: Vec<serde_json::Value> = bytes
                .iter()
                .map(|b| serde_json::Value::Number(serde_json::Number::from(*b)))
                .collect();
            Ok(serde_json::Value::Array(arr))
        }

        MontyObject::List(items) | MontyObject::Tuple(items) | MontyObject::Set(items) | MontyObject::FrozenSet(items) => {
            let arr: Result<Vec<_>, _> = items
                .iter()
                .map(|item| monty_to_json_inner(item, depth + 1))
                .collect();
            Ok(serde_json::Value::Array(arr?))
        }

        MontyObject::Dict(pairs) => dict_pairs_to_json(pairs, depth),

        MontyObject::NamedTuple {
            field_names,
            values,
            ..
        } => {
            let mut map = serde_json::Map::with_capacity(field_names.len());
            for (name, value) in field_names.iter().zip(values.iter()) {
                map.insert(name.clone(), monty_to_json_inner(value, depth + 1)?);
            }
            Ok(serde_json::Value::Object(map))
        }

        MontyObject::Dataclass {
            field_names, attrs, ..
        } => {
            // Build a map from the attrs DictPairs, using field_names for ordering
            let attrs_map: std::collections::HashMap<String, &MontyObject> = attrs
                .into_iter()
                .map(|(k, v)| (format!("{k}"), v))
                .collect();

            let mut map = serde_json::Map::with_capacity(field_names.len());
            for name in field_names {
                if let Some(value) = attrs_map.get(name) {
                    map.insert(name.clone(), monty_to_json_inner(value, depth + 1)?);
                } else {
                    map.insert(name.clone(), serde_json::Value::Null);
                }
            }
            Ok(serde_json::Value::Object(map))
        }

        MontyObject::Exception { exc_type, arg } => {
            let mut inner = serde_json::Map::new();
            inner.insert("type".to_string(), serde_json::Value::String(format!("{exc_type:?}")));
            if let Some(msg) = arg {
                inner.insert("message".to_string(), serde_json::Value::String(msg.clone()));
            }
            let mut outer = serde_json::Map::new();
            outer.insert("$exception".to_string(), serde_json::Value::Object(inner));
            Ok(serde_json::Value::Object(outer))
        }

        MontyObject::Repr(s) | MontyObject::Path(s) => {
            Ok(serde_json::Value::String(s.clone()))
        }

        MontyObject::Type(t) => {
            Ok(serde_json::Value::String(format!("{t:?}")))
        }

        MontyObject::Cycle(_, repr) => {
            // Cycle indicates a reference loop; represent as null
            let _ = repr;
            Ok(serde_json::Value::Null)
        }

        MontyObject::BuiltinFunction(_) => Err(InterpreterError::ConversionError {
            message: "cannot convert BuiltinFunction to JSON".to_string(),
        }),
    }
}

/// Converts `DictPairs` to a JSON object.
///
/// Keys are converted to strings via `Display` formatting on the key `MontyObject`.
fn dict_pairs_to_json(
    pairs: &DictPairs,
    depth: usize,
) -> Result<serde_json::Value, InterpreterError> {
    let entries: Vec<_> = pairs.into_iter().collect();
    let mut map = serde_json::Map::with_capacity(entries.len());
    for (key, value) in entries {
        let key_str = monty_key_to_string(key);
        map.insert(key_str, monty_to_json_inner(value, depth + 1)?);
    }
    Ok(serde_json::Value::Object(map))
}

/// Converts a `MontyObject` dict key to a string representation.
///
/// JSON objects require string keys, so non-string keys are formatted via Display-like logic.
fn monty_key_to_string(key: &MontyObject) -> String {
    match key {
        MontyObject::String(s) => s.clone(),
        MontyObject::Int(i) => i.to_string(),
        MontyObject::Float(f) => f.to_string(),
        MontyObject::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        MontyObject::None => "None".to_string(),
        MontyObject::BigInt(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

/// Converts a `serde_json::Value` to a `MontyObject`.
///
/// # Mapping
/// - `Null` → `None`
/// - `Bool(b)` → `Bool(b)`
/// - `Number` → `Int(i64)` if representable, otherwise `Float(f64)`
/// - `String(s)` → `String(s)`
/// - `Array` → `List` (recursively converted)
/// - `Object` → `Dict(DictPairs)` (keys as MontyObject::String)
pub fn json_to_monty(value: serde_json::Value) -> MontyObject {
    match value {
        serde_json::Value::Null => MontyObject::None,
        serde_json::Value::Bool(b) => MontyObject::Bool(b),
        serde_json::Value::Number(n) => {
            // Prefer integer representation if possible
            if let Some(i) = n.as_i64() {
                MontyObject::Int(i)
            } else if let Some(f) = n.as_f64() {
                MontyObject::Float(f)
            } else {
                // Fallback: large unsigned integers
                MontyObject::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => MontyObject::String(s),
        serde_json::Value::Array(items) => {
            MontyObject::List(items.into_iter().map(json_to_monty).collect())
        }
        serde_json::Value::Object(map) => {
            let pairs: Vec<(MontyObject, MontyObject)> = map
                .into_iter()
                .map(|(k, v)| (MontyObject::String(k), json_to_monty(v)))
                .collect();
            MontyObject::Dict(DictPairs::from(pairs))
        }
    }
}

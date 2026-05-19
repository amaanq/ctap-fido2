//! Thin wrappers around `ciborium` for CTAP-flavored CBOR.

use std::io::Cursor;

use ciborium::Value;

use crate::error::{
   Error,
   Result,
};

/// Encode a [`Value`] to CBOR bytes.
///
/// # Errors
///
/// [`Error::Cbor`] if `ciborium::into_writer` fails.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
   let mut buf = Vec::<u8>::new();
   ciborium::into_writer(value, &mut buf).map_err(|err| Error::Cbor(err.to_string()))?;
   Ok(buf)
}

/// Decode a single CBOR value from a byte slice. Trailing bytes are an error.
///
/// # Errors
///
/// [`Error::Cbor`] if the input is not a valid CBOR value or has trailing
/// bytes.
pub fn decode(bytes: &[u8]) -> Result<Value> {
   let mut cursor = Cursor::new(bytes);
   let value =
      ciborium::from_reader::<Value, _>(&mut cursor).map_err(|err| Error::Cbor(err.to_string()))?;
   let consumed = usize::try_from(cursor.position())
      .map_err(|_| Error::Cbor("cursor position out of usize range".into()))?;
   if consumed != bytes.len() {
      return Err(Error::Cbor(format!(
         "trailing bytes after CBOR value ({consumed}/{} consumed)",
         bytes.len()
      )));
   }
   Ok(value)
}

/// Look up an integer-keyed map field. CTAP responses are CBOR maps with
/// [`u64`] keys.
#[must_use]
pub fn get_int_field(value: &Value, key: i128) -> Option<&Value> {
   value
      .as_map()?
      .iter()
      .find_map(|&(ref stored_key, ref stored_val)| {
         let stored = Into::<i128>::into(stored_key.as_integer()?);
         (stored == key).then_some(stored_val)
      })
}

/// Look up a string-keyed map field. Used inside extension sub-maps where
/// CTAP encodes extension identifiers as text strings.
#[must_use]
pub fn get_text_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
   value
      .as_map()?
      .iter()
      .find_map(|&(ref stored_key, ref stored_val)| {
         (stored_key.as_text()? == key).then_some(stored_val)
      })
}

/// Force a [`Value`] to bytes, returning a parse error if it isn't a byte
/// string.
///
/// # Errors
///
/// [`Error::Parse`] carrying `label` if `value` isn't a byte string.
pub fn require_bytes<'a>(value: &'a Value, label: &'static str) -> Result<&'a [u8]> {
   value
      .as_bytes()
      .map(Vec::as_slice)
      .ok_or(Error::Parse(label))
}

/// Remove and return the value at an integer-keyed entry.
#[must_use]
pub fn take_int_field(entries: &mut Vec<(Value, Value)>, key: i128) -> Option<Value> {
   let pos = entries
      .iter()
      .position(|&(ref stored, _)| stored.as_integer().map(Into::<i128>::into) == Some(key))?;
   Some(entries.swap_remove(pos).1)
}

/// Remove and return the value at a text-keyed entry.
#[must_use]
pub fn take_text_field(entries: &mut Vec<(Value, Value)>, key: &str) -> Option<Value> {
   let pos = entries
      .iter()
      .position(|&(ref stored, _)| stored.as_text() == Some(key))?;
   Some(entries.swap_remove(pos).1)
}

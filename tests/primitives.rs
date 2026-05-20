//! Deterministic tests for the parts of the crate that don't require a
//! real authenticator.

use ciborium::Value;
use ctap_fido2::{
   cbor,
   error::{
      CtapStatus,
      Error,
   },
   hid::KeepAlive,
};

#[test]
fn ctap_status_round_trip() {
   // Every typed variant must encode back to the byte it came from.
   for byte in [
      0x00, 0x01, 0x11, 0x27, 0x2E, 0x2F, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
   ] {
      assert_eq!(CtapStatus::from_byte(byte).as_byte(), byte);
   }
   // Unknown bytes flow through `Other` losslessly.
   assert_eq!(CtapStatus::from_byte(0xAA).as_byte(), 0xAA);
   assert!(matches!(
      CtapStatus::from_byte(0xAA),
      CtapStatus::Other(0xAA)
   ));
}

#[test]
fn keepalive_classification() {
   assert_eq!(KeepAlive::from_byte(0x01), KeepAlive::Processing);
   assert_eq!(KeepAlive::from_byte(0x02), KeepAlive::UserPresenceNeeded);
   assert!(matches!(KeepAlive::from_byte(0xFF), KeepAlive::Other(0xFF)));
}

#[test]
fn cbor_round_trip_int_keyed_map() {
   let original = Value::Map(vec![
      (Value::Integer(1.into()), Value::Bytes(vec![0xDE, 0xAD])),
      (Value::Integer(2.into()), Value::Text("hmac-secret".into())),
   ]);
   let bytes = cbor::encode(&original).expect("encode");
   let decoded = cbor::decode(&bytes).expect("decode");

   let field1 = cbor::get_int_field(&decoded, 1).expect("field 1 present");
   assert_eq!(
      field1.as_bytes().map(Vec::as_slice),
      Some([0xDE, 0xAD].as_slice())
   );

   let field2 = cbor::get_int_field(&decoded, 2).expect("field 2 present");
   assert_eq!(field2.as_text(), Some("hmac-secret"));

   assert!(cbor::get_int_field(&decoded, 99).is_none());
}

#[test]
fn cbor_text_field_lookup() {
   let map = Value::Map(vec![
      (Value::Text("a".into()), Value::Integer(1.into())),
      (Value::Text("b".into()), Value::Integer(2.into())),
   ]);
   assert_eq!(
      cbor::get_text_field(&map, "b").and_then(Value::as_integer),
      Some(2.into())
   );
   assert!(cbor::get_text_field(&map, "z").is_none());
}

#[test]
fn cbor_require_bytes_errors_on_wrong_type() {
   let value = Value::Integer(7.into());
   match cbor::require_bytes(&value, "test_field") {
      Err(Error::Parse("test_field")) => {},
      other => panic!("expected parse error, got {other:?}"),
   }
}

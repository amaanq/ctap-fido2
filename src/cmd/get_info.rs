//! `authenticatorGetInfo` (CTAP2 command `0x04`).

use ciborium::Value;

use crate::{
   cbor,
   cmd::AuthenticatorInfo,
   error::Result,
   hid::Transport,
};

/// CTAP2 command byte for `authenticatorGetInfo`.
pub const COMMAND: u8 = 0x04;

/// Run `getInfo` and parse every field this crate exposes.
///
/// # Errors
///
/// [`Error::Ctap`](crate::Error::Ctap) if the device rejects the command,
/// [`Error::Hid`](crate::Error::Hid) on transport failure,
/// [`Error::Cbor`](crate::Error::Cbor) if the response isn't valid CBOR.
pub fn call(transport: &mut Transport) -> Result<AuthenticatorInfo> {
   let response = transport.transact(&[COMMAND], None)?;
   let map = cbor::decode(&response)?;
   Ok(parse(&map))
}

fn parse(map: &Value) -> AuthenticatorInfo {
   let mut aaguid = [0_u8; 16];
   if let Some(bytes) = cbor::get_int_field(map, 0x03).and_then(Value::as_bytes)
      && bytes.len() == 16
   {
      aaguid.copy_from_slice(bytes);
   }
   let options = cbor::get_int_field(map, 0x04)
      .and_then(Value::as_map)
      .map(|entries| {
         entries
            .iter()
            .filter_map(|&(ref key, ref value)| Some((key.as_text()?.to_owned(), value.as_bool()?)))
            .collect()
      })
      .unwrap_or_default();
   let pin_protocols = cbor::get_int_field(map, 0x06)
      .and_then(Value::as_array)
      .map(|arr| {
         arr.iter()
            .filter_map(|item| item.as_integer().map(Into::<i128>::into))
            .filter_map(|i| u8::try_from(i).ok())
            .collect()
      })
      .unwrap_or_default();
   let algorithms = cbor::get_int_field(map, 0x0A)
      .and_then(Value::as_array)
      .map(|arr| {
         arr.iter()
            .filter_map(|item| cbor::get_text_field(item, "alg"))
            .filter_map(Value::as_integer)
            .filter_map(|i| i32::try_from(Into::<i128>::into(i)).ok())
            .collect()
      })
      .unwrap_or_default();

   AuthenticatorInfo {
      versions: string_array(map, 0x01),
      extensions: string_array(map, 0x02),
      aaguid,
      options,
      max_msg_size: u32_field(map, 0x05),
      pin_protocols,
      max_credential_count_in_list: u32_field(map, 0x07),
      max_credential_id_length: u32_field(map, 0x08),
      transports: string_array(map, 0x09),
      algorithms,
      max_serialized_large_blob_array: u32_field(map, 0x0B),
      force_pin_change: cbor::get_int_field(map, 0x0C)
         .and_then(Value::as_bool)
         .unwrap_or(false),
      min_pin_length: u32_field(map, 0x0D),
      firmware_version: u32_field(map, 0x0E),
      max_cred_blob_length: u32_field(map, 0x0F),
      max_rp_ids_for_set_min_pin_length: u32_field(map, 0x10),
      preferred_platform_uv_attempts: u32_field(map, 0x11),
      uv_modality: u32_field(map, 0x12),
      remaining_discoverable_credentials: u32_field(map, 0x14),
   }
}

fn string_array(map: &Value, key: i128) -> Vec<String> {
   cbor::get_int_field(map, key)
      .and_then(Value::as_array)
      .map(|arr| {
         arr.iter()
            .filter_map(|item| item.as_text().map(str::to_owned))
            .collect()
      })
      .unwrap_or_default()
}

fn u32_field(map: &Value, key: i128) -> Option<u32> {
   let raw = cbor::get_int_field(map, key)
      .and_then(Value::as_integer)
      .map(i128::from)?;
   u32::try_from(raw).ok()
}

#[cfg(test)]
mod tests {
   use super::*;

   /// Verify our parser silently ignores unknown fieldsd rather than erroring
   /// on "unknown info".
   #[test]
   fn parse_tolerates_unknown_fields() {
      let map = Value::Map(vec![
         (
            Value::Integer(0x01.into()),
            Value::Array(vec![
               Value::Text("U2F_V2".into()),
               Value::Text("FIDO_2_0".into()),
               Value::Text("FIDO_2_1".into()),
            ]),
         ),
         (
            Value::Integer(0x02.into()),
            Value::Array(vec![
               Value::Text("credProtect".into()),
               Value::Text("hmac-secret".into()),
               Value::Text("thirdPartyPayment".into()),
            ]),
         ),
         (Value::Integer(0x03.into()), Value::Bytes(vec![0xEC; 16])),
         (
            Value::Integer(0x04.into()),
            Value::Map(vec![
               (Value::Text("rk".into()), Value::Bool(true)),
               (Value::Text("up".into()), Value::Bool(true)),
               (Value::Text("clientPin".into()), Value::Bool(true)),
               (Value::Text("credMgmt".into()), Value::Bool(true)),
            ]),
         ),
         (Value::Integer(0x05.into()), Value::Integer(3072.into())),
         (
            Value::Integer(0x06.into()),
            Value::Array(vec![Value::Integer(2.into()), Value::Integer(1.into())]),
         ),
         // CTAP 2.2 field `attestationFormats` at key 0x16 .
         (
            Value::Integer(0x16.into()),
            Value::Array(vec![
               Value::Text("packed".into()),
               Value::Text("none".into()),
            ]),
         ),
         // Future-spec key the crate has no knowledge of.
         (Value::Integer(0xFF.into()), Value::Text("future".into())),
      ]);

      let info = parse(&map);

      assert_eq!(info.versions, ["U2F_V2", "FIDO_2_0", "FIDO_2_1"]);
      assert_eq!(info.extensions, [
         "credProtect",
         "hmac-secret",
         "thirdPartyPayment"
      ]);
      assert_eq!(info.aaguid, [0xEC; 16]);
      assert_eq!(info.option("credMgmt"), Some(true));
      assert_eq!(info.max_msg_size, Some(3072));
      assert_eq!(info.pin_protocols, [2, 1]);
      assert!(info.supports_pin_protocol_v1());
      assert!(info.supports_pin_protocol_v2());
      assert!(info.client_pin_set());
      assert!(info.hmac_secret());
   }
}

//! `authenticatorMakeCredential` (CTAP2 0x01) with `hmac-secret` and the
//! `credProtect`, `credBlob`, `largeBlobKey`, `minPinLength` extensions.

use base64::{
   Engine as _,
   engine::general_purpose::STANDARD_NO_PAD,
};
use ciborium::Value;
use rand::Rng as _;

use crate::{
   cbor,
   cmd::MakeCredentialOptions,
   cose::{
      self,
      CredentialPublicKey,
   },
   error::{
      Error,
      Result,
   },
   hid::Transport,
   pin::{
      self,
      PinSession,
   },
};

pub const COMMAND: u8 = 0x01;

/// `credProtect` policy levels (CTAP2.1 §12.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CredProtect {
   /// UV optional. Default behavior when the extension is absent.
   UvOptional         = 1,
   /// UV optional with allow-list assertions; UV required when discovering
   /// resident credentials.
   UvOptionalWithList = 2,
   /// UV always required.
   UvRequired         = 3,
}

impl CredProtect {
   #[must_use]
   pub const fn as_u8(self) -> u8 {
      self as u8
   }
}

/// Raw attestation object from `makeCredential`.
///
/// Format and statement shape vary by `fmt`. The crate does not verify, but
/// rather callers that need attestation pass these bytes to a verifier.
#[derive(Clone, Debug)]
pub struct AttestationObject {
   /// Attestation format identifier (e.g. `"packed"`, `"none"`).
   pub fmt:       String,
   /// `authData` bytes, identical to what's parsed for cred id / pubkey.
   pub auth_data: Vec<u8>,
   /// CBOR-encoded attestation statement; shape depends on `fmt`.
   pub att_stmt:  Vec<u8>,
}

/// Echo of extensions the device honored at registration time.
#[derive(Clone, Debug, Default)]
pub struct CredentialExtensions {
   /// True iff the device acknowledged storing the `credBlob`.
   pub cred_blob_set:  bool,
   /// `credProtect` level the device applied. Absent if the extension
   /// wasn't requested or wasn't supported.
   pub cred_protect:   Option<u8>,
   /// `minPinLength` value the device returned, when the caller opted in.
   pub min_pin_length: Option<u32>,
}

/// Newly registered credential.
#[derive(Clone, Debug)]
pub struct Credential {
   /// Credential id. Hand back to `getAssertion` to assert on this credential.
   pub id:             Vec<u8>,
   /// Public key. Persist alongside the id; required to verify assertion
   /// signatures on subsequent `get_hmac_secret` calls.
   pub public_key:     CredentialPublicKey,
   /// Full attestation object as returned by the device.
   pub attestation:    AttestationObject,
   /// Per-credential AES key tied to the device's large-blob store,
   /// returned only when [`MakeCredentialOptions::large_blob_key`] is
   /// `true` and the device supports the extension.
   pub large_blob_key: Option<Vec<u8>>,
   /// Echoed extension fields from the registration response.
   pub extensions:     CredentialExtensions,
}

/// Returns the registered credential. Forces `options.uv = false` for
/// interop with the Go upstream's non-UV-scoped hmac-secret output.
///
/// # Errors
///
/// [`Error::Ctap`] for PIN, touch, or policy failures.
/// [`Error::Cbor`] / [`Error::Parse`] if the response is malformed.
pub fn call(
   transport: &mut Transport,
   rp_id: &str,
   client_data_hash: &[u8; 32],
   opts: &MakeCredentialOptions<'_>,
) -> Result<Credential> {
   // Randomized userId/userName so we don't fingerprint the authenticator.
   let mut user_id = [0_u8; 32];
   rand::rng().fill_bytes(&mut user_id);
   let mut user_name_bytes = [0_u8; 6];
   rand::rng().fill_bytes(&mut user_name_bytes);
   let user_name = STANDARD_NO_PAD.encode(user_name_bytes);

   // pinUvAuthParam = HMAC-SHA256(pinUvAuthToken, clientDataHash)[..16].
   let pin_auth = match opts.pin {
      Some(pin_str) => {
         let session = PinSession::establish(transport)?;
         let token = session.get_pin_token(transport, pin_str)?;
         Some(token.auth_param(client_data_hash))
      },
      None => None,
   };

   let mut extensions = vec![(Value::Text("hmac-secret".into()), Value::Bool(true))];
   if let Some(level) = opts.cred_protect {
      extensions.push((
         Value::Text("credProtect".into()),
         Value::Integer(level.as_u8().into()),
      ));
   }
   if let Some(blob) = opts.cred_blob {
      if blob.len() > 32 {
         return Err(Error::Pin("credBlob exceeds 32 bytes"));
      }
      extensions.push((Value::Text("credBlob".into()), Value::Bytes(blob.to_vec())));
   }
   if opts.large_blob_key {
      extensions.push((Value::Text("largeBlobKey".into()), Value::Bool(true)));
   }
   if opts.min_pin_length {
      extensions.push((Value::Text("minPinLength".into()), Value::Bool(true)));
   }

   let mut request = vec![
      (
         Value::Integer(1.into()),
         Value::Bytes(client_data_hash.to_vec()),
      ),
      (
         Value::Integer(2.into()),
         Value::Map(vec![(Value::Text("id".into()), Value::Text(rp_id.into()))]),
      ),
      (
         Value::Integer(3.into()),
         Value::Map(vec![
            (Value::Text("id".into()), Value::Bytes(user_id.to_vec())),
            (Value::Text("name".into()), Value::Text(user_name)),
         ]),
      ),
      (
         Value::Integer(4.into()),
         Value::Array(vec![Value::Map(vec![
            (
               Value::Text("alg".into()),
               Value::Integer(opts.algorithm.cose_id().into()),
            ),
            (Value::Text("type".into()), Value::Text("public-key".into())),
         ])]),
      ),
      // CTAP2 makeCredential keys: 5=excludeList, 6=extensions, 7=options,
      // 8=pinUvAuthParam, 9=pinProtocol. Wrong-keyed extensions trip 0x11.
      (Value::Integer(6.into()), Value::Map(extensions)),
      (
         Value::Integer(7.into()),
         Value::Map({
            let mut options = vec![(Value::Text("uv".into()), Value::Bool(false))];
            if opts.resident_key {
               options.push((Value::Text("rk".into()), Value::Bool(true)));
            }
            options
         }),
      ),
   ];

   if let Some(auth) = pin_auth {
      request.push((Value::Integer(8.into()), Value::Bytes(auth.to_vec())));
      request.push((
         Value::Integer(9.into()),
         Value::Integer(pin::PROTOCOL_V1.into()),
      ));
   }

   let payload = {
      let mut bytes = vec![COMMAND];
      bytes.extend(cbor::encode(&Value::Map(request))?);
      bytes
   };
   let response = transport.transact(&payload, None)?;
   parse_response(&response)
}

fn parse_response(response: &[u8]) -> Result<Credential> {
   let Value::Map(mut entries) = cbor::decode(response)? else {
      return Err(Error::Parse("makeCredential response not a CBOR map"));
   };

   let Some(Value::Text(fmt)) = cbor::take_int_field(&mut entries, 0x01) else {
      return Err(Error::Parse("makeCredential response missing fmt"));
   };
   let Some(Value::Bytes(auth_data)) = cbor::take_int_field(&mut entries, 0x02) else {
      return Err(Error::Parse("makeCredential response missing authData"));
   };
   let att_stmt_value = cbor::take_int_field(&mut entries, 0x03)
      .ok_or(Error::Parse("makeCredential response missing attStmt"))?;
   let att_stmt = cbor::encode(&att_stmt_value)?;

   let large_blob_key = match cbor::take_int_field(&mut entries, 0x04) {
      Some(Value::Bytes(bytes)) => Some(bytes),
      _ => None,
   };

   let (id, public_key, extensions) = parse_credential(&auth_data)?;

   Ok(Credential {
      id,
      public_key,
      attestation: AttestationObject {
         fmt,
         auth_data,
         att_stmt,
      },
      large_blob_key,
      extensions,
   })
}

/// Parse credential id + public key + extensions echo out of `authData`:
///
/// ```text
/// rpIdHash(32) | flags(1) | signCount(4) | aaguid(16)
///   | credIdLen(2 BE) | credId | credPubKey(CBOR) | [extensions(CBOR)]
/// ```
fn parse_credential(
   auth_data: &[u8],
) -> Result<(Vec<u8>, CredentialPublicKey, CredentialExtensions)> {
   if auth_data.len() < 32 + 1 + 4 + 16 + 2 {
      return Err(Error::Parse("authData too short for attested credential"));
   }
   let flags = auth_data[32];
   if flags & 0x40 == 0 {
      return Err(Error::Parse(
         "authData missing AT flag, no attested credential data",
      ));
   }
   let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
   let id_start = 55_usize;
   let id_end = id_start
      .checked_add(cred_id_len)
      .ok_or(Error::Parse("credential id length overflow"))?;
   if id_end > auth_data.len() {
      return Err(Error::Parse("credential id length exceeds authData"));
   }
   let id = auth_data[id_start..id_end].to_vec();
   let (public_key, ext_offset) = cose::parse_authdata_pubkey(auth_data, id_end)?;

   // Extensions echo lives after credPubKey, gated by the ED flag.
   let extensions = if flags & 0x80 != 0 && ext_offset < auth_data.len() {
      parse_extensions_echo(&auth_data[ext_offset..])?
   } else {
      CredentialExtensions::default()
   };

   Ok((id, public_key, extensions))
}

fn parse_extensions_echo(bytes: &[u8]) -> Result<CredentialExtensions> {
   let Value::Map(entries) = cbor::decode(bytes)? else {
      return Ok(CredentialExtensions::default());
   };
   let mut out = CredentialExtensions::default();
   for &(ref key, ref value) in &entries {
      let Some(name) = key.as_text() else { continue };
      match name {
         "credBlob" => out.cred_blob_set = value.as_bool().unwrap_or(false),
         "credProtect" => {
            out.cred_protect = value
               .as_integer()
               .map(Into::<i128>::into)
               .and_then(|i| u8::try_from(i).ok());
         },
         "minPinLength" => {
            out.min_pin_length = value
               .as_integer()
               .map(Into::<i128>::into)
               .and_then(|i| u32::try_from(i).ok());
         },
         _ => {},
      }
   }
   Ok(out)
}

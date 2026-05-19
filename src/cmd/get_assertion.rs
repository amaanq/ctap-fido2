//! `authenticatorGetAssertion` (CTAP2 0x02), with an `hmac-secret` helper.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetAssertion>.

use std::io::{
   Cursor,
   Seek as _,
   SeekFrom,
};

use ciborium::Value;

use crate::{
   cbor,
   cmd::HmacSecret,
   cose::CredentialPublicKey,
   error::{
      Error,
      Result,
   },
   hid::Transport,
   pin::{
      self,
      PinSession,
      PinToken,
   },
};

/// `authData` flag bits we care about for CTAP / `WebAuthn`.
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;
/// `authData` fixed-prefix length: rpIdHash (32) + flags (1) + signCount (4).
const AUTH_DATA_HEADER: usize = 37;
/// Length of the AAGUID + credIdLen prefix when the AT bit is set.
const ATTESTED_FIXED: usize = 16 + 2;

pub const COMMAND: u8 = 0x02;

/// `PublicKeyCredentialUserEntity` from a `getAssertion` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
   /// User handle bytes. Always present.
   pub id:           Vec<u8>,
   /// Account name (e.g. `"alice@example.com"`).
   pub name:         Option<String>,
   /// Human-friendly display name.
   pub display_name: Option<String>,
}

/// Parsed `authenticatorGetAssertion` response.
#[derive(Clone, Debug)]
pub struct Assertion {
   /// Credential id of the selected credential.
   pub credential_id:         Option<Vec<u8>>,
   /// Raw `authData` bytes.
   pub auth_data:             Vec<u8>,
   /// Assertion signature over `authData || clientDataHash`.
   pub signature:             Vec<u8>,
   /// User entity, populated when the credential is resident (rk=true).
   pub user:                  Option<User>,
   /// Total number of credentials the device has for this request. When
   /// `> 1` the caller should issue `getNextAssertion` to retrieve the
   /// remaining matches.
   pub number_of_credentials: Option<u32>,
}

/// Issue a generic `getAssertion`. Empty `allow_list` omits the field
/// and triggers resident-credential discovery.
///
/// # Errors
///
/// [`Error::Ctap`] with
/// [`CtapStatus::NoCredentials`](crate::CtapStatus::NoCredentials) or the PIN/
/// touch statuses from
/// [`make_credential::call`](crate::cmd::make_credential::call).
/// [`Error::Cbor`] / [`Error::Parse`] on a malformed response.
pub fn call(
   transport: &mut Transport,
   rp_id: &str,
   client_data_hash: &[u8; 32],
   allow_list: &[&[u8]],
   extensions: Option<Value>,
   pin_token: Option<&PinToken>,
) -> Result<Assertion> {
   let mut request = vec![
      (Value::Integer(1.into()), Value::Text(rp_id.into())),
      (
         Value::Integer(2.into()),
         Value::Bytes(client_data_hash.to_vec()),
      ),
   ];
   if !allow_list.is_empty() {
      let descriptors = allow_list
         .iter()
         .map(|cred_id| {
            Value::Map(vec![
               (Value::Text("id".into()), Value::Bytes(cred_id.to_vec())),
               (Value::Text("type".into()), Value::Text("public-key".into())),
            ])
         })
         .collect();
      request.push((Value::Integer(3.into()), Value::Array(descriptors)));
   }
   if let Some(ext) = extensions {
      request.push((Value::Integer(4.into()), ext));
   }
   if let Some(token) = pin_token {
      let pin_auth_param = token.auth_param(client_data_hash);
      request.push((
         Value::Integer(6.into()),
         Value::Bytes(pin_auth_param.to_vec()),
      ));
      request.push((
         Value::Integer(7.into()),
         Value::Integer(pin::PROTOCOL_V1.into()),
      ));
   }

   let mut payload = vec![COMMAND];
   payload.extend(cbor::encode(&Value::Map(request))?);
   let response = transport.transact(&payload, None)?;
   parse_response(&response)
}

/// Parse a CBOR-encoded `getAssertion` / `getNextAssertion` response.
pub(crate) fn parse_response(response: &[u8]) -> Result<Assertion> {
   let Value::Map(mut entries) = cbor::decode(response)? else {
      return Err(Error::Parse("getAssertion response not a CBOR map"));
   };

   let credential_id = match cbor::take_int_field(&mut entries, 0x01) {
      Some(Value::Map(mut descriptor)) => {
         match cbor::take_text_field(&mut descriptor, "id") {
            Some(Value::Bytes(bytes)) => Some(bytes),
            _ => None,
         }
      },
      _ => None,
   };
   let Some(Value::Bytes(auth_data)) = cbor::take_int_field(&mut entries, 0x02) else {
      return Err(Error::Parse("getAssertion response missing authData"));
   };
   let Some(Value::Bytes(signature)) = cbor::take_int_field(&mut entries, 0x03) else {
      return Err(Error::Parse("getAssertion response missing signature"));
   };
   let user = parse_user(cbor::take_int_field(&mut entries, 0x04));
   let number_of_credentials = cbor::take_int_field(&mut entries, 0x05)
      .and_then(|value| value.as_integer().map(Into::<i128>::into))
      .and_then(|i| u32::try_from(i).ok());

   Ok(Assertion {
      credential_id,
      auth_data,
      signature,
      user,
      number_of_credentials,
   })
}

fn parse_user(value: Option<Value>) -> Option<User> {
   let Value::Map(mut entries) = value? else {
      return None;
   };
   let Some(Value::Bytes(id)) = cbor::take_text_field(&mut entries, "id") else {
      return None;
   };
   let name = match cbor::take_text_field(&mut entries, "name") {
      Some(Value::Text(text)) => Some(text),
      _ => None,
   };
   let display_name = match cbor::take_text_field(&mut entries, "displayName") {
      Some(Value::Text(text)) => Some(text),
      _ => None,
   };
   Some(User {
      id,
      name,
      display_name,
   })
}

/// Inputs to [`call_hmac_secret`].
#[derive(Clone, Copy, Debug)]
pub struct HmacSecretRequest<'a> {
   /// Relying party id the credential was registered under.
   pub rp_id:             &'a str,
   /// Per-call 32-byte client data hash. Random is fine.
   pub client_data_hash:  &'a [u8; 32],
   /// Credential id from [`make_credential`](crate::cmd::make_credential).
   pub cred_id:           &'a [u8],
   /// First HMAC salt.
   pub salt:              &'a [u8; 32],
   /// Optional second salt. Some devices implement single-salt only and
   /// will be detected at response time.
   pub salt2:             Option<&'a [u8; 32]>,
   /// PIN, when the device requires one.
   pub pin:               Option<&'a str>,
   /// Credential public key. When `Some`, the assertion signature is
   /// verified before the output is decrypted.
   pub public_key:        Option<&'a CredentialPublicKey>,
   /// Request the `credBlob` extension echo in the same assertion. The
   /// blob is whatever was stored at registration time via
   /// `MakeCredentialOptions::cred_blob`.
   pub request_cred_blob: bool,
}

/// Outputs from [`call_hmac_secret`].
pub struct HmacSecretResponse {
   /// First HMAC output. Always present.
   pub secret:    HmacSecret,
   /// Second HMAC output. Present iff [`HmacSecretRequest::salt2`] was
   /// supplied and the device honored it.
   pub secret2:   Option<HmacSecret>,
   /// `credBlob` bytes echoed by the device. Present iff
   /// [`HmacSecretRequest::request_cred_blob`] was `true` and the
   /// credential has a blob set.
   pub cred_blob: Option<Vec<u8>>,
}

/// Run `getAssertion` with the `hmac-secret` extension and return the
/// decrypted 32-byte output(s). The second slot is `None` when `salt2`
/// was not requested.
///
/// # Errors
///
/// CTAP statuses (PIN, touch, no-credentials) from [`call`].
/// [`Error::MissingExtension`] when the device omits the hmac-secret
/// output or returns only one half despite a salt2 request.
/// [`Error::Pin`] on signature-verification failure.
pub fn call_hmac_secret(
   transport: &mut Transport,
   req: &HmacSecretRequest<'_>,
) -> Result<HmacSecretResponse> {
   let session = PinSession::establish(transport)?;
   let pin_token = match req.pin {
      Some(value) => Some(session.get_pin_token(transport, value)?),
      None => None,
   };

   // `saltEnc` is `AES-CBC(shared, salt1 || salt2)` when salt2 is present,
   // `AES-CBC(shared, salt1)` otherwise. The device replies with the same
   // shape under the same key.
   let salt_plain: Vec<u8> = req.salt2.map_or_else(
      || req.salt.to_vec(),
      |salt2_bytes| {
         let mut buf = Vec::with_capacity(64);
         buf.extend_from_slice(req.salt);
         buf.extend_from_slice(salt2_bytes);
         buf
      },
   );
   let salt_enc = session.aes_cbc_encrypt(&salt_plain)?;
   let salt_auth = pin::hmac_truncated(session.shared_secret(), &salt_enc);
   let mut extension_entries = vec![(
      Value::Text("hmac-secret".into()),
      Value::Map(vec![
         (Value::Integer(1.into()), session.platform_cose_pubkey()?),
         (Value::Integer(2.into()), Value::Bytes(salt_enc)),
         (Value::Integer(3.into()), Value::Bytes(salt_auth.to_vec())),
         (
            Value::Integer(4.into()),
            Value::Integer(pin::PROTOCOL_V1.into()),
         ),
      ]),
   )];
   if req.request_cred_blob {
      extension_entries.push((Value::Text("credBlob".into()), Value::Bool(true)));
   }

   let assertion = call(
      transport,
      req.rp_id,
      req.client_data_hash,
      &[req.cred_id],
      Some(Value::Map(extension_entries)),
      pin_token.as_ref(),
   )?;

   if let Some(pubkey) = req.public_key {
      let mut signed = Vec::with_capacity(assertion.auth_data.len() + 32);
      signed.extend_from_slice(&assertion.auth_data);
      signed.extend_from_slice(req.client_data_hash);
      pubkey.verify(&signed, &assertion.signature)?;
   }

   let extensions = decode_extensions(&assertion.auth_data)?;
   let hmac_blob = cbor::get_text_field(&extensions, "hmac-secret")
      .and_then(Value::as_bytes)
      .ok_or(Error::MissingExtension("hmac-secret"))?;
   let cred_blob = if req.request_cred_blob {
      match cbor::get_text_field(&extensions, "credBlob") {
         Some(&Value::Bytes(ref bytes)) => Some(bytes.clone()),
         _ => None,
      }
   } else {
      None
   };

   let plaintext = session.aes_cbc_decrypt(hmac_blob)?;
   let mut first = [0_u8; 32];
   match plaintext.len() {
      32 => {
         if req.salt2.is_some() {
            return Err(Error::MissingExtension("hmac-secret salt2"));
         }
         first.copy_from_slice(&plaintext);
         Ok(HmacSecretResponse {
            secret: HmacSecret(first),
            secret2: None,
            cred_blob,
         })
      },
      64 => {
         first.copy_from_slice(&plaintext[..32]);
         let mut second = [0_u8; 32];
         second.copy_from_slice(&plaintext[32..]);
         Ok(HmacSecretResponse {
            secret: HmacSecret(first),
            secret2: Some(HmacSecret(second)),
            cred_blob,
         })
      },
      _ => {
         Err(Error::Parse(
            "hmac-secret output is neither 32 nor 64 bytes",
         ))
      },
   }
}

/// Pull the extensions CBOR map out of `authData` (`WebAuthn` §6.1):
///
/// ```text
/// rpIdHash(32) | flags(1) | signCount(4)
///   [if AT (0x40)]: aaguid(16) | credIdLen(2 BE) | credId | credPubKey(CBOR)
///   [if ED (0x80)]: extensions(CBOR map)
/// ```
fn decode_extensions(auth_data: &[u8]) -> Result<Value> {
   if auth_data.len() < AUTH_DATA_HEADER {
      return Err(Error::Parse("authData truncated before flags"));
   }
   let flags = auth_data[32];
   if flags & FLAG_ED == 0 {
      return Err(Error::MissingExtension("hmac-secret"));
   }
   let mut offset = AUTH_DATA_HEADER;
   if flags & FLAG_AT != 0 {
      if auth_data.len() < offset + ATTESTED_FIXED {
         return Err(Error::Parse("authData truncated in attested credential"));
      }
      let cred_id_len =
         u16::from_be_bytes([auth_data[offset + 16], auth_data[offset + 17]]) as usize;
      offset = offset
         .checked_add(ATTESTED_FIXED)
         .and_then(|next| next.checked_add(cred_id_len))
         .ok_or(Error::Parse("credId length overflow in authData"))?;
      if offset > auth_data.len() {
         return Err(Error::Parse("credId length exceeds authData"));
      }
      // Consume credPubKey via Cursor to advance past it. ciborium has
      // no "parse with remainder" helper.
      let mut cursor = Cursor::new(auth_data);
      cursor
         .seek(SeekFrom::Start(offset as u64))
         .map_err(|err| Error::Cbor(err.to_string()))?;
      ciborium::from_reader::<Value, _>(&mut cursor).map_err(|err| Error::Cbor(err.to_string()))?;
      offset = usize::try_from(cursor.position())
         .map_err(|_| Error::Parse("cursor position out of usize range"))?;
   }
   cbor::decode(&auth_data[offset..])
}

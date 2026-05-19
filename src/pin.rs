//! CTAP `authenticatorClientPIN`.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorClientPIN>.

use aes::{
   Aes256,
   cipher::{
      Array,
      BlockCipherDecrypt as _,
      BlockCipherEncrypt as _,
      KeyInit as _,
   },
};
use ciborium::Value;
use hmac_sha256::{
   HMAC,
   Hash,
};
use p256::{
   EncodedPoint,
   PublicKey,
   SecretKey,
   ecdh::diffie_hellman,
   elliptic_curve::{
      generic_array::GenericArray,
      rand_core::OsRng,
      sec1::{
         FromEncodedPoint as _,
         ToEncodedPoint as _,
      },
   },
};
use zeroize::Zeroize as _;

use crate::{
   cbor,
   error::{
      Error,
      Result,
   },
   hid::Transport,
};

/// `clientPin` command byte.
pub const CLIENT_PIN_COMMAND: u8 = 0x06;
/// `clientPin` subcommand: read remaining PIN retry count.
pub const GET_PIN_RETRIES: u8 = 0x01;
/// `clientPin` subcommand: ECDH key agreement.
pub const GET_KEY_AGREEMENT: u8 = 0x02;
/// `clientPin` subcommand: set the device's PIN.
pub const SET_PIN: u8 = 0x03;
/// `clientPin` subcommand: change the device's PIN.
pub const CHANGE_PIN: u8 = 0x04;
/// `clientPin` subcommand: exchange PIN for `pinUvAuthToken`.
pub const GET_PIN_TOKEN: u8 = 0x05;

/// PIN protocol v1 identifier.
pub const PROTOCOL_V1: u64 = 1;

const AES_BLOCK: usize = 16;

/// AES-256-CBC encrypt with zero IV.
fn aes256_cbc_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
   assert!(
      !plaintext.is_empty() && plaintext.len().is_multiple_of(AES_BLOCK),
      "AES-CBC plaintext must be a non-empty multiple of 16"
   );
   let cipher = Aes256::new(&Array::from(*key));
   let mut out = Vec::<u8>::with_capacity(plaintext.len());
   let mut prev = [0_u8; AES_BLOCK];
   for chunk in plaintext.chunks_exact(AES_BLOCK) {
      let mut block = [0_u8; AES_BLOCK];
      for ((dst, lhs), rhs) in block.iter_mut().zip(chunk.iter()).zip(prev.iter()) {
         *dst = *lhs ^ *rhs;
      }
      let mut arr = Array::from(block);
      cipher.encrypt_block(&mut arr);
      let bytes: [u8; AES_BLOCK] = arr.into();
      out.extend_from_slice(&bytes);
      prev = bytes;
   }
   out
}

/// AES-256-CBC decrypt with zero IV.
fn aes256_cbc_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
   assert!(
      !ciphertext.is_empty() && ciphertext.len().is_multiple_of(AES_BLOCK),
      "AES-CBC ciphertext must be a non-empty multiple of 16"
   );
   let cipher = Aes256::new(&Array::from(*key));
   let mut out = Vec::<u8>::with_capacity(ciphertext.len());
   let mut prev = [0_u8; AES_BLOCK];
   for chunk in ciphertext.chunks_exact(AES_BLOCK) {
      let mut in_block = [0_u8; AES_BLOCK];
      in_block.copy_from_slice(chunk);
      let mut arr = Array::from(in_block);
      cipher.decrypt_block(&mut arr);
      let decrypted: [u8; AES_BLOCK] = arr.into();
      let mut plain = [0_u8; AES_BLOCK];
      for ((dst, lhs), rhs) in plain.iter_mut().zip(decrypted.iter()).zip(prev.iter()) {
         *dst = *lhs ^ *rhs;
      }
      out.extend_from_slice(&plain);
      prev = in_block;
   }
   out
}

/// Returns PIN attempts remaining before the authenticator permanently blocks.
///
/// # Errors
///
/// [`Error::Ctap`](crate::Error::Ctap) if the device rejects the command,
/// [`Error::Pin`] if the response is missing or out-of-range.
pub fn get_pin_retries(transport: &mut Transport) -> Result<u8> {
   let request = Value::Map(vec![
      (Value::Integer(1.into()), Value::Integer(PROTOCOL_V1.into())),
      (
         Value::Integer(2.into()),
         Value::Integer(GET_PIN_RETRIES.into()),
      ),
   ]);
   let mut payload = Vec::<u8>::with_capacity(1 + 16);
   payload.push(CLIENT_PIN_COMMAND);
   payload.extend(cbor::encode(&request)?);

   let response = transport.transact(&payload, None)?;
   let map = cbor::decode(&response)?;
   // Field `0x03` carries the remaining-attempts integer.
   let raw: i128 = cbor::get_int_field(&map, 3)
      .and_then(Value::as_integer)
      .ok_or(Error::Pin("getPinRetries response missing pinRetries"))?
      .into();
   u8::try_from(raw).map_err(|_| Error::Pin("getPinRetries value out of u8 range"))
}

/// Per-session PIN state. Holds the AES-CBC shared secret derived from
/// `ECDH(platform_priv, authenticator_pub)` plus the platform's public
/// key for follow-up subcommands.
pub struct PinSession {
   /// 32-byte shared secret used as the AES-CBC key for `pinHashEnc` /
   /// `saltEnc` and as the HMAC-SHA256 key for `saltAuth`.
   shared_secret:   [u8; 32],
   /// Platform's P-256 public key in uncompressed `(x, y)` form.
   platform_pubkey: PublicKey,
}

impl PinSession {
   /// Run `clientPin.getKeyAgreement` and derive the shared secret.
   ///
   /// # Errors
   ///
   /// [`Error::Pin`] if the authenticator's `COSE_Key` is missing or
   /// malformed, [`Error::Ctap`](crate::Error::Ctap) on transport failure.
   pub fn establish(transport: &mut Transport) -> Result<Self> {
      let platform_secret = SecretKey::random(&mut OsRng);
      let platform_pubkey = platform_secret.public_key();

      let request = Value::Map(vec![
         (Value::Integer(1.into()), Value::Integer(PROTOCOL_V1.into())),
         (
            Value::Integer(2.into()),
            Value::Integer(GET_KEY_AGREEMENT.into()),
         ),
      ]);
      let mut payload = vec![CLIENT_PIN_COMMAND];
      payload.extend(cbor::encode(&request)?);
      let response = transport.transact(&payload, None)?;
      let map = cbor::decode(&response)?;

      // Field 1 in the response carries the authenticator's COSE_Key.
      let cose = cbor::get_int_field(&map, 1).ok_or(Error::Pin(
         "getKeyAgreement response missing key agreement field",
      ))?;
      let authenticator_pk = parse_cose_p256_pubkey(cose)?;

      let shared = diffie_hellman(
         platform_secret.to_nonzero_scalar(),
         authenticator_pk.as_affine(),
      );
      // v1 shared_secret = SHA-256(ECDH x-coordinate).
      let shared_secret = Hash::hash(shared.raw_secret_bytes());

      Ok(Self {
         shared_secret,
         platform_pubkey,
      })
   }

   /// Encrypt the PIN with AES-CBC under the shared secret and exchange
   /// it for a `pinUvAuthToken`.
   ///
   /// # Errors
   ///
   /// [`Error::Ctap`](crate::Error::Ctap) with
   /// [`CtapStatus::PinInvalid`](crate::CtapStatus::PinInvalid) or
   /// [`PinBlocked`](crate::CtapStatus::PinBlocked).
   /// [`Error::Pin`] if the encrypted token length is not a valid AES
   /// block multiple up to 48 bytes.
   pub fn get_pin_token(&self, transport: &mut Transport, pin: &str) -> Result<PinToken> {
      // pinHash = LEFT(SHA-256(pin), 16). Full digest holds the unencrypted
      // PIN hash so zeroize it explicitly once the prefix is copied out.
      let mut digest = Hash::hash(pin.as_bytes());
      let mut pin_hash = [0_u8; 16];
      pin_hash.copy_from_slice(&digest[..16]);
      digest.zeroize();

      let mut pin_hash_enc = aes256_cbc_encrypt(&self.shared_secret, &pin_hash);
      pin_hash.zeroize();

      let mut payload = vec![CLIENT_PIN_COMMAND];
      payload.extend(cbor::encode(&Value::Map(vec![
         (Value::Integer(1.into()), Value::Integer(PROTOCOL_V1.into())),
         (
            Value::Integer(2.into()),
            Value::Integer(GET_PIN_TOKEN.into()),
         ),
         (
            Value::Integer(3.into()),
            encode_platform_cose_pubkey(&self.platform_pubkey)?,
         ),
         (Value::Integer(6.into()), Value::Bytes(pin_hash_enc.clone())),
      ]))?);
      pin_hash_enc.zeroize();
      let response = transport.transact(&payload, None)?;
      let map = cbor::decode(&response)?;

      // Per CTAP2.1 the encrypted pinUvAuthToken is any AES-block multiple
      // up to 48 bytes. YubiKey ships 32.
      let encrypted = cbor::get_int_field(&map, 2)
         .and_then(Value::as_bytes)
         .ok_or(Error::Pin("getPinToken response missing token"))?;
      if encrypted.is_empty() || !encrypted.len().is_multiple_of(16) || encrypted.len() > 48 {
         return Err(Error::Pin(
            "encrypted pinUvAuthToken length must be 16, 32, or 48 bytes",
         ));
      }

      let bytes = aes256_cbc_decrypt(&self.shared_secret, encrypted);
      Ok(PinToken { bytes })
   }

   /// 32-byte shared secret. Accessor for the `get_assertion` salt
   /// encryption path which needs the same key.
   #[must_use]
   pub const fn shared_secret(&self) -> &[u8; 32] {
      &self.shared_secret
   }

   /// Platform P-256 public key in COSE form, ready to embed in a request
   /// map. The `get_assertion` `hmac-secret` extension needs this too.
   ///
   /// # Errors
   ///
   /// [`Error::Pin`] if the encoded P-256 point is missing its x/y
   /// coordinates (unreachable in practice for a freshly generated key).
   pub fn platform_cose_pubkey(&self) -> Result<Value> {
      encode_platform_cose_pubkey(&self.platform_pubkey)
   }

   /// AES-256-CBC encrypt plaintext under the session shared secret with
   /// zero IV. Plaintext must be a non-empty multiple of 16 bytes.
   ///
   /// # Errors
   ///
   /// [`Error::Pin`] if `plaintext` is empty or not a multiple of 16.
   pub fn aes_cbc_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
      if plaintext.is_empty() || !plaintext.len().is_multiple_of(16) {
         return Err(Error::Pin(
            "AES-CBC plaintext must be a non-empty multiple of 16",
         ));
      }
      Ok(aes256_cbc_encrypt(&self.shared_secret, plaintext))
   }

   /// AES-256-CBC decrypt ciphertext under the session shared secret with
   /// zero IV. Ciphertext must be a non-empty multiple of 16 bytes.
   ///
   /// # Errors
   ///
   /// [`Error::Pin`] if `ciphertext` is empty or not a multiple of 16.
   pub fn aes_cbc_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
      if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
         return Err(Error::Pin(
            "AES-CBC ciphertext must be a non-empty multiple of 16",
         ));
      }
      Ok(aes256_cbc_decrypt(&self.shared_secret, ciphertext))
   }
}

impl Drop for PinSession {
   fn drop(&mut self) {
      self.shared_secret.zeroize();
   }
}

/// Authenticator-issued `pinUvAuthToken`. The length is authenticator-chosen.
pub struct PinToken {
   bytes: Vec<u8>,
}

impl PinToken {
   /// The PIN protocol v1 `pinUvAuthParam` derivation.
   #[must_use]
   pub fn auth_param(&self, message: &[u8]) -> [u8; 16] {
      let tag = HMAC::mac(message, self.bytes.as_slice());
      let mut out = [0_u8; 16];
      out.copy_from_slice(&tag[..16]);
      out
   }
}

impl Drop for PinToken {
   fn drop(&mut self) {
      self.bytes.zeroize();
   }
}

/// COSE metadata values required by CTAP2 PIN protocol v1 (RFC 8152 / 9053).
const COSE_KTY_EC2: i128 = 2;
const COSE_ALG_ECDH_ES_HKDF_256: i128 = -25;
const COSE_CRV_P256: i128 = 1;

/// Decode a `COSE_Key` map carrying a P-256 public key (used in
/// `getKeyAgreement` responses).
fn parse_cose_p256_pubkey(cose: &Value) -> Result<PublicKey> {
   let kty: i128 = cbor::get_int_field(cose, 1)
      .and_then(Value::as_integer)
      .ok_or(Error::Pin("COSE key missing kty"))?
      .into();
   if kty != COSE_KTY_EC2 {
      return Err(Error::Pin("COSE key kty is not EC2"));
   }
   let alg: i128 = cbor::get_int_field(cose, 3)
      .and_then(Value::as_integer)
      .ok_or(Error::Pin("COSE key missing alg"))?
      .into();
   if alg != COSE_ALG_ECDH_ES_HKDF_256 {
      return Err(Error::Pin("COSE key alg is not ECDH-ES+HKDF-256"));
   }
   let crv: i128 = cbor::get_int_field(cose, -1)
      .and_then(Value::as_integer)
      .ok_or(Error::Pin("COSE key missing crv"))?
      .into();
   if crv != COSE_CRV_P256 {
      return Err(Error::Pin("COSE key crv is not P-256"));
   }
   let x_field = cbor::get_int_field(cose, -2)
      .and_then(Value::as_bytes)
      .ok_or(Error::Pin("COSE key missing x coordinate"))?;
   let y_field = cbor::get_int_field(cose, -3)
      .and_then(Value::as_bytes)
      .ok_or(Error::Pin("COSE key missing y coordinate"))?;
   if x_field.len() != 32 || y_field.len() != 32 {
      return Err(Error::Pin("COSE key coordinates wrong length"));
   }
   let encoded = EncodedPoint::from_affine_coordinates(
      GenericArray::from_slice(x_field),
      GenericArray::from_slice(y_field),
      false,
   );
   Option::<PublicKey>::from(PublicKey::from_encoded_point(&encoded))
      .ok_or(Error::Pin("authenticator pubkey is not on curve"))
}

/// Encode the platform's P-256 public key as a `COSE_Key` for inclusion
/// in `clientPin` / extension request maps.
fn encode_platform_cose_pubkey(pubkey: &PublicKey) -> Result<Value> {
   let encoded = pubkey.to_encoded_point(false);
   let x = encoded
      .x()
      .ok_or(Error::Pin("platform pubkey missing x"))?
      .to_vec();
   let y = encoded
      .y()
      .ok_or(Error::Pin("platform pubkey missing y"))?
      .to_vec();
   Ok(Value::Map(vec![
      // kty = EC2
      (Value::Integer(1.into()), Value::Integer(2.into())),
      // alg = ECDH-ES + HKDF-256 (per CTAP2 PIN protocol v1)
      (Value::Integer(3.into()), Value::Integer((-25_i32).into())),
      // crv = P-256
      (Value::Integer((-1_i32).into()), Value::Integer(1.into())),
      (Value::Integer((-2_i32).into()), Value::Bytes(x)),
      (Value::Integer((-3_i32).into()), Value::Bytes(y)),
   ]))
}

/// `HMAC-SHA256(shared_secret, data)[..16]`. Used for the `saltAuth`
/// field in the `hmac-secret` extension request.
#[must_use]
pub fn hmac_truncated(shared_secret: &[u8; 32], data: &[u8]) -> [u8; 16] {
   let tag = HMAC::mac(data, shared_secret);
   let mut out = [0_u8; 16];
   out.copy_from_slice(&tag[..16]);
   out
}

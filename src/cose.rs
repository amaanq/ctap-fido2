//! `COSE_Key` parsing for credential public keys plus signature verification.

use ciborium::Value;
use p256::{
   EncodedPoint,
   ecdsa::{
      Signature as P256Signature,
      VerifyingKey as P256VerifyingKey,
      signature::Verifier as _,
   },
   elliptic_curve::generic_array::GenericArray,
};

use crate::{
   cbor,
   error::{
      Error,
      Result,
   },
};

const COSE_KTY_OKP: i128 = 1;
const COSE_KTY_EC2: i128 = 2;
const COSE_ALG_ES256: i128 = -7;
const COSE_ALG_EDDSA: i128 = -8;
const COSE_CRV_P256: i128 = 1;
const COSE_CRV_ED25519: i128 = 6;

/// A credential public key returned by `makeCredential`. Opaque to
/// callers. Store [`Self::as_cose_bytes`] alongside the credential id and
/// hand it back at assertion time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPublicKey {
   cose_bytes: Vec<u8>,
}

impl CredentialPublicKey {
   /// CBOR-encoded `COSE_Key` bytes.
   #[must_use]
   pub fn as_cose_bytes(&self) -> &[u8] {
      &self.cose_bytes
   }

   /// Build from previously persisted COSE bytes. Validates the algorithm
   /// and key shape so a malformed blob fails here rather than at
   /// verification time.
   ///
   /// # Errors
   ///
   /// [`Error::Cbor`] if `bytes` isn't valid CBOR. [`Error::Pin`] if the
   /// COSE metadata names an unsupported algorithm or the key fields are
   /// missing.
   pub fn from_cose_bytes(bytes: Vec<u8>) -> Result<Self> {
      let value = cbor::decode(&bytes)?;
      validate(&value)?;
      Ok(Self { cose_bytes: bytes })
   }

   /// Verify `signature` over `message` with this key.
   ///
   /// # Errors
   ///
   /// [`Error::Pin`] if the signature doesn't validate or if the key
   /// algorithm is unsupported.
   pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
      let value = cbor::decode(&self.cose_bytes)?;
      let alg = cose_int(&value, 3, "COSE key missing alg")?;
      match alg {
         COSE_ALG_ES256 => verify_es256(&value, message, signature),
         COSE_ALG_EDDSA => verify_eddsa(&value, message, signature),
         _ => Err(Error::Pin("unsupported COSE algorithm")),
      }
   }
}

/// Parse the credential public key out of a `WebAuthn` `authData` blob.
///
/// Starts at `offset`  and returns the parsed key plus the new offset, which
/// lands on the extensions blob if present.
///
/// # Errors
///
/// [`Error::Cbor`] on a malformed COSE value, [`Error::Pin`] on
/// unsupported COSE metadata.
pub fn parse_authdata_pubkey(
   auth_data: &[u8],
   offset: usize,
) -> Result<(CredentialPublicKey, usize)> {
   use std::io::{
      Cursor,
      Seek as _,
      SeekFrom,
   };
   let mut cursor = Cursor::new(auth_data);
   cursor
      .seek(SeekFrom::Start(offset as u64))
      .map_err(|err| Error::Cbor(err.to_string()))?;
   let value =
      ciborium::from_reader::<Value, _>(&mut cursor).map_err(|err| Error::Cbor(err.to_string()))?;
   let consumed = usize::try_from(cursor.position())
      .map_err(|_| Error::Parse("cursor position out of usize range"))?;
   validate(&value)?;
   let mut cose_bytes = Vec::with_capacity(consumed - offset);
   cose_bytes.extend_from_slice(&auth_data[offset..consumed]);
   Ok((CredentialPublicKey { cose_bytes }, consumed))
}

fn validate(value: &Value) -> Result<()> {
   let alg = cose_int(value, 3, "COSE key missing alg")?;
   match alg {
      COSE_ALG_ES256 => {
         let kty = cose_int(value, 1, "COSE key missing kty")?;
         if kty != COSE_KTY_EC2 {
            return Err(Error::Pin("ES256 COSE key kty is not EC2"));
         }
         let crv = cose_int(value, -1, "COSE key missing crv")?;
         if crv != COSE_CRV_P256 {
            return Err(Error::Pin("ES256 COSE key crv is not P-256"));
         }
         require_bytes(value, -2, 32, "x")?;
         require_bytes(value, -3, 32, "y")?;
         Ok(())
      },
      COSE_ALG_EDDSA => {
         let kty = cose_int(value, 1, "COSE key missing kty")?;
         if kty != COSE_KTY_OKP {
            return Err(Error::Pin("EdDSA COSE key kty is not OKP"));
         }
         let crv = cose_int(value, -1, "COSE key missing crv")?;
         if crv != COSE_CRV_ED25519 {
            return Err(Error::Pin("EdDSA COSE key crv is not Ed25519"));
         }
         require_bytes(value, -2, 32, "x")?;
         Ok(())
      },
      _ => Err(Error::Pin("unsupported COSE algorithm")),
   }
}

fn verify_es256(value: &Value, message: &[u8], signature: &[u8]) -> Result<()> {
   let x = require_bytes(value, -2, 32, "x")?;
   let y = require_bytes(value, -3, 32, "y")?;
   let encoded = EncodedPoint::from_affine_coordinates(
      GenericArray::from_slice(x),
      GenericArray::from_slice(y),
      false,
   );
   let key = P256VerifyingKey::from_encoded_point(&encoded)
      .map_err(|_| Error::Pin("ES256 pubkey not on curve"))?;
   let sig = P256Signature::from_der(signature)
      .map_err(|_| Error::Pin("ES256 signature is not valid DER"))?;
   key.verify(message, &sig)
      .map_err(|_| Error::Pin("ES256 signature verification failed"))
}

fn verify_eddsa(value: &Value, message: &[u8], signature: &[u8]) -> Result<()> {
   let x = require_bytes(value, -2, 32, "x")?;
   let mut x_arr = [0_u8; 32];
   x_arr.copy_from_slice(x);
   let key = ed25519_dalek::VerifyingKey::from_bytes(&x_arr)
      .map_err(|_| Error::Pin("Ed25519 pubkey is not a valid compressed point"))?;
   if signature.len() != 64 {
      return Err(Error::Pin("Ed25519 signature is not 64 bytes"));
   }
   let mut sig_arr = [0_u8; 64];
   sig_arr.copy_from_slice(signature);
   let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
   key.verify(message, &sig)
      .map_err(|_| Error::Pin("Ed25519 signature verification failed"))
}

fn cose_int(value: &Value, key: i128, label: &'static str) -> Result<i128> {
   cbor::get_int_field(value, key)
      .and_then(Value::as_integer)
      .map(Into::into)
      .ok_or(Error::Pin(label))
}

fn require_bytes<'a>(
   value: &'a Value,
   key: i128,
   len: usize,
   label: &'static str,
) -> Result<&'a [u8]> {
   let bytes = cbor::get_int_field(value, key)
      .and_then(Value::as_bytes)
      .ok_or(Error::Pin(label))?;
   if bytes.len() != len {
      return Err(Error::Pin(label));
   }
   Ok(bytes)
}

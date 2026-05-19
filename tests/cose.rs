//! COSE parsing + signature verification tests for the parts of the
//! crate that don't require a real authenticator.

use ciborium::Value;
use ctap_fido2::{
   CredentialPublicKey,
   cbor,
};
use ed25519_dalek::Signer as _;
use p256::ecdsa::{
   Signature as P256Signature,
   SigningKey as P256SigningKey,
};
#[expect(unused_imports, reason = "needed for to_encoded_point on VerifyingKey")]
use p256::elliptic_curve::sec1::ToEncodedPoint as _;

fn build_cose_es256(x: [u8; 32], y: [u8; 32]) -> Vec<u8> {
   let map = Value::Map(vec![
      (Value::Integer(1.into()), Value::Integer(2.into())),
      (Value::Integer(3.into()), Value::Integer((-7_i32).into())),
      (Value::Integer((-1_i32).into()), Value::Integer(1.into())),
      (Value::Integer((-2_i32).into()), Value::Bytes(x.to_vec())),
      (Value::Integer((-3_i32).into()), Value::Bytes(y.to_vec())),
   ]);
   cbor::encode(&map).unwrap()
}

fn build_cose_eddsa(x: [u8; 32]) -> Vec<u8> {
   let map = Value::Map(vec![
      (Value::Integer(1.into()), Value::Integer(1.into())),
      (Value::Integer(3.into()), Value::Integer((-8_i32).into())),
      (Value::Integer((-1_i32).into()), Value::Integer(6.into())),
      (Value::Integer((-2_i32).into()), Value::Bytes(x.to_vec())),
   ]);
   cbor::encode(&map).unwrap()
}

fn fresh_es256() -> (P256SigningKey, [u8; 32], [u8; 32]) {
   let mut seed = [0_u8; 32];
   seed[31] = 1;
   let key = P256SigningKey::from_bytes(seed.as_slice().into()).unwrap();
   let point = key.verifying_key().to_encoded_point(false);
   let mut x = [0_u8; 32];
   let mut y = [0_u8; 32];
   x.copy_from_slice(point.x().unwrap());
   y.copy_from_slice(point.y().unwrap());
   (key, x, y)
}

fn fresh_eddsa() -> (ed25519_dalek::SigningKey, [u8; 32]) {
   let mut seed = [0_u8; 32];
   seed[0] = 9;
   let key = ed25519_dalek::SigningKey::from_bytes(&seed);
   let verifying = key.verifying_key();
   (key, verifying.to_bytes())
}

#[test]
fn es256_parse_accepts_valid_key() {
   let (_, x, y) = fresh_es256();
   CredentialPublicKey::from_cose_bytes(build_cose_es256(x, y)).unwrap();
}

#[test]
fn eddsa_parse_accepts_valid_key() {
   let (_, x) = fresh_eddsa();
   CredentialPublicKey::from_cose_bytes(build_cose_eddsa(x)).unwrap();
}

#[test]
fn rejects_wrong_kty_for_es256() {
   let (_, x, y) = fresh_es256();
   let map = Value::Map(vec![
      (Value::Integer(1.into()), Value::Integer(1.into())),
      (Value::Integer(3.into()), Value::Integer((-7_i32).into())),
      (Value::Integer((-1_i32).into()), Value::Integer(1.into())),
      (Value::Integer((-2_i32).into()), Value::Bytes(x.to_vec())),
      (Value::Integer((-3_i32).into()), Value::Bytes(y.to_vec())),
   ]);
   CredentialPublicKey::from_cose_bytes(cbor::encode(&map).unwrap()).unwrap_err();
}

#[test]
fn rejects_unknown_algorithm() {
   let map = Value::Map(vec![
      (Value::Integer(1.into()), Value::Integer(2.into())),
      (Value::Integer(3.into()), Value::Integer((-257_i32).into())),
      (Value::Integer((-1_i32).into()), Value::Integer(1.into())),
      (
         Value::Integer((-2_i32).into()),
         Value::Bytes(vec![0_u8; 32]),
      ),
      (
         Value::Integer((-3_i32).into()),
         Value::Bytes(vec![0_u8; 32]),
      ),
   ]);
   CredentialPublicKey::from_cose_bytes(cbor::encode(&map).unwrap()).unwrap_err();
}

#[test]
fn rejects_truncated_es256_coords() {
   let map = Value::Map(vec![
      (Value::Integer(1.into()), Value::Integer(2.into())),
      (Value::Integer(3.into()), Value::Integer((-7_i32).into())),
      (Value::Integer((-1_i32).into()), Value::Integer(1.into())),
      (
         Value::Integer((-2_i32).into()),
         Value::Bytes(vec![0_u8; 16]),
      ),
      (
         Value::Integer((-3_i32).into()),
         Value::Bytes(vec![0_u8; 32]),
      ),
   ]);
   CredentialPublicKey::from_cose_bytes(cbor::encode(&map).unwrap()).unwrap_err();
}

#[test]
fn rejects_garbage_cbor() {
   CredentialPublicKey::from_cose_bytes(vec![0xFF, 0xFF, 0xFF]).unwrap_err();
}

#[test]
fn es256_verify_round_trip() {
   let (signing_key, x, y) = fresh_es256();
   let pubkey = CredentialPublicKey::from_cose_bytes(build_cose_es256(x, y)).unwrap();
   let message = b"hello, ctap2";
   let sig: P256Signature = signing_key.sign(message);
   pubkey.verify(message, sig.to_der().as_bytes()).unwrap();
}

#[test]
fn es256_verify_rejects_wrong_message() {
   let (signing_key, x, y) = fresh_es256();
   let pubkey = CredentialPublicKey::from_cose_bytes(build_cose_es256(x, y)).unwrap();
   let sig: P256Signature = signing_key.sign(b"original");
   pubkey
      .verify(b"tampered", sig.to_der().as_bytes())
      .unwrap_err();
}

#[test]
fn es256_verify_rejects_non_der_signature() {
   let (_, x, y) = fresh_es256();
   let pubkey = CredentialPublicKey::from_cose_bytes(build_cose_es256(x, y)).unwrap();
   // Raw r||s without ASN.1 wrapping should be rejected outright.
   pubkey.verify(b"any", &[0xAB_u8; 64]).unwrap_err();
}

#[test]
fn eddsa_verify_round_trip() {
   let (signing_key, x) = fresh_eddsa();
   let pubkey = CredentialPublicKey::from_cose_bytes(build_cose_eddsa(x)).unwrap();
   let message = b"hello, ed25519";
   let sig = signing_key.sign(message);
   pubkey.verify(message, &sig.to_bytes()).unwrap();
}

#[test]
fn eddsa_verify_rejects_wrong_length() {
   let (_, x) = fresh_eddsa();
   let pubkey = CredentialPublicKey::from_cose_bytes(build_cose_eddsa(x)).unwrap();
   pubkey.verify(b"any", &[0_u8; 63]).unwrap_err();
}

#[test]
fn eddsa_verify_rejects_tampered_signature() {
   let (signing_key, x) = fresh_eddsa();
   let pubkey = CredentialPublicKey::from_cose_bytes(build_cose_eddsa(x)).unwrap();
   let mut sig = signing_key.sign(b"original").to_bytes();
   sig[0] ^= 0x01;
   pubkey.verify(b"original", &sig).unwrap_err();
}

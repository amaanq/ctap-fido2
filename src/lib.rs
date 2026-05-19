//! `ctap-fido2` - A CTAP2 client for FIDO2 `hmac-secret` over USB HID.
//!
//! Quick tour:
//! - [`enumerate`] walks attached HID devices and returns the ones that
//!   advertise the `hmac-secret` extension.
//! - [`Authenticator`] is the opened, ready-to-use handle. It is constructed
//!   via [`Authenticator::open`] from an enumerated [`DeviceInfo`].
//! - [`Authenticator::make_credential`] creates a non-discoverable credential
//!   bound to `hmac-secret`.
//! - [`Authenticator::get_hmac_secret`] runs a `getAssertion` against an
//!   existing credential and returns the 32-byte HMAC output.
//! - All errors flow through [`Error`], which preserves CTAP status bytes as
//!   typed variants.

pub mod cbor;
pub mod cmd;
pub mod cose;
pub mod enumerate;
pub mod error;
pub mod hid;
pub mod pin;

pub use crate::{
   cmd::{
      Algorithm,
      Authenticator,
      AuthenticatorInfo,
      MakeCredentialOptions,
      get_assertion::{
         Assertion,
         HmacSecretRequest,
         HmacSecretResponse,
         User,
      },
      make_credential::{
         AttestationObject,
         CredProtect,
         Credential,
         CredentialExtensions,
      },
   },
   cose::CredentialPublicKey,
   enumerate::{
      DeviceInfo,
      list_devices,
   },
   error::{
      CtapStatus,
      Error,
      Result,
   },
};

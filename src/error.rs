//! Typed errors for every CTAP status byte.

use core::fmt;
use std::{
   error::Error as StdError,
   io,
   result,
};

/// CTAP2 / CTAPHID status codes that callers might want to distinguish.
///
/// Anything besides PIN retry, credential probing, and timeout
/// handling collapses to [`CtapStatus::Other`] with the
/// raw byte.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CtapStatus {
   /// 0x00: success.
   Ok,
   /// 0x01: invalid command.
   InvalidCommand,
   /// 0x06: CTAPHID channel busy. Only ever arrives in a `CTAPHID_ERROR`
   /// frame (cmd=0xBF). Do not expect it inside a CBOR response.
   ChannelBusy,
   /// 0x11: CBOR map value had an unexpected major type.
   CborUnexpectedType,
   /// 0x12: CBOR parse failure.
   InvalidCbor,
   /// 0x13: required CBOR parameter was missing.
   MissingParameter,
   /// 0x27: operation denied (often "user touched cancel" or policy refusal).
   OperationDenied,
   /// 0x2D: in-flight operation was cancelled via `CTAPHID_CANCEL`.
   KeepaliveCancel,
   /// 0x2E: no credentials match the request.
   NoCredentials,
   /// 0x2F: user action timeout (no touch in time).
   UserActionTimeout,
   /// 0x31: PIN is invalid.
   PinInvalid,
   /// 0x32: PIN is blocked (all retries exhausted).
   PinBlocked,
   /// 0x33: pinUvAuthParam failed validation.
   PinAuthInvalid,
   /// 0x34: pinUvAuth blocked for this boot.
   PinAuthBlocked,
   /// 0x35: authenticator does not have a PIN set.
   PinNotSet,
   /// 0x36: PIN is required for this operation.
   PinRequired,
   /// 0x37: PIN policy violation (e.g. PIN too short).
   PinPolicyViolation,
   /// Any other CTAP byte.
   Other(u8),
}

impl CtapStatus {
   /// Build a status from a raw CTAP response byte.
   #[must_use]
   pub const fn from_byte(byte: u8) -> Self {
      match byte {
         0x00 => Self::Ok,
         0x01 => Self::InvalidCommand,
         0x06 => Self::ChannelBusy,
         0x11 => Self::CborUnexpectedType,
         0x12 => Self::InvalidCbor,
         0x13 => Self::MissingParameter,
         0x27 => Self::OperationDenied,
         0x2D => Self::KeepaliveCancel,
         0x2E => Self::NoCredentials,
         0x2F => Self::UserActionTimeout,
         0x31 => Self::PinInvalid,
         0x32 => Self::PinBlocked,
         0x33 => Self::PinAuthInvalid,
         0x34 => Self::PinAuthBlocked,
         0x35 => Self::PinNotSet,
         0x36 => Self::PinRequired,
         0x37 => Self::PinPolicyViolation,
         other => Self::Other(other),
      }
   }

   /// Raw byte the authenticator sent on the wire.
   #[must_use]
   pub const fn as_byte(self) -> u8 {
      match self {
         Self::Ok => 0x00,
         Self::InvalidCommand => 0x01,
         Self::ChannelBusy => 0x06,
         Self::CborUnexpectedType => 0x11,
         Self::InvalidCbor => 0x12,
         Self::MissingParameter => 0x13,
         Self::OperationDenied => 0x27,
         Self::KeepaliveCancel => 0x2D,
         Self::NoCredentials => 0x2E,
         Self::UserActionTimeout => 0x2F,
         Self::PinInvalid => 0x31,
         Self::PinBlocked => 0x32,
         Self::PinAuthInvalid => 0x33,
         Self::PinAuthBlocked => 0x34,
         Self::PinNotSet => 0x35,
         Self::PinRequired => 0x36,
         Self::PinPolicyViolation => 0x37,
         Self::Other(byte) => byte,
      }
   }
}

impl From<u8> for CtapStatus {
   fn from(byte: u8) -> Self {
      Self::from_byte(byte)
   }
}

impl From<CtapStatus> for u8 {
   fn from(status: CtapStatus) -> Self {
      status.as_byte()
   }
}

impl fmt::Display for CtapStatus {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "CTAP status 0x{:02X}", self.as_byte())
   }
}

/// Top-level error type.
#[derive(Debug)]
pub enum Error {
   /// The authenticator returned a non-success CTAP status.
   Ctap(CtapStatus),
   /// An hmac-secret extension was requested but the device didn't return one.
   MissingExtension(&'static str),
   /// The host couldn't reach the device (USB / HID I/O).
   Io(io::Error),
   /// hidapi error during enumeration or open.
   Hid(String),
   /// CBOR encoding/decoding failure.
   Cbor(String),
   /// PIN protocol step produced an unexpected result.
   Pin(&'static str),
   /// A response field had an unexpected type or shape.
   Parse(&'static str),
}

impl fmt::Display for Error {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match *self {
         Self::Ctap(ref status) => write!(f, "{status}"),
         Self::MissingExtension(name) => write!(f, "device omitted required extension: {name}"),
         Self::Io(ref err) => write!(f, "hid io: {err}"),
         Self::Hid(ref msg) => write!(f, "hidapi: {msg}"),
         Self::Cbor(ref msg) => write!(f, "cbor: {msg}"),
         Self::Pin(msg) => write!(f, "pin protocol: {msg}"),
         Self::Parse(msg) => write!(f, "parse: {msg}"),
      }
   }
}

impl StdError for Error {
   fn source(&self) -> Option<&(dyn StdError + 'static)> {
      match *self {
         Self::Io(ref err) => Some(err),
         _ => None,
      }
   }
}

impl From<io::Error> for Error {
   fn from(err: io::Error) -> Self {
      Self::Io(err)
   }
}

/// Crate-wide result alias.
pub type Result<T> = result::Result<T, Error>;

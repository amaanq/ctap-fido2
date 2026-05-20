//! `ctap-fido2` is a CTAP2 client for FIDO2 `hmac-secret` over USB HID.
//!
//! Typically, one might want to use the following:
//! - [`device::list_devices`] to enumerate eligible authenticators.
//! - [`device::DeviceInfo`] for the descriptor of each.
//! - [`cmd::Authenticator::open`] to acquire an open handle.
//! - [`cmd::Authenticator::make_credential`] and
//!   [`cmd::Authenticator::get_hmac_secret`] for the headline operations.
//! - [`error::Error`] / [`error::Result`] / [`error::CtapStatus`] for the typed
//!   error tree.
//!
//! The following modules are also exposed:
//! - [`cose`] — [`CredentialPublicKey`](`cose::CredentialPublicKey`) and
//!   signature verification.
//! - [`hid`] — [`Transport`](`hid::Transport`) for raw CTAPHID frames and
//!   [`hid::Transport::vendor_command`] for vendor-specific probes.
//! - [`pin`] — [`PinSession`](`pin::PinSession`) /
//!   [`PinToken`](`pin::PinToken`) for callers building their own PIN-protected
//!   commands on top of [`hid::Transport`].
//! - [`cbor`] — CBOR helpers used by the command parsers.

pub mod cbor;
pub mod cmd;
pub mod cose;
pub mod device;
pub mod error;
pub mod hid;
pub mod pin;

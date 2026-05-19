//! `authenticatorGetNextAssertion` (CTAP2 0x08).
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetNextAssertion>.

use crate::{
   cmd::get_assertion::{
      Assertion,
      parse_response,
   },
   error::Result,
   hid::Transport,
};

/// CTAP2 command byte for `authenticatorGetNextAssertion`.
pub const COMMAND: u8 = 0x08;

/// Retrieve the next assertion in a multi-credential getAssertion sequence.
///
/// Call once per remaining credential after the initial `getAssertion`
/// response reports `number_of_credentials > 1`. This must be issued on the
/// same authenticator and within the device's idle timeout.
///
/// # Errors
///
/// [`Error::Ctap`](crate::Error::Ctap) with
/// [`CtapStatus::NotAllowed`](crate::CtapStatus::Other) if invoked outside
/// the spec's allowed sequence, plus the usual transport / CBOR errors.
pub fn call(transport: &mut Transport) -> Result<Assertion> {
   let response = transport.transact(&[COMMAND], None)?;
   parse_response(&response)
}

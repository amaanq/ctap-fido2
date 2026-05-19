//! `authenticatorReset` (CTAP2 command `0x07`).
//!
//! Wipes every credential, the PIN, and most internal state on the device.
//! There is no parameter map; the wire payload is just the command byte.

use crate::{
   error::Result,
   hid::Transport,
};

/// CTAP2 command byte for `authenticatorReset`.
pub const COMMAND: u8 = 0x07;

/// Issue `authenticatorReset`.
///
/// Most authenticators enforce two constraints the caller has to meet:
/// the command must arrive within ~10 seconds of the device being
/// plugged in, and the user must touch the device within ~30 seconds of
/// the command being received. Outside either window the device returns
/// a CTAP error and refuses the reset.
///
/// # Errors
///
/// [`Error::Ctap`](crate::Error::Ctap) if the device rejects the reset
/// (e.g. outside the insertion window or no touch within the grace).
pub fn call(transport: &mut Transport) -> Result<()> {
   transport.transact(&[COMMAND], None)?;
   Ok(())
}

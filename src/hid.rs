//! CTAP-HID transport. Owns the `hidapi::HidDevice` and negotiated CID;
//! exposes [`Transport::transact`] for CBOR commands.
//!
//! Spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb>.

use std::{
   ffi::CString,
   time::Duration,
};

use hidapi::{
   HidApi,
   HidDevice,
};
use rand::Rng as _;

use crate::error::{
   CtapStatus,
   Error,
   Result,
};

/// CTAPHID command bytes.
pub mod cmd {
   /// `CTAPHID_INIT`: channel allocation handshake.
   pub const CTAPHID_INIT: u8 = 0x86;
   /// `CTAPHID_CBOR`: wraps a CTAP2 CBOR-encoded command.
   pub const CTAPHID_CBOR: u8 = 0x90;
   /// `CTAPHID_CANCEL`: cancels an in-flight operation.
   pub const CTAPHID_CANCEL: u8 = 0x91;
   /// `CTAPHID_WINK`: blink/buzz the device. Optional per spec.
   pub const CTAPHID_WINK: u8 = 0x88;
   /// `CTAPHID_KEEPALIVE`: heartbeat during user-presence waits.
   pub const CTAPHID_KEEPALIVE: u8 = 0xBB;
   /// `CTAPHID_ERROR`: transport-level error frame.
   pub const CTAPHID_ERROR: u8 = 0xBF;
}

/// Fixed CTAPHID frame size.
pub const REPORT_SIZE: usize = 64;

const BROADCAST_CID: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// Backstop for a wedged device. Real timing is driven by KEEPALIVE frames.
const READ_TIMEOUT: Duration = Duration::from_mins(1);

const INIT_FRAME_DATA: usize = REPORT_SIZE - 7;
const CONT_FRAME_DATA: usize = REPORT_SIZE - 5;
const MAX_PAYLOAD: usize = INIT_FRAME_DATA + 128 * CONT_FRAME_DATA;

/// Opened CTAP-HID transport ready to issue commands.
pub struct Transport {
   device: HidDevice,
   cid:    [u8; 4],
}

impl Transport {
   /// Open `path` and run `CTAPHID_INIT` to allocate a channel.
   ///
   /// # Errors
   ///
   /// [`Error::Hid`] if `hidapi` can't open the device, [`Error::Parse`]
   /// if the INIT response is malformed.
   pub fn open(path: &str) -> Result<Self> {
      log::trace!("Transport::open path={path}");
      let api = HidApi::new().map_err(|err| Error::Hid(err.to_string()))?;
      let cpath = CString::new(path).map_err(|err| Error::Hid(format!("bad path: {err}")))?;
      let device = api
         .open_path(&cpath)
         .map_err(|err| Error::Hid(err.to_string()))?;

      // No `set_blocking_mode(true)`: makes hidapi non-interruptible on
      // Linux and swallows Ctrl-C. `read_timeout` works regardless.
      let mut transport = Self {
         device,
         cid: BROADCAST_CID,
      };
      transport.cid = transport.allocate_channel()?;
      log::trace!("Transport::open ok cid={:02x?}", transport.cid);
      Ok(transport)
   }

   /// Send a CBOR command, return the response body with the CTAP status
   /// byte stripped. Non-zero status becomes [`Error::Ctap`].
   ///
   /// `on_keepalive` fires per `KEEPALIVE` frame so callers can prompt
   /// "touch your security key…" only once the device starts asking.
   ///
   /// # Errors
   ///
   /// [`Error::Ctap`] on a non-zero CTAP status from the device,
   /// [`Error::Hid`] on transport failure, [`Error::Parse`] on a malformed
   /// frame.
   pub fn transact(
      &mut self,
      payload: &[u8],
      on_keepalive: Option<&mut dyn FnMut(KeepAlive)>,
   ) -> Result<Vec<u8>> {
      self.send_message(cmd::CTAPHID_CBOR, payload)?;
      let mut body = self.recv_message(cmd::CTAPHID_CBOR, on_keepalive)?;
      let status_byte = body
         .first()
         .copied()
         .ok_or(Error::Parse("CBOR response missing status byte"))?;
      let status = CtapStatus::from_byte(status_byte);
      if status == CtapStatus::Ok {
         body.drain(..1);
         Ok(body)
      } else {
         Err(Error::Ctap(status))
      }
   }

   /// Blink/buzz the device. Optional per spec. Devices without it return
   /// [`Error::Ctap`] with an invalid-command status.
   ///
   /// # Errors
   ///
   /// [`Error::Ctap`] if the device doesn't implement `CTAPHID_WINK`,
   /// [`Error::Hid`] on transport failure.
   pub fn wink(&mut self) -> Result<()> {
      self.send_message(cmd::CTAPHID_WINK, &[])?;
      self.recv_message(cmd::CTAPHID_WINK, None)?;
      Ok(())
   }

   /// Fire-and-forget `CTAPHID_CANCEL`. The device surfaces the cancel as
   /// [`CtapStatus::KeepaliveCancel`] on the in-flight command's reply,
   /// not as a reply to this frame.
   ///
   /// # Errors
   ///
   /// [`Error::Hid`] if the underlying HID write fails.
   pub fn cancel(&self) -> Result<()> {
      self.send_message(cmd::CTAPHID_CANCEL, &[])
   }

   /// Run `CTAPHID_INIT` and parse the assigned CID.
   fn allocate_channel(&self) -> Result<[u8; 4]> {
      let mut nonce = [0_u8; 8];
      rand::rng().fill_bytes(&mut nonce);
      log::trace!("allocate_channel: sending INIT nonce={nonce:02x?}");

      self.send_message(cmd::CTAPHID_INIT, &nonce)?;
      let body = self.recv_message(cmd::CTAPHID_INIT, None)?;
      log::trace!("allocate_channel: INIT body len={} ", body.len());
      if body.len() < 17 {
         return Err(Error::Parse("INIT response too short"));
      }
      if body[0..8] != nonce {
         return Err(Error::Parse("INIT response nonce mismatch"));
      }
      Ok([body[8], body[9], body[10], body[11]])
   }

   /// Fragment `payload` into one init frame and zero or more continuation
   /// frames and write them to the device.
   fn send_message(&self, command: u8, payload: &[u8]) -> Result<()> {
      log::trace!(
         "send_message cid={:02x?} cmd=0x{:02x} bcnt={}",
         self.cid,
         command,
         payload.len()
      );
      if payload.len() > MAX_PAYLOAD {
         return Err(Error::Parse(
            "payload exceeds CTAPHID wire ceiling (7609 bytes)",
         ));
      }
      let bcnt =
         u16::try_from(payload.len()).map_err(|_| Error::Parse("payload exceeds u16 BCNT"))?;

      let (init_chunk, mut rest) = payload.split_at(payload.len().min(INIT_FRAME_DATA));
      let mut frame = [0_u8; REPORT_SIZE + 1];
      // Byte 0 is the HID report id (0 for FIDO authenticators).
      frame[1..5].copy_from_slice(&self.cid);
      frame[5] = command;
      frame[6..8].copy_from_slice(&bcnt.to_be_bytes());
      frame[8..8 + init_chunk.len()].copy_from_slice(init_chunk);
      self.write_frame(&frame)?;

      let mut seq: u8 = 0;
      while !rest.is_empty() {
         let (chunk, tail) = rest.split_at(rest.len().min(CONT_FRAME_DATA));
         rest = tail;
         frame.fill(0);
         frame[1..5].copy_from_slice(&self.cid);
         frame[5] = seq & 0x7F;
         frame[6..6 + chunk.len()].copy_from_slice(chunk);
         self.write_frame(&frame)?;
         seq = seq.wrapping_add(1);
      }
      Ok(())
   }

   fn recv_message(
      &self,
      expected_cmd: u8,
      mut on_keepalive: Option<&mut dyn FnMut(KeepAlive)>,
   ) -> Result<Vec<u8>> {
      log::trace!(
         "recv_message: waiting for cid={:02x?} expected_cmd=0x{:02x}",
         self.cid,
         expected_cmd
      );
      loop {
         let frame = self.read_frame()?;
         log::trace!(
            "recv_message: got frame cid={:02x?} cmd=0x{:02x} bcnt={}",
            &frame[0..4],
            frame[4],
            u16::from_be_bytes([frame[5], frame[6]])
         );
         if frame[0..4] != self.cid {
            // Stray frame for another channel, ignore.
            log::trace!("recv_message: cid mismatch, skipping");
            continue;
         }
         let cmd_byte = frame[4];
         match cmd_byte {
            byte if byte == cmd::CTAPHID_KEEPALIVE => {
               if let Some(keepalive) = on_keepalive.as_mut() {
                  keepalive(KeepAlive::from_byte(frame[7]));
               }
               continue;
            },
            byte if byte == cmd::CTAPHID_ERROR => {
               let status = CtapStatus::from_byte(frame[7]);
               return Err(Error::Ctap(status));
            },
            byte if byte == expected_cmd => {},
            _ => return Err(Error::Parse("unexpected CTAPHID command byte in response")),
         }
         let bcnt = u16::from_be_bytes([frame[5], frame[6]]) as usize;
         let mut body = Vec::<u8>::with_capacity(bcnt);
         let init_take = bcnt.min(INIT_FRAME_DATA);
         body.extend_from_slice(&frame[7..7 + init_take]);

         let mut seq = 0_u8;
         while body.len() < bcnt {
            let cont = self.read_frame()?;
            if cont[0..4] != self.cid {
               continue;
            }
            if cont[4] & 0x80 != 0 {
               return Err(Error::Parse(
                  "expected CTAPHID continuation frame, got init",
               ));
            }
            if cont[4] != seq {
               return Err(Error::Parse("CTAPHID continuation sequence skew"));
            }
            let remaining = bcnt - body.len();
            let take = remaining.min(CONT_FRAME_DATA);
            body.extend_from_slice(&cont[5..5 + take]);
            seq = seq.wrapping_add(1);
         }
         return Ok(body);
      }
   }

   fn write_frame(&self, frame: &[u8; REPORT_SIZE + 1]) -> Result<()> {
      let written = self
         .device
         .write(frame)
         .map_err(|err| Error::Hid(err.to_string()))?;
      if written != frame.len() {
         return Err(Error::Hid(format!(
            "short HID write: {written} of {}",
            frame.len()
         )));
      }
      Ok(())
   }

   fn read_frame(&self) -> Result<[u8; REPORT_SIZE]> {
      log::trace!("read_frame: blocking on read_timeout");
      let mut buf = [0_u8; REPORT_SIZE];
      let read = self
         .device
         .read_timeout(
            &mut buf,
            i32::try_from(READ_TIMEOUT.as_millis()).unwrap_or(i32::MAX),
         )
         .map_err(|err| Error::Hid(err.to_string()))?;
      log::trace!("read_frame: returned {read} bytes");
      if read == 0 {
         return Err(Error::Hid("HID read timed out".into()));
      }
      if read != REPORT_SIZE {
         return Err(Error::Hid(format!(
            "short HID read: {read} of {REPORT_SIZE}"
         )));
      }
      Ok(buf)
   }
}

/// Keep-alive payload from the authenticator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeepAlive {
   /// 0x01. Authenticator is busy processing.
   Processing,
   /// 0x02. Authenticator is waiting for the user to touch the sensor.
   UserPresenceNeeded,
   /// Any other byte the spec doesn't define.
   Other(u8),
}

impl KeepAlive {
   /// Decode a single keep-alive byte from a `CTAPHID_KEEPALIVE` frame.
   #[must_use]
   pub const fn from_byte(byte: u8) -> Self {
      match byte {
         0x01 => Self::Processing,
         0x02 => Self::UserPresenceNeeded,
         other => Self::Other(other),
      }
   }
}

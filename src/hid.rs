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
   device:           HidDevice,
   cid:              [u8; 4],
   firmware_version: (u8, u8, u8),
}

struct InitResponse {
   cid:              [u8; 4],
   firmware_version: (u8, u8, u8),
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

      let init = ctaphid_init(&device)?;
      log::trace!("Transport::open ok cid={:02x?}", init.cid);
      Ok(Self {
         device,
         cid: init.cid,
         firmware_version: init.firmware_version,
      })
   }

   /// Firmware version reported in the `CTAPHID_INIT` response that ran
   /// during [`Self::open`]. The tuple is presented as `(major, minor, build)`.
   #[must_use]
   pub const fn firmware_version(&self) -> (u8, u8, u8) {
      self.firmware_version
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

   /// Send a CTAPHID vendor command (`0xC0..=0xFF`) and return the raw
   /// response body. The argument is the **wire byte** — i.e. the
   /// init-frame command field with bit 7 already set. Yubico's logical
   /// `CTAP_VENDOR_FIRST + N` is wire byte `0xC0 + N`; `SoloKey`'s
   /// `SOLO_VERSION` (logical `0x53`) is wire byte `0xD3`; and so on.
   ///
   /// `KEEPALIVE` frames are drained automatically. The returned bytes
   /// are whatever the device put in the response body — vendors define
   /// their own framing inside.
   ///
   /// # Errors
   ///
   /// [`Error::Hid`] on transport failure, [`Error::Parse`] on a
   /// malformed CTAPHID response, or an `Error::Parse("CTAPHID command
   /// mismatch")`-equivalent if the device replies with a different
   /// command byte than the caller asked for.
   pub fn vendor_command(&self, command: u8, payload: &[u8]) -> Result<Vec<u8>> {
      if command & 0x80 == 0 {
         return Err(Error::Parse(
            "vendor_command requires an init-frame command byte (bit 7 set)",
         ));
      }
      self.send_message(command, payload)?;
      self.recv_message(command, None)
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

      let mut seq = 0_u8;
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
      write_hid_frame(&self.device, frame)
   }

   fn read_frame(&self) -> Result<[u8; REPORT_SIZE]> {
      read_hid_frame(&self.device)
   }
}

/// Raw HID write of one CTAPHID frame.
fn write_hid_frame(device: &HidDevice, frame: &[u8; REPORT_SIZE + 1]) -> Result<()> {
   let written = device
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

/// Raw HID read of one CTAPHID frame, with the standard read timeout.
fn read_hid_frame(device: &HidDevice) -> Result<[u8; REPORT_SIZE]> {
   log::trace!("read_hid_frame: blocking on read_timeout");
   let mut buf = [0_u8; REPORT_SIZE];
   let read = device
      .read_timeout(
         &mut buf,
         i32::try_from(READ_TIMEOUT.as_millis()).unwrap_or(i32::MAX),
      )
      .map_err(|err| Error::Hid(err.to_string()))?;
   log::trace!("read_hid_frame: returned {read} bytes");
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

/// Run `CTAPHID_INIT` directly against a freshly opened `HidDevice`,
/// without requiring a partially-built [`Transport`]. INIT request and
/// response both fit in a single 64-byte report, so we don't need the
/// full send/recv machinery here. Response layout: `nonce(8) | cid(4) |
/// protocol(1) | major(1) | minor(1) | build(1) | capabilities(1)`.
fn ctaphid_init(device: &HidDevice) -> Result<InitResponse> {
   let mut nonce = [0_u8; 8];
   rand::rng().fill_bytes(&mut nonce);
   log::trace!("ctaphid_init: sending INIT nonce={nonce:02x?}");

   let mut frame = [0_u8; REPORT_SIZE + 1];
   frame[1..5].copy_from_slice(&BROADCAST_CID);
   frame[5] = cmd::CTAPHID_INIT;
   frame[6..8].copy_from_slice(&8_u16.to_be_bytes());
   frame[8..16].copy_from_slice(&nonce);
   write_hid_frame(device, &frame)?;

   loop {
      let resp = read_hid_frame(device)?;
      if resp[0..4] != BROADCAST_CID {
         continue;
      }
      if resp[4] != cmd::CTAPHID_INIT {
         return Err(Error::Parse(
            "unexpected CTAPHID command byte in INIT response",
         ));
      }
      let bcnt = u16::from_be_bytes([resp[5], resp[6]]) as usize;
      if bcnt < 17 {
         return Err(Error::Parse("INIT response too short"));
      }
      let body = &resp[7..7 + bcnt.min(REPORT_SIZE - 7)];
      if body[0..8] != nonce {
         return Err(Error::Parse("INIT response nonce mismatch"));
      }
      return Ok(InitResponse {
         cid:              [body[8], body[9], body[10], body[11]],
         firmware_version: (body[13], body[14], body[15]),
      });
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

impl From<u8> for KeepAlive {
   fn from(byte: u8) -> Self {
      Self::from_byte(byte)
   }
}

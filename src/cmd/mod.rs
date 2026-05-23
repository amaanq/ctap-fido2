//! Public-facing command API. Submodules carry the wire encoding/parsing.

use ciborium::Value;
use zeroize::ZeroizeOnDrop;

use crate::{
   cmd::{
      get_assertion::{
         Assertion,
         HmacSecretRequest,
         HmacSecretResponse,
      },
      make_credential::{
         CredProtect,
         Credential,
      },
   },
   device::DeviceInfo,
   error::Result,
   hid::Transport,
   pin::{
      self,
      PinSession,
      PinToken,
   },
};

pub mod get_assertion;
pub mod get_info;
pub mod get_next_assertion;
pub mod make_credential;
pub mod reset;

/// COSE algorithms this crate will ask the authenticator for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
   /// ECDSA P-256 / SHA-256, COSE `-7`.
   Es256,
   /// `EdDSA` Ed25519, COSE `-8`.
   EdDsa,
}

impl Algorithm {
   /// Wire-level COSE algorithm identifier.
   #[must_use]
   pub const fn cose_id(self) -> i32 {
      match self {
         Self::Es256 => -7,
         Self::EdDsa => -8,
      }
   }
}

impl From<Algorithm> for i32 {
   fn from(alg: Algorithm) -> Self {
      alg.cose_id()
   }
}

/// Parsed `authenticatorGetInfo` response.
///
/// Fields mirror the CTAP2.1 spec; absent values are `None`/empty.
#[derive(Clone, Debug, Default)]
pub struct AuthenticatorInfo {
   /// `versions` (0x01) — protocol versions, e.g. `"FIDO_2_0"`, `"FIDO_2_1"`.
   pub versions:                           Vec<String>,
   /// `extensions` (0x02) — extension names the device understands.
   pub extensions:                         Vec<String>,
   /// `aaguid` (0x03) — 16-byte authenticator model identifier.
   pub aaguid:                             [u8; 16],
   /// `options` (0x04) — capability flags such as `rk`, `up`, `uv`, `plat`,
   /// `clientPin`. Missing keys mean the option isn't supported.
   pub options:                            Vec<(String, bool)>,
   /// `maxMsgSize` (0x05).
   pub max_msg_size:                       Option<u32>,
   /// `pinProtocols` (0x06) — PIN protocol versions supported, ordered by
   /// device preference. Empty if `clientPin` is unsupported.
   pub pin_protocols:                      Vec<u8>,
   /// `maxCredentialCountInList` (0x07).
   pub max_credential_count_in_list:       Option<u32>,
   /// `maxCredentialIdLength` (0x08).
   pub max_credential_id_length:           Option<u32>,
   /// `transports` (0x09) — `"usb"`, `"nfc"`, `"ble"`, `"internal"`.
   pub transports:                         Vec<String>,
   /// `algorithms` (0x0A) — COSE algorithm ids the device will sign with.
   pub algorithms:                         Vec<i32>,
   /// `maxSerializedLargeBlobArray` (0x0B).
   pub max_serialized_large_blob_array:    Option<u32>,
   /// `forcePINChange` (0x0C).
   pub force_pin_change:                   bool,
   /// `minPINLength` (0x0D).
   pub min_pin_length:                     Option<u32>,
   /// `firmwareVersion` (0x0E).
   pub firmware_version:                   Option<u32>,
   /// `maxCredBlobLength` (0x0F).
   pub max_cred_blob_length:               Option<u32>,
   /// `maxRPIDsForSetMinPINLength` (0x10).
   pub max_rp_ids_for_set_min_pin_length:  Option<u32>,
   /// `preferredPlatformUvAttempts` (0x11).
   pub preferred_platform_uv_attempts:     Option<u32>,
   /// `uvModality` (0x12).
   pub uv_modality:                        Option<u32>,
   /// `remainingDiscoverableCredentials` (0x14).
   pub remaining_discoverable_credentials: Option<u32>,
}

impl AuthenticatorInfo {
   /// Read a named option, returning `None` if the device didn't advertise it.
   #[must_use]
   pub fn option(&self, name: &str) -> Option<bool> {
      self
         .options
         .iter()
         .find_map(|&(ref stored_key, value)| (stored_key == name).then_some(value))
   }

   /// True iff a client PIN is currently set on the device.
   #[must_use]
   pub fn client_pin_set(&self) -> bool {
      self.option("clientPin").unwrap_or(false)
   }

   /// True iff the device advertises the `hmac-secret` extension.
   #[must_use]
   pub fn hmac_secret(&self) -> bool {
      self.extensions.iter().any(|name| name == "hmac-secret")
   }

   /// True iff the device accepts PIN protocol v1 commands. CTAP2.0 devices
   /// that don't advertise `pinProtocols` are treated as v1.
   #[must_use]
   pub fn supports_pin_protocol_v1(&self) -> bool {
      self.pin_protocols.is_empty() || self.pin_protocols.contains(&1)
   }

   /// True iff the device advertises PIN protocol v2. The crate does not
   /// implement v2 yet; this is exposed so callers can detect v2-only
   /// devices and fail early rather than time out on a v1 exchange.
   #[must_use]
   pub fn supports_pin_protocol_v2(&self) -> bool {
      self.pin_protocols.contains(&2)
   }
}

/// Options for [`Authenticator::make_credential`].
#[derive(Clone, Debug)]
pub struct MakeCredentialOptions<'a> {
   /// Algorithm to request.
   pub algorithm:      Algorithm,
   /// `None` disables UV too. UV-scoped hmac-secret outputs would break
   /// interop with the Go `age-plugin-fido2-hmac`.
   pub pin:            Option<&'a str>,
   /// Ask the device to create a resident (discoverable) credential.
   pub resident_key:   bool,
   /// `credProtect` policy level to apply to the credential. `None`
   /// leaves the device's default in place.
   pub cred_protect:   Option<CredProtect>,
   /// Up to 32 bytes of arbitrary data to store on the device alongside
   /// the credential. Retrievable on every assertion without a second
   /// touch.
   pub cred_blob:      Option<&'a [u8]>,
   /// Request the per-credential large-blob key from the device. Returned
   /// in [`Credential::large_blob_key`] when the device supports the
   /// extension.
   pub large_blob_key: bool,
   /// Ask the device to report its current `minPinLength` value in the
   /// extensions echo.
   pub min_pin_length: bool,
}

impl Default for MakeCredentialOptions<'_> {
   fn default() -> Self {
      Self {
         algorithm:      Algorithm::Es256,
         pin:            None,
         resident_key:   false,
         cred_protect:   None,
         cred_blob:      None,
         large_blob_key: false,
         min_pin_length: false,
      }
   }
}

/// 32-byte hmac-secret output.
#[derive(ZeroizeOnDrop)]
pub struct HmacSecret(pub [u8; 32]);

/// Open CTAP2 authenticator handle.
pub struct Authenticator {
   pub(crate) transport: Transport,
   pub(crate) info:      Option<AuthenticatorInfo>,
}

impl Authenticator {
   /// Open a device returned by
   /// [`list_devices`](crate::device::list_devices). Runs `CTAPHID_INIT`
   /// to allocate a channel id.
   ///
   /// # Errors
   ///
   /// [`Error::Hid`] if `hidapi` can't open the path, [`Error::Parse`] if
   /// the INIT response is malformed.
   pub fn open(info: &DeviceInfo) -> Result<Self> {
      let transport = Transport::open(&info.path)?;
      Ok(Self {
         transport,
         info: None,
      })
   }

   /// Borrow the underlying [`Transport`] for raw CTAPHID exchanges.
   pub const fn transport_mut(&mut self) -> &mut Transport {
      &mut self.transport
   }

   /// Firmware version reported in the `CTAPHID_INIT` response that ran
   /// during [`Self::open`]. Tuple is `(major, minor, build)`.
   #[must_use]
   pub const fn firmware_version(&self) -> (u8, u8, u8) {
      self.transport.firmware_version()
   }

   /// Cached `authenticatorGetInfo`, fetched on first call.
   ///
   /// # Errors
   ///
   /// Whatever [`get_info::call`] propagates: [`Error::Ctap`],
   /// [`Error::Hid`], [`Error::Cbor`].
   pub fn info(&mut self) -> Result<&AuthenticatorInfo> {
      if let Some(ref info) = self.info {
         return Ok(info);
      }
      let fresh = get_info::call(&mut self.transport)?;
      Ok(self.info.insert(fresh))
   }

   /// Create a non-discoverable credential bound to `hmac-secret`.
   /// Returns the credential id and public key. Persist both: the public
   /// key is required to verify assertion signatures via
   /// [`Self::get_hmac_secret`].
   ///
   /// # Errors
   ///
   /// PIN/touch/policy failures from CTAP, plus the transport and CBOR
   /// errors from the lower layers.
   pub fn make_credential(
      &mut self,
      rp_id: &str,
      client_data_hash: &[u8; 32],
      opts: &MakeCredentialOptions<'_>,
   ) -> Result<Credential> {
      make_credential::call(&mut self.transport, rp_id, client_data_hash, opts)
   }

   /// Remaining PIN attempts. Does not consume one.
   ///
   /// # Errors
   ///
   /// [`Error::Ctap`] if the device rejects `clientPIN.getPinRetries`, or
   /// [`Error::Pin`] if the response is missing the retry count.
   pub fn pin_retries(&mut self) -> Result<u8> {
      pin::get_pin_retries(&mut self.transport)
   }

   /// Return the 32-byte `hmac-secret` output(s) for the given request.
   /// When `req.salt2` is `Some`, the second slot of the returned tuple
   /// holds the second output. When `None`, the second slot is `None`.
   ///
   /// # Errors
   ///
   /// Same as [`Self::make_credential`], plus
   /// [`CtapStatus::NoCredentials`](crate::CtapStatus::NoCredentials)
   /// when `req.cred_id` is unknown to the device, and
   /// [`Error::MissingExtension`] when a salt2 was requested but the
   /// device returned a single-output response.
   pub fn get_hmac_secret(&mut self, req: &HmacSecretRequest<'_>) -> Result<HmacSecretResponse> {
      get_assertion::call_hmac_secret(&mut self.transport, req)
   }

   /// Fetch the next assertion in a multi-credential sequence. Call once
   /// per remaining credential after [`Self::get_assertion`] returns an
   /// [`Assertion`] with `number_of_credentials > 1`.
   ///
   /// # Errors
   ///
   /// Forwards from [`get_next_assertion::call`].
   pub fn get_next_assertion(&mut self) -> Result<Assertion> {
      get_next_assertion::call(&mut self.transport)
   }

   /// Run `getAssertion`. Empty `allow_list` triggers resident-credential
   /// discovery. `extensions` is a CBOR map of `{name: input}`.
   ///
   /// # Errors
   ///
   /// Forwards from [`get_assertion::call`].
   pub fn get_assertion(
      &mut self,
      rp_id: &str,
      client_data_hash: &[u8; 32],
      allow_list: &[&[u8]],
      extensions: Option<Value>,
      pin: Option<&str>,
   ) -> Result<Assertion> {
      let pin_token = match pin {
         Some(value) => {
            let session = PinSession::establish(&mut self.transport)?;
            Some(session.get_pin_token(&mut self.transport, value)?)
         },
         None => None,
      };
      get_assertion::call(
         &mut self.transport,
         rp_id,
         client_data_hash,
         allow_list,
         extensions,
         pin_token.as_ref(),
      )
   }

   /// Silent (`up=false`) allow-list probe: returns the matching
   /// credential id without touch, or [`None`] when the device has none
   /// of the candidates. Callers follow up with a touch-requiring
   /// assertion (e.g. [`Self::get_hmac_secret`]) to derive the secret.
   ///
   /// # Errors
   ///
   /// CTAP statuses other than `NoCredentials` propagate via
   /// [`Error::Ctap`]. Older firmware rejects `up=false` outright;
   /// callers should fall back to per-credential probing.
   pub fn probe_credential(
      &mut self,
      rp_id: &str,
      client_data_hash: &[u8; 32],
      allow_list: &[&[u8]],
   ) -> Result<Option<Vec<u8>>> {
      use crate::{
         cmd::get_assertion::AssertionOptions,
         error::{
            CtapStatus,
            Error,
         },
      };
      match get_assertion::call_with_options(
         &mut self.transport,
         rp_id,
         client_data_hash,
         allow_list,
         None,
         None,
         AssertionOptions::SILENT,
      ) {
         Ok(assertion) => Ok(assertion.credential_id),
         Err(Error::Ctap(CtapStatus::NoCredentials)) => Ok(None),
         Err(other) => Err(other),
      }
   }

   /// Establish a PIN session for amortizing one ECDH across multiple commands.
   ///
   /// # Errors
   ///
   /// [`Error::Pin`] if the authenticator's `COSE_Key` is malformed,
   /// [`Error::Ctap`] for transport failures.
   pub fn pin_session(&mut self) -> Result<PinSession> {
      PinSession::establish(&mut self.transport)
   }

   /// Exchange a PIN for a `pinUvAuthToken` within an established session.
   ///
   /// # Errors
   ///
   /// [`Error::Ctap`] with
   /// [`CtapStatus::PinInvalid`](crate::CtapStatus::PinInvalid)
   /// or [`PinBlocked`](crate::CtapStatus::PinBlocked).
   pub fn pin_token(&mut self, session: &PinSession, pin: &str) -> Result<PinToken> {
      session.get_pin_token(&mut self.transport, pin)
   }

   /// Blink/buzz the device so the user can identify it. Optional per spec.
   ///
   /// # Errors
   ///
   /// [`Error::Ctap`] with an invalid-command status on devices that don't
   /// implement `CTAPHID_WINK`.
   pub fn wink(&mut self) -> Result<()> {
      self.transport.wink()
   }

   /// Fire-and-forget `CTAPHID_CANCEL`. Cannot interrupt your own in-flight
   /// `transact`. Intended for signal handlers and `Drop` paths.
   ///
   /// # Errors
   ///
   /// [`Error::Hid`] if the underlying HID write fails.
   pub fn cancel(&self) -> Result<()> {
      self.transport.cancel()
   }

   /// **Destructive: wipes all credentials and the PIN.**
   ///
   /// Devices typically require the command within ~10s of insertion and
   /// touch within ~30s of the command.
   ///
   /// # Errors
   ///
   /// [`Error::Ctap`] if the device rejects the reset (outside the
   /// 10s-since-insertion window, or no touch within the 30s grace).
   pub fn reset(&mut self) -> Result<()> {
      reset::call(&mut self.transport)
   }
}

//! USB HID enumeration. Filters by FIDO usage page and `hmac-secret`
//! extension support. Probe handles close before [`list_devices`] returns.

use hidapi::HidApi;

use crate::{
   cmd::get_info,
   error::{
      Error,
      Result,
   },
   hid::Transport,
};

/// FIDO authenticator HID usage page.
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;
/// FIDO usage within the FIDO usage page.
pub const FIDO_USAGE: u16 = 0x0001;

/// Metadata about a discovered authenticator.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
   /// `hidraw` path on Linux or platform-specific opaque path elsewhere.
   pub path:           String,
   /// USB vendor id.
   pub vendor_id:      u16,
   /// USB product id.
   pub product_id:     u16,
   /// Manufacturer-provided product string, when set.
   pub product_string: Option<String>,
   /// Manufacturer-assigned serial number, when the device exposes one.
   pub serial_number:  Option<String>,
}

/// List authenticators advertising `hmac-secret`. Devices that fail to
/// open or `getInfo` are silently skipped.
///
/// # Errors
///
/// [`Error::Hid`] if `hidapi` initialization itself fails. Per-device
/// failures are logged at `debug` and skipped.
pub fn list_devices() -> Result<Vec<DeviceInfo>> {
   let api = HidApi::new().map_err(|err| Error::Hid(err.to_string()))?;
   let mut out = Vec::<DeviceInfo>::new();
   for raw in api.device_list() {
      if raw.usage_page() != FIDO_USAGE_PAGE || raw.usage() != FIDO_USAGE {
         continue;
      }
      let Some(path) = raw.path().to_str().ok().map(str::to_owned) else {
         continue;
      };
      let mut transport = match Transport::open(&path) {
         Ok(transport) => transport,
         Err(err) => {
            log::debug!("enumerate: Transport::open({path}) failed: {err}");
            continue;
         },
      };
      let info = match get_info::call(&mut transport) {
         Ok(info) => info,
         Err(err) => {
            log::debug!("enumerate: get_info({path}) failed: {err}");
            continue;
         },
      };
      if !info.hmac_secret() {
         continue;
      }
      out.push(DeviceInfo {
         path,
         vendor_id: raw.vendor_id(),
         product_id: raw.product_id(),
         product_string: raw.product_string().map(str::to_owned),
         serial_number: raw.serial_number().map(str::to_owned),
      });
   }
   Ok(out)
}

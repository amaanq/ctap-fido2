# ctap-fido2

A CTAP2 client for FIDO2 over USB HID.

This crate allows one to enumerate HID authenticators, create credentials, run assertions, and read the `hmac-secret` extension.

On the TODO list is bio enrollment, credential management, large blobs, U2F, and PIN protocol v2.

## Example

```rust
use ctap_fido2::{Authenticator, MakeCredentialOptions};

let info = ctap_fido2::list_devices()?
    .into_iter()
    .next()
    .expect("plug a security key in first");
let mut auth = Authenticator::open(&info)?;

let cdh = [0xAB; 32];
let credential = auth.make_credential("example.com", &cdh, &MakeCredentialOptions::default())?;
// Persist `credential.id` and `credential.public_key.as_cose_bytes()` together.

let salt = [0xCD; 32];
let secret = auth.get_hmac_secret(
    "example.com",
    &cdh,
    &credential.id,
    &salt,
    None,
    Some(&credential.public_key),
)?;
// `secret.0` is the 32-byte hmac-secret output, zeroized on drop.
# Ok::<(), ctap_fido2::Error>(())
```

Pass `None` for the PIN only on keys without one set.

## Debugging

`ctap-fido2` uses the `log` crate, so setting `RUST_LOG=ctap_fido2=trace` with any backend installed gets you frame-level
chatter.

## Hardware

This crate has been tested against a YubiKey 5C, however any CTAP2.1 authenticator with `hmac-secret` should work.

## License

`ctap-fido2` is licensed under the MIT license.

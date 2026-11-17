//! Derive an ed25519 SSH signing key from a security key's `hmac-secret` and
//! hold it in ssh-agent for a few minutes, so one touch signs a whole push.
//!
//! - `fido2-sign enroll` creates the resident credential on the plugged-in key
//!   you touch and prints its derived public key.
//! - `fido2-sign unlock [SECONDS]` derives the key on the first plugged-in key
//!   holding the credential, loads it into ssh-agent with that lifetime and
//!   prints the public key.

use std::{
   env,
   fs::File,
   io::{
      self,
      BufRead as _,
      BufReader,
      Read as _,
      Write as _,
   },
   os::unix::net::UnixStream,
   sync::atomic::{
      AtomicBool,
      Ordering,
   },
   thread,
};

use base64::{
   Engine as _,
   engine::general_purpose::STANDARD,
};
use ctap_fido2::{
   cmd::{
      Authenticator,
      InfoOption,
      MakeCredentialOptions,
      get_assertion::HmacSecretRequest,
   },
   device::list_devices,
};
use ed25519_dalek::SigningKey;
use eyre::{
   WrapErr as _,
   bail,
   eyre,
};
use hmac_sha256::Hash;
use rustix::{
   process::{
      DumpableBehavior,
      set_dumpable_behavior,
   },
   termios::{
      LocalModes,
      OptionalActions,
      tcgetattr,
      tcsetattr,
   },
};
use zeroize::Zeroizing;

const RELYING_PARTY: &str = "ssh:git-sign";
const DEFAULT_LIFETIME_SECS: u32 = 300;
const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
const SSH_AGENT_SUCCESS: u8 = 6;

enum Command {
   Enroll,
   Unlock { lifetime_secs: u32 },
}

impl Command {
   fn from_args() -> eyre::Result<Self> {
      let mut args = env::args().skip(1);
      match args.next().as_deref() {
         Some("enroll") => Ok(Self::Enroll),
         Some("unlock") => {
            let lifetime_secs = args
               .next()
               .map(|secs| secs.parse::<u32>())
               .transpose()
               .wrap_err("SECONDS must be a whole number")?
               .unwrap_or(DEFAULT_LIFETIME_SECS);
            Ok(Self::Unlock { lifetime_secs })
         },
         _ => bail!("usage: fido2-sign enroll | fido2-sign unlock [SECONDS]"),
      }
   }
}

fn main() -> eyre::Result<()> {
   color_eyre::install()?;
   set_dumpable_behavior(DumpableBehavior::NotDumpable).wrap_err("mark process non-dumpable")?;

   match Command::from_args()? {
      Command::Enroll => enroll(),
      Command::Unlock { lifetime_secs } => unlock(lifetime_secs),
   }
}

fn salt() -> [u8; 32] {
   Hash::hash(b"ctap-fido2 git signing key v1")
}

fn client_data_hash() -> [u8; 32] {
   let mut cdh = [0_u8; 32];
   rand::fill(&mut cdh);
   cdh
}

/// Open every plugged-in authenticator, paired with its resident credential
/// id when it has one. The probe is silent, so it costs no touch.
fn authenticators() -> eyre::Result<Vec<(Authenticator, Option<Vec<u8>>)>> {
   list_devices()?
      .iter()
      .map(|info| {
         let mut auth = Authenticator::open(info)?;
         let cred = auth.probe_credential(RELYING_PARTY, &client_data_hash(), &[])?;
         Ok((auth, cred))
      })
      .collect()
}

fn derive_key(auth: &mut Authenticator, cred_id: &[u8]) -> eyre::Result<SigningKey> {
   let response = auth.get_hmac_secret(&HmacSecretRequest {
      rp_id: RELYING_PARTY,
      client_data_hash: &client_data_hash(),
      cred_id,
      salt: &salt(),
      salt2: None,
      pin: None,
      public_key: None,
      request_cred_blob: false,
   })?;
   Ok(SigningKey::from_bytes(&response.secret.0))
}

fn public_key_line(key: &SigningKey) -> String {
   let mut blob = Vec::new();
   put_string(&mut blob, b"ssh-ed25519");
   put_string(&mut blob, key.verifying_key().as_bytes());
   format!("ssh-ed25519 {} git-sign", STANDARD.encode(blob))
}

fn enroll() -> eyre::Result<()> {
   let candidates = authenticators()?
      .into_iter()
      .filter_map(|(auth, cred)| cred.is_none().then_some(auth))
      .collect::<Vec<_>>();
   let mut auth = match candidates.len() {
      0 => bail!("every plugged-in key already has a git-sign credential"),
      1 => candidates.into_iter().next().expect("one candidate"),
      _ => pick_by_touch(candidates)?,
   };

   let pin = if auth.info()?.option(InfoOption::ClientPin) == Some(true) {
      Some(read_pin("PIN: ")?)
   } else {
      None
   };

   eprintln!("Touch the key to create the credential...");
   let credential =
      auth.make_credential(RELYING_PARTY, &client_data_hash(), &MakeCredentialOptions {
         pin: pin.as_deref().map(String::as_str),
         resident_key: true,
         ..MakeCredentialOptions::default()
      })?;

   eprintln!("Touch it again to derive the signing key...");
   let key = derive_key(&mut auth, &credential.id)?;
   println!("{}", public_key_line(&key));
   Ok(())
}

fn pick_by_touch(candidates: Vec<Authenticator>) -> eyre::Result<Authenticator> {
   eprintln!("Touch the key to enroll...");
   let cancelled = AtomicBool::new(false);
   let outcomes = thread::scope(|scope| {
      let handles = candidates
         .into_iter()
         .map(|auth| {
            let cancelled = &cancelled;
            scope.spawn(move || {
               let touched = auth.select(cancelled);
               if matches!(touched, Ok(true)) {
                  cancelled.store(true, Ordering::Relaxed);
               }
               (auth, touched)
            })
         })
         .collect::<Vec<_>>();
      handles
         .into_iter()
         .map(|handle| handle.join().expect("selection thread panicked"))
         .collect::<Vec<_>>()
   });

   let mut errors = Vec::new();
   for (auth, touched) in outcomes {
      match touched {
         Ok(true) => return Ok(auth),
         Ok(false) => {},
         Err(err) => errors.push(err.to_string()),
      }
   }
   bail!("no key was selected: {}", errors.join(", "))
}

fn unlock(lifetime_secs: u32) -> eyre::Result<()> {
   let (mut auth, cred_id) = authenticators()?
      .into_iter()
      .find_map(|(auth, cred)| cred.map(|id| (auth, id)))
      .ok_or_else(|| {
         eyre!("no plugged-in key has a git-sign credential, run `fido2-sign enroll`")
      })?;

   let key = derive_key(&mut auth, &cred_id)?;
   add_to_agent(&key, lifetime_secs)?;
   println!("{}", public_key_line(&key));
   Ok(())
}

fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
   buf.extend_from_slice(
      &u32::try_from(bytes.len())
         .expect("ssh string fits u32")
         .to_be_bytes(),
   );
   buf.extend_from_slice(bytes);
}

/// `SSH_AGENTC_ADD_ID_CONSTRAINED` with a lifetime, per
/// draft-ietf-sshm-ssh-agent §3.2 and §3.2.7.1.
fn add_to_agent(key: &SigningKey, lifetime_secs: u32) -> eyre::Result<()> {
   let socket = env::var_os("SSH_AUTH_SOCK").ok_or_else(|| eyre!("SSH_AUTH_SOCK is not set"))?;
   let public = key.verifying_key().to_bytes();
   let mut keypair = Zeroizing::new([0_u8; 64]);
   keypair[..32].copy_from_slice(key.as_bytes());
   keypair[32..].copy_from_slice(&public);

   let mut body = Zeroizing::new(vec![SSH_AGENTC_ADD_ID_CONSTRAINED]);
   put_string(&mut body, b"ssh-ed25519");
   put_string(&mut body, &public);
   put_string(&mut body, keypair.as_slice());
   put_string(&mut body, b"git-sign");
   body.push(SSH_AGENT_CONSTRAIN_LIFETIME);
   body.extend_from_slice(&lifetime_secs.to_be_bytes());

   let mut message = Zeroizing::new(Vec::with_capacity(body.len() + 4));
   put_string(&mut message, &body);

   let mut stream = UnixStream::connect(&socket).wrap_err("connect to ssh-agent")?;
   stream.write_all(&message)?;

   let mut len = [0_u8; 4];
   stream.read_exact(&mut len)?;
   let mut reply = vec![0_u8; u32::from_be_bytes(len) as usize];
   stream.read_exact(&mut reply)?;
   if reply.first() != Some(&SSH_AGENT_SUCCESS) {
      bail!("ssh-agent refused the key");
   }
   Ok(())
}

fn read_pin(prompt: &str) -> eyre::Result<Zeroizing<String>> {
   let tty = File::options()
      .read(true)
      .write(true)
      .open("/dev/tty")
      .wrap_err("open /dev/tty")?;
   let saved = tcgetattr(&tty)?;
   let mut silent = saved.clone();
   silent.local_modes.remove(LocalModes::ECHO);
   tcsetattr(&tty, OptionalActions::Now, &silent)?;

   let mut pin = Zeroizing::new(String::new());
   let read = (&tty)
      .write_all(prompt.as_bytes())
      .and_then(|()| BufReader::new(&tty).read_line(&mut pin));
   tcsetattr(&tty, OptionalActions::Now, &saved)?;
   (&tty).write_all(b"\n")?;
   read?;

   let trimmed = pin.trim_end_matches(['\r', '\n']).len();
   pin.truncate(trimmed);
   if pin.is_empty() {
      return Err(io::Error::other("empty PIN").into());
   }
   Ok(pin)
}

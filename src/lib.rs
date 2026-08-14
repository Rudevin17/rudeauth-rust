//! RudeAuth client SDK.
//!
//! The client embeds only an application id and an Ed25519 public key. Every
//! response is signed and verified against that key before any field of it is
//! trusted, so a patched binary cannot be talked into a forged "success", and
//! there is deliberately no function that returns a bool meaning "is licensed":
//! [`Client::authenticate`] returns a [`Session`] or an [`Error`], and the gating
//! calls exist only on a `Session`.
//!
//! ```no_run
//! use rudeauth::{Client, Error};
//!
//! # fn run() -> Result<(), Error> {
//! // app_id and public_key come from `rudeauth-cli app create`.
//! let client = Client::new("app-id", "base64-public-key", "https://api.example.com")?;
//! let session = client.authenticate("user-entered-key")?;
//! let offset = session.variable("offset")?;
//! let core = session.file("core.dll")?;
//! # let _ = (offset, core);
//! # Ok(())
//! # }
//! ```

mod client;
mod crypto;
mod errors;
mod fingerprint;
mod session;
mod wire;

pub use client::{request_device_reset, Client};
pub use errors::Error;
pub use session::Session;
pub use wire::LicenseInfo;

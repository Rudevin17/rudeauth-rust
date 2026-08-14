use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::crypto;
use crate::errors::Error;
use crate::session::Session;
use crate::wire::{DeviceResetPayload, Envelope, HandshakePayload};

const MIN_COMPONENTS: usize = 2;
const MAX_CLOCK_SKEW: i64 = 300;
const MAX_RESPONSE_BYTES: u64 = 64 << 20; // encrypted files can be large

/// The shared HTTP + verify core, held behind an Arc so a Session can keep using
/// it (for gating calls and the heartbeat) after `authenticate` returns.
pub(crate) struct Inner {
    agent: ureq::Agent,
    pub(crate) app_id: String,
    public_key: [u8; 32],
    base_url: String,
    app_version: String,
}

impl Inner {
    /// Post `body` and return the VERIFIED payload bytes. There is no path through
    /// this function that yields unverified data.
    pub(crate) fn call_endpoint(
        &self,
        path: &str,
        endpoint: &str,
        body: serde_json::Value,
    ) -> Result<Vec<u8>, Error> {
        let url = format!("{}{}", self.base_url, path);
        let payload = serde_json::to_vec(&body).map_err(|_| Error::BadResponse)?;

        let response = match self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_bytes(&payload)
        {
            Ok(resp) => resp,
            // A non-200 carries no signed envelope, so nothing about it can be trusted.
            Err(ureq::Error::Status(_, _)) => return Err(Error::BadResponse),
            Err(_) => return Err(Error::Network),
        };

        let mut raw = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut raw)
            .map_err(|_| Error::Network)?;

        let env: Envelope = serde_json::from_slice(&raw).map_err(|_| Error::BadResponse)?;
        let data = b64_decode(&env.data)?;
        let sig = b64_decode(&env.signature)?;
        if data.is_empty() || sig.is_empty() {
            return Err(Error::BadResponse);
        }

        // STEP ONE, before anything is parsed: the bytes must be signed by the key
        // pinned into this client. Everything downstream depends on it, and there
        // is no flag to skip it.
        if !crypto::verify(&self.public_key, endpoint, &data, &sig) {
            return Err(Error::SignatureInvalid);
        }
        Ok(data)
    }
}

/// Holds the pinned public key and talks to one RudeAuth server.
pub struct Client {
    inner: Arc<Inner>,
    collect: Box<dyn Fn() -> Vec<String> + Send + Sync>,
    label: Box<dyn Fn() -> String + Send + Sync>,
}

impl Client {
    /// Build a client. `app_id` and `public_key_b64` come from
    /// `rudeauth-cli app create`; both are safe to embed, because the public key
    /// verifies responses and cannot forge them.
    pub fn new(app_id: &str, public_key_b64: &str, base_url: &str) -> Result<Client, Error> {
        let bytes = b64_decode(public_key_b64)
            .map_err(|_| Error::Config("public key is not valid base64".into()))?;
        let public_key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Config("public key must be a 32-byte Ed25519 key".into()))?;

        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(20))
            .build();

        Ok(Client {
            inner: Arc::new(Inner {
                agent,
                app_id: app_id.to_string(),
                public_key,
                base_url: base_url.trim_end_matches('/').to_string(),
                app_version: "1.0.0".to_string(),
            }),
            collect: Box::new(crate::fingerprint::collect),
            label: Box::new(crate::fingerprint::label),
        })
    }

    /// Override the `app_version` reported to the server. Call before `authenticate`.
    pub fn with_app_version(mut self, version: &str) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.app_version = version.to_string();
        }
        self
    }

    /// Perform the handshake and return a live [`Session`], or an error. A rejected
    /// licence is a specific [`Error`], never a bool.
    pub fn authenticate(&self, license_key: &str) -> Result<Session, Error> {
        let components = (self.collect)();
        if components.len() < MIN_COMPONENTS {
            // Refusing beats sending a weak identity the server would have to accept.
            return Err(Error::Config(format!(
                "could not read enough hardware components ({}, need {})",
                components.len(),
                MIN_COMPONENTS
            )));
        }

        let (eph_pub, eph_priv) = crypto::ephemeral();
        let nonce_b64 = b64_encode(&crypto::random_nonce());

        let body = serde_json::json!({
            "app_id": self.inner.app_id,
            "app_version": self.inner.app_version,
            "license_key": license_key,
            "fingerprint_components": components,
            "fingerprint_label": (self.label)(),
            "client_nonce": nonce_b64,
            "eph_pubkey": b64_encode(&eph_pub),
            "sent_at": now_unix(),
        });

        let data = self
            .inner
            .call_endpoint("/v1/handshake", "handshake", body)?;
        let hs: HandshakePayload = serde_json::from_slice(&data).map_err(|_| Error::BadResponse)?;

        // The echoed nonce proves this response was produced for THIS request and
        // is not a recording of an earlier one.
        if hs.client_nonce != nonce_b64 {
            return Err(Error::NonceMismatch);
        }
        if hs.server_time > 0 {
            let delta = now_unix() - hs.server_time;
            if delta > MAX_CLOCK_SKEW || delta < -MAX_CLOCK_SKEW {
                return Err(Error::ClockSkew);
            }
        }
        if !hs.success {
            return Err(Error::from_wire(&hs.error));
        }

        let server_eph = b64_decode(&hs.server_eph_pubkey)?;
        let key = crypto::derive_session_key(&eph_priv, &server_eph, &hs.session_id)
            .ok_or(Error::BadResponse)?;
        let info = hs.license.unwrap_or_default();

        Ok(Session::new(
            Arc::clone(&self.inner),
            hs.session_token,
            key,
            info,
            hs.session_expires_at,
        ))
    }

    /// Test-only hook to inject a deterministic fingerprint instead of reading
    /// real hardware.
    #[cfg(test)]
    pub(crate) fn with_fingerprint(
        mut self,
        collect: impl Fn() -> Vec<String> + Send + Sync + 'static,
        label: impl Fn() -> String + Send + Sync + 'static,
    ) -> Self {
        self.collect = Box::new(collect);
        self.label = Box::new(label);
        self
    }
}

/// Unbind a licence from its machines so it can be moved. The server bounds this
/// by cooldown and lifetime cap; the client cannot.
pub fn request_device_reset(
    app_id: &str,
    public_key_b64: &str,
    base_url: &str,
    license_key: &str,
) -> Result<(), Error> {
    let client = Client::new(app_id, public_key_b64, base_url)?;
    let body = serde_json::json!({ "app_id": app_id, "license_key": license_key });
    let data = client
        .inner
        .call_endpoint("/v1/device/reset", "device_reset", body)?;
    let dr: DeviceResetPayload = serde_json::from_slice(&data).map_err(|_| Error::BadResponse)?;
    if !dr.success {
        return Err(Error::from_wire(&dr.error));
    }
    Ok(())
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, Error> {
    STANDARD.decode(s).map_err(|_| Error::BadResponse)
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use std::thread;

    fn envelope(sk: &SigningKey, endpoint: &str, payload: Value) -> String {
        let data = serde_json::to_vec(&payload).unwrap();
        let sig = sk.sign(&crypto::signing_input(endpoint, &data));
        json!({
            "data": STANDARD.encode(&data),
            "signature": STANDARD.encode(sig.to_bytes()),
        })
        .to_string()
    }

    fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> String {
        let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).unwrap();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        STANDARD.encode(blob)
    }

    /// An in-process server that signs and seals exactly as the real one does, so
    /// the SDK verifies real signatures and opens real payloads.
    fn spawn_server(seed: [u8; 32], fail: Option<String>) -> String {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        thread::spawn(move || {
            let sk = SigningKey::from_bytes(&seed);
            let session_key = Mutex::new([0u8; 32]);
            for mut request in server.incoming_requests() {
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                let req: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let out = handle(&sk, &session_key, &fail, &request.url().to_string(), &req);
                let _ = request.respond(tiny_http::Response::from_string(out));
            }
        });
        url
    }

    fn handle(
        sk: &SigningKey,
        session_key: &Mutex<[u8; 32]>,
        fail: &Option<String>,
        path: &str,
        req: &Value,
    ) -> String {
        match path {
            "/v1/handshake" => {
                if let Some(code) = fail {
                    return envelope(
                        sk,
                        "handshake",
                        json!({
                            "success": false,
                            "client_nonce": req["client_nonce"],
                            "server_time": now_unix(),
                            "error": code,
                        }),
                    );
                }
                let client_eph = STANDARD
                    .decode(req["eph_pubkey"].as_str().unwrap())
                    .unwrap();
                let (server_pub, server_priv) = crypto::ephemeral();
                let session_id = "test-session-0001";
                let key =
                    crypto::derive_session_key(&server_priv, &client_eph, session_id).unwrap();
                *session_key.lock().unwrap() = key;
                envelope(
                    sk,
                    "handshake",
                    json!({
                        "success": true,
                        "client_nonce": req["client_nonce"],
                        "server_time": now_unix(),
                        "session_token": "tok",
                        "session_expires_at": now_unix() + 3600,
                        "session_id": session_id,
                        "server_eph_pubkey": STANDARD.encode(server_pub),
                        "license": {"level": 1, "expires_at": 0, "devices_used": 1, "max_devices": 1},
                    }),
                )
            }
            "/v1/variables" => {
                let key = *session_key.lock().unwrap();
                let sealed = seal(&key, br#"{"offset":"0x4A1F","tier":"gold"}"#, b"variables");
                envelope(
                    sk,
                    "variables",
                    json!({ "success": true, "sealed": sealed }),
                )
            }
            "/v1/files" => {
                let key = *session_key.lock().unwrap();
                let name = req["name"].as_str().unwrap_or("");
                let sealed = seal(&key, b"core-dll-bytes", format!("files:{name}").as_bytes());
                envelope(
                    sk,
                    "files",
                    json!({ "success": true, "version": 1, "sealed": sealed }),
                )
            }
            "/v1/heartbeat" => envelope(
                sk,
                "heartbeat",
                json!({ "valid": true, "expires_at": now_unix() + 3600 }),
            ),
            _ => envelope(sk, "unknown", json!({ "error": "not found" })),
        }
    }

    fn test_client(pub_b64: &str, url: &str, components: Vec<&'static str>) -> Client {
        Client::new("app", pub_b64, url).unwrap().with_fingerprint(
            move || components.iter().map(|s| s.to_string()).collect(),
            || "test-box".into(),
        )
    }

    #[test]
    fn authenticate_and_gating() {
        let seed = [7u8; 32];
        let pub_b64 = STANDARD.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let url = spawn_server(seed, None);

        let client = test_client(&pub_b64, &url, vec!["test:cpu", "test:disk"]);
        let session = client.authenticate("RUDE-KEY").unwrap();

        assert_eq!(session.info().max_devices, 1);
        assert_eq!(session.info().level, 1);
        assert_eq!(session.variable("offset").unwrap(), "0x4A1F");
        assert_eq!(session.file("core.dll").unwrap(), b"core-dll-bytes");
    }

    #[test]
    fn rejects_forged_signature() {
        let url = spawn_server([1u8; 32], None);
        let other_pub = STANDARD.encode(
            SigningKey::from_bytes(&[2u8; 32])
                .verifying_key()
                .to_bytes(),
        );

        let client = test_client(&other_pub, &url, vec!["a", "b"]);
        assert!(matches!(
            client.authenticate("k"),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn maps_licence_error() {
        let seed = [3u8; 32];
        let pub_b64 = STANDARD.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let url = spawn_server(seed, Some("LICENSE_EXPIRED".into()));

        let client = test_client(&pub_b64, &url, vec!["a", "b"]);
        assert!(matches!(
            client.authenticate("k"),
            Err(Error::LicenseExpired)
        ));
    }

    #[test]
    fn refuses_weak_fingerprint() {
        let seed = [4u8; 32];
        let pub_b64 = STANDARD.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let url = spawn_server(seed, None);

        let client = test_client(&pub_b64, &url, vec!["only-one"]);
        assert!(matches!(client.authenticate("k"), Err(Error::Config(_))));
    }
}

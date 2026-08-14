use std::collections::HashMap;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::client::{b64_decode, now_unix, Inner};
use crate::crypto;
use crate::errors::Error;
use crate::wire::{GatingPayload, HeartbeatPayload, LicenseInfo, WebhookPayload};

struct State {
    key: [u8; 32],
    expires_at: i64,
    closed: bool,
}

/// An authenticated, live connection to the server. It heartbeats on its own
/// thread from construction. Dropping it (or calling [`Session::close`]) stops the
/// heartbeat and zeroes the session key.
pub struct Session {
    inner: Arc<Inner>,
    token: String,
    info: LicenseInfo,
    state: Arc<Mutex<State>>,
    stop_tx: mpsc::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl Session {
    pub(crate) fn new(
        inner: Arc<Inner>,
        token: String,
        key: [u8; 32],
        info: LicenseInfo,
        expires_at: i64,
    ) -> Session {
        let state = Arc::new(Mutex::new(State {
            key,
            expires_at,
            closed: false,
        }));
        let (stop_tx, stop_rx) = mpsc::channel();

        let hb_inner = Arc::clone(&inner);
        let hb_state = Arc::clone(&state);
        let hb_token = token.clone();
        let hb_app_id = inner.app_id.clone();
        let handle = thread::spawn(move || {
            beat_loop(hb_inner, hb_app_id, hb_token, hb_state, stop_rx);
        });

        Session {
            inner,
            token,
            info,
            state,
            stop_tx,
            handle: Some(handle),
        }
    }

    /// What the server reported about the licence at handshake.
    pub fn info(&self) -> LicenseInfo {
        self.info.clone()
    }

    /// A server-side value, fetched fresh. There is no cache and no fallback: a
    /// cached "last known good" value is exactly what an attacker induces by
    /// blocking the network.
    pub fn variable(&self, name: &str) -> Result<String, Error> {
        let body = serde_json::json!({
            "app_id": self.inner.app_id,
            "session_token": self.token,
        });
        let data = self.sealed_call("/v1/variables", "variables", body, b"variables")?;
        let vars: HashMap<String, String> =
            serde_json::from_slice(&data).map_err(|_| Error::BadResponse)?;
        vars.get(name)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("no such variable: {name}")))
    }

    /// A decrypted payload that never shipped inside your binary.
    pub fn file(&self, name: &str) -> Result<Vec<u8>, Error> {
        let body = serde_json::json!({
            "app_id": self.inner.app_id,
            "session_token": self.token,
            "name": name,
        });
        let aad = format!("files:{name}");
        self.sealed_call("/v1/files", "files", body, aad.as_bytes())
    }

    /// Ask the server to call one of your configured endpoints, so the URL never
    /// appears in your binary.
    pub fn webhook(&self, name: &str, params: &HashMap<String, String>) -> Result<String, Error> {
        let body = serde_json::json!({
            "app_id": self.inner.app_id,
            "session_token": self.token,
            "name": name,
            "params": params,
        });
        let data = self.inner.call_endpoint("/v1/webhook", "webhook", body)?;
        let wp: WebhookPayload = serde_json::from_slice(&data).map_err(|_| Error::BadResponse)?;
        if !wp.success {
            return Err(Error::from_wire(&wp.error));
        }
        let decoded = b64_decode(&wp.body)?;
        String::from_utf8(decoded).map_err(|_| Error::BadResponse)
    }

    /// Stop the heartbeat and zero the session key. Safe to call more than once.
    pub fn close(&mut self) {
        let _ = self.stop_tx.send(());
        {
            let mut st = self.state.lock().unwrap();
            st.closed = true;
            st.key = [0u8; 32];
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    fn sealed_call(
        &self,
        path: &str,
        endpoint: &str,
        body: serde_json::Value,
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let data = self.inner.call_endpoint(path, endpoint, body)?;
        let gp: GatingPayload = serde_json::from_slice(&data).map_err(|_| Error::BadResponse)?;
        if !gp.success {
            return Err(Error::from_wire(&gp.error));
        }
        let sealed = b64_decode(&gp.sealed)?;

        // Lock only for the key access, not the HTTP call above.
        let st = self.state.lock().unwrap();
        if st.closed {
            return Err(Error::SessionExpired);
        }
        crypto::open_sealed(&st.key, &sealed, aad).ok_or(Error::BadResponse)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// Keep the session alive. A missed beat is NOT a logout: it retries until the
/// TTL genuinely lapses, so a brief network blip does not drop a paying customer.
fn beat_loop(
    inner: Arc<Inner>,
    app_id: String,
    token: String,
    state: Arc<Mutex<State>>,
    stop_rx: mpsc::Receiver<()>,
) {
    loop {
        let remaining = {
            let st = state.lock().unwrap();
            st.expires_at - now_unix()
        };
        let wait = if remaining > 4 {
            Duration::from_secs((remaining / 2) as u64)
        } else {
            Duration::from_secs(2)
        };

        match stop_rx.recv_timeout(wait) {
            Ok(_) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {}
        }

        let body = serde_json::json!({ "app_id": app_id, "session_token": token });
        if let Ok(data) = inner.call_endpoint("/v1/heartbeat", "heartbeat", body) {
            if let Ok(hp) = serde_json::from_slice::<HeartbeatPayload>(&data) {
                if hp.valid && hp.expires_at > 0 {
                    state.lock().unwrap().expires_at = hp.expires_at;
                }
            }
        }
    }
}

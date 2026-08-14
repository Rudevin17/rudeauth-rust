//! Response types, mirroring the server's wire format exactly. The signature is
//! verified over the raw bytes and only then are they parsed into these structs.

use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Envelope {
    pub(crate) data: String,      // base64
    pub(crate) signature: String, // base64 Ed25519
}

/// What the server reports about the licence at handshake.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct LicenseInfo {
    #[serde(default)]
    pub level: i32,
    /// Unix seconds; 0 means perpetual.
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub devices_used: i32,
    #[serde(default)]
    pub max_devices: i32,
}

#[derive(Deserialize)]
pub(crate) struct HandshakePayload {
    #[serde(default)]
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) client_nonce: String,
    #[serde(default)]
    pub(crate) server_time: i64,
    #[serde(default)]
    pub(crate) session_token: String,
    #[serde(default)]
    pub(crate) session_expires_at: i64,
    #[serde(default)]
    pub(crate) session_id: String,
    #[serde(default)]
    pub(crate) server_eph_pubkey: String,
    pub(crate) license: Option<LicenseInfo>,
    #[serde(default)]
    pub(crate) error: String,
}

#[derive(Deserialize)]
pub(crate) struct GatingPayload {
    #[serde(default)]
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) sealed: String, // base64
    #[allow(dead_code)]
    #[serde(default)]
    pub(crate) version: i32,
    #[serde(default)]
    pub(crate) error: String,
}

#[derive(Deserialize)]
pub(crate) struct HeartbeatPayload {
    #[serde(default)]
    pub(crate) valid: bool,
    #[serde(default)]
    pub(crate) expires_at: i64,
    #[allow(dead_code)]
    #[serde(default)]
    pub(crate) error: String,
}

#[derive(Deserialize)]
pub(crate) struct WebhookPayload {
    #[serde(default)]
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) body: String, // base64
    #[serde(default)]
    pub(crate) error: String,
}

#[derive(Deserialize)]
pub(crate) struct DeviceResetPayload {
    #[serde(default)]
    pub(crate) success: bool,
    #[serde(default)]
    pub(crate) error: String,
}

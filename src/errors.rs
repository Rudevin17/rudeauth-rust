use std::fmt;

/// The error vocabulary, one to one with the other RudeAuth SDKs. A rejected
/// licence is a specific variant, never a bool: `authenticate` returns a
/// [`crate::Session`] or one of these, and the gating calls exist only on a Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The server could not be reached.
    Network,
    /// The response was malformed or its envelope did not decode.
    BadResponse,
    /// The responder is not holding this application's key.
    SignatureInvalid,
    /// The response was replayed from an earlier request.
    NonceMismatch,
    /// This machine's clock is too far from the server's.
    ClockSkew,
    LicenseInvalid,
    LicenseExpired,
    DeviceLimit,
    DeviceBlacklisted,
    RateLimited,
    SessionExpired,
    EndpointDisabled,
    AppDisabled,
    ResetUnavailable,
    FileNotFound,
    /// The server returned an error this SDK does not recognise. An unknown code
    /// is a reason to stop, not to continue.
    ServerError,
    /// A local misconfiguration: a bad public key, or too weak a fingerprint.
    Config(String),
    /// The requested variable or file does not exist for this application.
    NotFound(String),
}

impl Error {
    /// Map the server's coarse error codes onto the variants above.
    pub(crate) fn from_wire(code: &str) -> Error {
        match code {
            "LICENSE_INVALID" => Error::LicenseInvalid,
            "LICENSE_EXPIRED" => Error::LicenseExpired,
            "DEVICE_LIMIT" => Error::DeviceLimit,
            "DEVICE_BLACKLISTED" => Error::DeviceBlacklisted,
            "RATE_LIMITED" => Error::RateLimited,
            "SESSION_EXPIRED" => Error::SessionExpired,
            "ENDPOINT_DISABLED" => Error::EndpointDisabled,
            "APP_DISABLED" => Error::AppDisabled,
            "CLOCK_SKEW" => Error::ClockSkew,
            "RESET_UNAVAILABLE" => Error::ResetUnavailable,
            "FILE_NOT_FOUND" => Error::FileNotFound,
            _ => Error::ServerError,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::Network => "network unreachable",
            Error::BadResponse => "malformed response",
            Error::SignatureInvalid => "signature invalid, the server is not authentic",
            Error::NonceMismatch => "nonce mismatch, replayed response",
            Error::ClockSkew => "system clock is too far from the server's",
            Error::LicenseInvalid => "licence invalid",
            Error::LicenseExpired => "licence expired",
            Error::DeviceLimit => "device limit reached",
            Error::DeviceBlacklisted => "device blacklisted",
            Error::RateLimited => "rate limited",
            Error::SessionExpired => "session expired",
            Error::EndpointDisabled => "endpoint disabled",
            Error::AppDisabled => "application unavailable",
            Error::ResetUnavailable => "device reset unavailable",
            Error::FileNotFound => "no such file for this application",
            Error::ServerError => "server error",
            Error::Config(m) => return write!(f, "rudeauth: {m}"),
            Error::NotFound(m) => return write!(f, "rudeauth: {m}"),
        };
        write!(f, "rudeauth: {msg}")
    }
}

impl std::error::Error for Error {}

//! Crypto primitives, matching the RudeAuth server exactly. Every construction
//! here is checked byte for byte against the server-generated vectors.json by the
//! tests at the bottom of this file, so signature verification, session-key
//! derivation and sealed-payload open all agree with the server or the build fails.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const SIG_PREFIX: &[u8] = b"rudeauth-v1:";
const HKDF_SALT: &[u8] = b"rudeauth-v1-session";

/// The exact bytes the server signs: "rudeauth-v1:" + endpoint + ":" + sha256(data).
pub(crate) fn signing_input(endpoint: &str, data: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(data);
    let mut msg = Vec::with_capacity(SIG_PREFIX.len() + endpoint.len() + 1 + digest.len());
    msg.extend_from_slice(SIG_PREFIX);
    msg.extend_from_slice(endpoint.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(&digest);
    msg
}

/// True only if `sig` is this application's key signing `data` for `endpoint`.
/// This is the gate every response passes before a single field is read.
pub(crate) fn verify(public_key: &[u8], endpoint: &str, data: &[u8], sig: &[u8]) -> bool {
    let pk: [u8; 32] = match public_key.try_into() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig: [u8; 64] = match sig.try_into() {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(&pk) {
        Ok(key) => key,
        Err(_) => return false,
    };
    key.verify(&signing_input(endpoint, data), &Signature::from_bytes(&sig))
        .is_ok()
}

/// X25519(our_priv, their_pub), then HKDF-SHA256 with the constant session salt
/// and the session id as info. Returns None on a low-order (all-zero) shared point.
pub(crate) fn derive_session_key(
    our_priv: &[u8],
    their_pub: &[u8],
    session_id: &str,
) -> Option<[u8; 32]> {
    let our_priv: [u8; 32] = our_priv.try_into().ok()?;
    let their_pub: [u8; 32] = their_pub.try_into().ok()?;
    let shared = x25519_dalek::x25519(our_priv, their_pub);
    if shared == [0u8; 32] {
        return None;
    }
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared);
    let mut key = [0u8; 32];
    hk.expand(session_id.as_bytes(), &mut key).ok()?;
    Some(key)
}

/// Open a sealed blob (24-byte XChaCha20-Poly1305 nonce prepended) with the
/// session key and the endpoint's AAD. None if the tag or AAD does not check out.
pub(crate) fn open_sealed(session_key: &[u8], blob: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 24 {
        return None;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(session_key).ok()?;
    let nonce = XNonce::from_slice(&blob[..24]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &blob[24..],
                aad,
            },
        )
        .ok()
}

/// A fresh X25519 keypair for one handshake, returned as (public, private).
pub(crate) fn ephemeral() -> ([u8; 32], [u8; 32]) {
    let mut private = [0u8; 32];
    getrandom::getrandom(&mut private).expect("system RNG unavailable");
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    (public, private)
}

/// 32 random bytes for the anti-replay nonce the server must echo back.
pub(crate) fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("system RNG unavailable");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors.json")).unwrap()
    }

    #[test]
    fn verify_matches_the_server_signature() {
        let v = vectors();
        let e = &v["ed25519"];
        let pk = unhex(e["public_key_hex"].as_str().unwrap());
        let data = unhex(e["data_hex"].as_str().unwrap());
        let sig = unhex(e["signature_hex"].as_str().unwrap());
        let endpoint = e["endpoint"].as_str().unwrap();

        // The bytes we sign must be exactly the server's signed message.
        assert_eq!(
            hex(&signing_input(endpoint, &data)),
            e["signed_message_hex"].as_str().unwrap()
        );
        assert!(verify(&pk, endpoint, &data, &sig));

        // A one-bit tamper of the payload is rejected.
        let mut tampered = data.clone();
        tampered[0] ^= 0x01;
        assert!(!verify(&pk, endpoint, &tampered, &sig));

        // The same signature under a different endpoint is rejected.
        assert!(!verify(&pk, "variables", &data, &sig));
    }

    #[test]
    fn derive_session_key_matches_the_server() {
        let v = vectors();
        let x = &v["x25519"];
        let sk = &v["session_key"];
        let key = derive_session_key(
            &unhex(x["private_a_hex"].as_str().unwrap()),
            &unhex(x["public_b_hex"].as_str().unwrap()),
            sk["session_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(hex(&key), sk["key_hex"].as_str().unwrap());
    }

    #[test]
    fn open_sealed_matches_the_server() {
        let v = vectors();
        let c = &v["xchacha20poly1305"];
        let key = unhex(c["key_hex"].as_str().unwrap());
        let blob = unhex(c["sealed_hex"].as_str().unwrap());
        let aad = c["aad"].as_str().unwrap();

        let plain = open_sealed(&key, &blob, aad.as_bytes()).unwrap();
        assert_eq!(hex(&plain), c["plaintext_hex"].as_str().unwrap());

        // Wrong AAD (a different endpoint) must not open.
        assert!(open_sealed(&key, &blob, b"files:core.dll").is_none());
    }
}

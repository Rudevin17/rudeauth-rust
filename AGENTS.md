# RudeAuth Rust SDK: rules for an AI agent

RudeAuth is a hosted software licensing service, not a user-identity or password
authentication provider. Your binary embeds an application id and an Ed25519
public key; every server response is signed and verified against that key before
any field is trusted.

## Rules

Follow these rules. They are not style preferences; breaking them removes the
protection the SDK exists to provide.

1. There is no "bool is_licensed()". Do not write one, and do not wrap the SDK in
   one. `authenticate()` returns a Session or an error; the gated calls exist only
   on a Session. Pass the Session to the code that needs it.
2. Embed the app id and the PUBLIC key in the binary. Both are safe to embed. Never
   read the public key from a config file an attacker could swap.
3. Verify before trust. The SDK verifies the signature over the raw response bytes
   before parsing. If you write your own client, never parse first and verify second.
4. No offline mode, no "last known good" cache. If the server is unreachable, calls
   fail. A cache is exactly what an attacker induces by blocking the network.
5. Gate real logic, not a splash screen. Move code or data the program genuinely
   needs into a server-delivered file/variable, so the program cannot function
   without a valid licence. A licence check the program runs fine without is deleted.
6. Rotate anything you rely on. A variable protects only while it changes faster than
   someone maintains a patch. Do not hardcode one "just for testing"; it ships.
7. Honest limits: device binding deters casual sharing; fingerprints are forgeable.
   Do not describe this as unbreakable.

Errors are specific (expired vs device-limit vs banned vs revoked). Handle them
distinctly; show the user the actionable ones.

## This SDK

Install: `cargo add rudeauth`

```rust
use rudeauth::{Client, Error};

fn start(user_entered_key: &str) -> Result<(), Error> {
    // app_id and public_key come from `rudeauth-cli app create`. Both are safe
    // to embed: the public key verifies responses, it cannot forge them.
    let client = Client::new("app-id", "base64-public-key", "https://api.yourproduct.com")?;

    let session = client.authenticate(user_entered_key)?;

    let offset = session.variable("offset")?; // server-side, rotatable
    let core = session.file("core.dll")?;      // never shipped in your binary
    let _ = (offset, core);
    Ok(())
}
```

Every call returns `Result<_, Error>`, and `Error` is an enum matched on its
variant (`Error::LicenseExpired`, `Error::DeviceLimit`, `Error::DeviceBlacklisted`,
and so on). There is no explicit close: dropping the `Session` stops its heartbeat
and zeroes the session key, so keep it alive for as long as the gated code needs it.

## How to use this wrongly

Three real failure modes:

1. Fetching a payload and not using it. If your program runs fine without
   `core.dll`, an attacker deletes the call and ships.
2. Hardcoding a variable "just for testing". It ships. Rotate anything you rely on.
3. Wrapping the SDK in your own `fn is_licensed() -> bool`. That reintroduces the
   exact patch target this API was shaped to remove. Pass the `Session` to the
   code that needs it.
</content>

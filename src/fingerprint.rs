//! Hardware fingerprinting, the shared per-OS component set every RudeAuth SDK
//! implements so a device is recognised identically no matter which SDK
//! authenticated it. Each component is tagged `tag:value` so two sources cannot
//! collide on an identical raw value. Components that cannot be read are skipped,
//! never substituted, because a placeholder shared across machines would make
//! unrelated devices look identical. These values are client-supplied and thus
//! forgeable: device binding deters casual sharing, it is not a hard control.

/// A human-readable machine name for the vendor's device list. Not part of the
/// identity, only a label.
pub(crate) fn label() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into())
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOSTNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "unknown".into())
    }
}

fn push(out: &mut Vec<String>, tag: &str, value: String) {
    let value = value.trim().to_string();
    if !value.is_empty() {
        out.push(format!("{tag}:{value}"));
    }
}

#[cfg(windows)]
pub(crate) fn collect() -> Vec<String> {
    let mut out = Vec::new();
    push(
        &mut out,
        "machine-guid",
        reg_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
    );
    push(&mut out, "volume", volume_serial());
    push(
        &mut out,
        "cpu",
        reg_string(
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString",
        ),
    );
    push(
        &mut out,
        "bios",
        reg_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemSerialNumber"),
    );
    push(
        &mut out,
        "board",
        reg_string(r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardProduct"),
    );
    out
}

#[cfg(windows)]
fn reg_string(path: &str, name: &str) -> String {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey_with_flags(path, KEY_QUERY_VALUE | KEY_WOW64_64KEY) {
        Ok(key) => key
            .get_value::<String, _>(name)
            .unwrap_or_default()
            .trim_end_matches([' ', '\0'])
            .to_string(),
        Err(_) => String::new(),
    }
}

#[cfg(windows)]
fn volume_serial() -> String {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetVolumeInformationW(
            root: *const u16,
            volume_name: *mut u16,
            volume_name_size: u32,
            serial: *mut u32,
            max_component_len: *mut u32,
            fs_flags: *mut u32,
            fs_name: *mut u16,
            fs_name_size: u32,
        ) -> i32;
    }

    // "C:\" followed by a NUL terminator, as UTF-16.
    let root: Vec<u16> = "C:\\\u{0}".encode_utf16().collect();
    let mut serial: u32 = 0;
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 || serial == 0 {
        return String::new();
    }
    format!("{serial:08X}")
}

#[cfg(target_os = "linux")]
pub(crate) fn collect() -> Vec<String> {
    let mut out = Vec::new();
    push(&mut out, "machine-id", read_first_line("/etc/machine-id"));
    push(
        &mut out,
        "product-uuid",
        read_first_line("/sys/class/dmi/id/product_uuid"),
    );
    push(
        &mut out,
        "board-serial",
        read_first_line("/sys/class/dmi/id/board_serial"),
    );
    push(
        &mut out,
        "product-serial",
        read_first_line("/sys/class/dmi/id/product_serial"),
    );
    push(&mut out, "cpu", cpu_model());
    out
}

#[cfg(target_os = "linux")]
fn read_first_line(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => s.lines().next().unwrap_or("").trim().to_string(),
        Err(_) => String::new(),
    }
}

#[cfg(target_os = "linux")]
fn cpu_model() -> String {
    let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") else {
        return String::new();
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            if let Some(idx) = rest.find(':') {
                return rest[idx + 1..].trim().to_string();
            }
        }
    }
    String::new()
}

#[cfg(target_os = "macos")]
pub(crate) fn collect() -> Vec<String> {
    let mut out = Vec::new();
    push(&mut out, "platform-uuid", ioreg_value("IOPlatformUUID"));
    push(&mut out, "serial", ioreg_value("IOPlatformSerialNumber"));
    push(&mut out, "model", sysctl("hw.model"));
    out
}

#[cfg(target_os = "macos")]
fn ioreg_value(key: &str) -> String {
    let Ok(output) = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
    else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let needle = format!("\"{key}\"");
    for line in text.lines() {
        if line.contains(&needle) {
            if let Some(idx) = line.find("= ") {
                return line[idx + 2..].trim().trim_matches('"').to_string();
            }
        }
    }
    String::new()
}

#[cfg(target_os = "macos")]
fn sysctl(name: &str) -> String {
    match std::process::Command::new("sysctl")
        .args(["-n", name])
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn collect() -> Vec<String> {
    // An unsupported platform yields no components, so authenticate refuses rather
    // than sending a weak identity.
    Vec::new()
}

//! Shared private-key loading for CLI commands.
//!
//! Preferred interactive form: `--key -` (one line from stdin).
//! Script form: `--key 0x…` still works.
//! File form: `--key @/path/to/key`.

use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

use signer_primitives::parse_secret_hex;

/// Load a 32-byte secret key from a CLI `--key` value.
///
/// | Value | Behavior |
/// | --- | --- |
/// | `-` | Read one trimmed line from stdin |
/// | `@path` | Read file contents (trimmed) |
/// | other | Treat as hex (optional `0x`) |
///
/// # Errors
///
/// I/O failures, empty input, or invalid hex/length.
pub(crate) fn load_secret_key(spec: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let raw = if spec == "-" {
        read_stdin_line()?
    } else if let Some(path) = spec.strip_prefix('@') {
        read_key_file(path)?
    } else {
        spec.to_owned()
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty private key".into());
    }
    Ok(parse_secret_hex(raw)?)
}

fn read_stdin_line() -> Result<String, Box<dyn std::error::Error>> {
    let mut line = String::new();
    let n = io::stdin().lock().read_line(&mut line)?;
    if n == 0 {
        return Err("expected private key on stdin, got EOF".into());
    }
    Ok(line)
}

fn read_key_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let p = Path::new(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(p) {
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                eprintln!(
                    "warning: key file {path} is group/world-accessible (mode {:o})",
                    meta.permissions().mode() & 0o777
                );
            }
        }
    }
    Ok(fs::read_to_string(p)?)
}

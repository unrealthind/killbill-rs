//! Writing the config file back out — the daemon owns config writes (charter §9).
//!
//! `killbillctl` and the TUI never touch `/etc/killbill/config.toml`; they ask
//! the daemon, which validates the change and, only if it passes, persists it
//! here. That keeps running-state and the file from ever drifting and gives one
//! validation authority.
//!
//! The write is atomic (temp file in the same directory, `fsync`, `rename`) so a
//! crash or power cut mid-write can never leave a half-written config that would
//! fail to parse on the next boot. Comments and layout in the file are **not**
//! preserved — the daemon re-serializes [`RawConfig`] from scratch.
//!
//! Permissions: an existing owner-only config keeps its exact mode; one that is
//! group/other-readable is tightened to `0600` on the next write (the file names
//! the user's security keys and LUKS partition). A symlinked config path is
//! resolved to its target's mode and then **replaced** by a regular file — a
//! `rename` cannot write *through* a symlink, and inheriting a symlink's own
//! `0777` would defeat the point.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::config::RawConfig;

/// Mode for a freshly-created config file: owner read/write only. The whitelist
/// enumerates which security keys the user owns and `luks_destroy.target_header`
/// names their LUKS partition — not world-readable.
const NEW_FILE_MODE: u32 = 0o600;

/// Prepended to every daemon-written config so a human opening the file knows
/// why their comments vanished.
const MANAGED_HEADER: &str = "\
# killbill-rs configuration.
#
# killbilld rewrites this file when the whitelist or a setting is changed
# through killbillctl or the TUI. Hand edits are fine, but comments and
# formatting are lost on the next daemon-side write; run `killbillctl reload`
# after editing by hand.
";

/// A failure serializing or writing the config file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigWriteError {
    #[error("serializing config to TOML: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("writing config to {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Render `raw` as the exact text that would be written to disk.
pub fn to_toml(raw: &RawConfig) -> Result<String, ConfigWriteError> {
    let body = toml::to_string(raw)?;
    Ok(format!("{MANAGED_HEADER}\n{body}"))
}

/// Atomically replace the config file at `path` with `raw`'s serialization.
///
/// Writes `path` + `.tmp` in the same directory, flushes it to disk, then
/// renames it over `path`. On any error `path` is left untouched.
pub fn write_atomic(path: &Path, raw: &RawConfig) -> Result<(), ConfigWriteError> {
    let contents = to_toml(raw)?;
    let io = |source| ConfigWriteError::Io {
        path: path.to_path_buf(),
        source,
    };

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp = {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        match dir {
            Some(d) => d.join(name),
            None => PathBuf::from(name),
        }
    };

    // Decide the replacement file's mode. `metadata` (not `symlink_metadata`)
    // so a symlinked config resolves to the *target's* mode — a symlink's own
    // mode is 0777, and inheriting that would rewrite the config
    // world-readable, leaking the whitelist and `luks_destroy.target_header`.
    // We carry an existing owner-only mode across the rewrite but never widen:
    // a config that is already group/other-accessible is tightened to 0600
    // (with a warning), not preserved. `create_new` on the temp file refuses to
    // follow a symlink or reuse a planted temp.
    let mode = match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {
            let existing = m.permissions().mode() & 0o777;
            if existing & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    existing_mode = %format!("{existing:04o}"),
                    "existing config is readable beyond its owner — writing the replacement 0600"
                );
                NEW_FILE_MODE
            } else {
                existing
            }
        }
        _ => NEW_FILE_MODE,
    };

    let _ = std::fs::remove_file(&tmp); // a temp left by a crashed prior write
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(io)?;
    file.write_all(contents.as_bytes()).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(e));
    }

    // Best-effort: fsync the directory so the rename itself is durable. A
    // failure here does not undo a successful rename, so it is not fatal.
    if let Some(d) = dir {
        if let Ok(handle) = std::fs::File::open(d) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::validate;

    fn sample() -> RawConfig {
        toml::from_str(
            r#"
            [general]
            armed_at_boot = true

            [detection]
            sensors = ["usb"]

            [[whitelist]]
            id = "1050:0407"
            label = "YubiKey 5C"
            max_count = 2

            [[whitelist]]
            id = "1d6b:0002"

            [response]
            dry_run = true
            power_action = "halt"
            lock_screen_first = false
            "#,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_through_toml_and_still_validates() {
        let original = sample();
        let text = to_toml(&original).unwrap();

        // Re-parse the rendered text and it must still be a valid config.
        let reparsed: RawConfig = toml::from_str(&text).expect("rendered config must parse");
        let cfg = validate(reparsed).expect("rendered config must validate");

        assert!(cfg.armed_at_boot);
        assert_eq!(cfg.whitelist.len(), 2);
        assert_eq!(cfg.whitelist[0].max_count, 2);
        assert_eq!(cfg.whitelist[1].max_count, 1); // resolved default
        assert_eq!(cfg.power_action, killbill_proto::PowerAction::Halt);
        assert!(cfg.dry_run);
    }

    #[test]
    fn rendered_text_carries_the_managed_header() {
        let text = to_toml(&sample()).unwrap();
        assert!(text.starts_with("# killbill-rs configuration."));
    }

    #[test]
    fn optional_fields_that_are_none_are_not_emitted() {
        let raw: RawConfig = toml::from_str(
            r#"
            [[whitelist]]
            id = "1050:0407"
            "#,
        )
        .unwrap();
        let text = to_toml(&raw).unwrap();
        assert!(!text.contains("label"), "absent label must not be written");
        assert!(
            !text.contains("max_count"),
            "absent max_count must not be written"
        );
        assert!(
            !text.contains("luks_destroy"),
            "absent luks_destroy must not be written"
        );
    }

    #[test]
    fn write_atomic_replaces_the_file_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("killbilld-cfgstore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "garbage that should be gone").unwrap();

        write_atomic(&path, &sample()).unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("armed_at_boot = true"));
        assert!(
            !dir.join("config.toml.tmp").exists(),
            "tmp file was left behind"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_file_is_owner_only_and_a_loose_mode_is_tightened() {
        let dir = std::env::temp_dir().join(format!("killbilld-cfgmode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Fresh file → 0600.
        let fresh = dir.join("fresh.toml");
        write_atomic(&fresh, &sample()).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Existing owner-only but stricter (0400) → the exact mode is carried.
        let ro = dir.join("readonly.toml");
        std::fs::write(&ro, "x = 1").unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o400)).unwrap();
        write_atomic(&ro, &sample()).unwrap();
        assert_eq!(
            std::fs::metadata(&ro).unwrap().permissions().mode() & 0o777,
            0o400
        );

        // Existing group/other-readable (0644) → tightened to 0600, never widened.
        let loose = dir.join("loose.toml");
        std::fs::write(&loose, "x = 1").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&loose, &sample()).unwrap();
        assert_eq!(
            std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlinked_config_is_rewritten_at_the_targets_mode_not_the_links() {
        let dir = std::env::temp_dir().join(format!("killbilld-cfgln-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let target = dir.join("real.toml");
        std::fs::write(&target, "x = 1").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        write_atomic(&link, &sample()).unwrap();

        // `rename` replaces the link with a regular file (documented behaviour);
        // the point of this test is that it lands owner-only — a naive
        // `symlink_metadata` would have seen the link's 0777 and widened it.
        let mode = std::fs::metadata(&link).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

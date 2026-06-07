//! Per-user UID sandboxing for stdio subprocesses.
//!
//! Opening stdio servers to every user means each can run an arbitrary command
//! inside the hub container. To contain that, each user's subprocesses are
//! dropped to a distinct unprivileged UID (`HUB_SANDBOX_UID_BASE + slot`). A
//! non-root child cannot read the hub's `/proc/1/environ` (so the master key is
//! safe) nor another user's subprocess environment (distinct UIDs). The DB is
//! additionally locked to root, and a built git venv is chowned to its owner.
//!
//! Sandboxing only engages when `HUB_SANDBOX_UID_BASE` is set *and* the hub runs
//! as root (it can then `setuid`); otherwise subprocesses spawn as today, so
//! local `cargo run` and the test suite are unaffected.

use std::path::Path;

/// The resolved sandbox identity + writable cache dir for a user's subprocesses.
#[derive(Clone, Debug)]
pub struct Sandbox {
    pub uid: u32,
    pub gid: u32,
    /// Writable HOME/cache directory owned by `uid` (uv/npx need somewhere to write).
    pub cache_dir: String,
}

/// Whether the hub is running as root (required to drop children to another UID).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid is always safe to call and has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The absolute sandbox UID for a user slot, or `None` if sandboxing is off
/// (no base configured, not root, or the user has no slot yet).
pub fn uid_for(base: Option<u32>, slot: Option<i64>) -> Option<u32> {
    let base = base?;
    if !is_root() {
        return None;
    }
    Some(base + u32::try_from(slot?).ok()?)
}

/// Prepare a [`Sandbox`] for `uid`: create and chown its cache directory under
/// `<env_dir>/../sandbox/<uid>`.
pub fn prepare(uid: u32, env_dir: &str) -> std::io::Result<Sandbox> {
    let root = Path::new(env_dir)
        .parent()
        .unwrap_or_else(|| Path::new(env_dir))
        .join("sandbox");
    let cache = root.join(uid.to_string());
    std::fs::create_dir_all(&cache)?;
    chown(&cache, uid, uid)?;
    Ok(Sandbox {
        uid,
        gid: uid,
        cache_dir: cache.to_string_lossy().into_owned(),
    })
}

/// chown a single path (used for the cache dir and to lock the DB to root).
pub fn chown(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("path contains NUL"))?;
        // SAFETY: `c` is a valid NUL-terminated C string for the call's lifetime.
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid);
        Ok(())
    }
}

/// Lock the SQLite database (and its WAL/SHM sidecars) to `0600` so a sandbox
/// UID cannot read the encrypted secrets. Best-effort; logs on failure.
pub fn lock_database(db_path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let p = format!("{db_path}{suffix}");
            if std::path::Path::new(&p).exists() {
                if let Err(e) = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                {
                    tracing::warn!(path = %p, error = %e, "could not lock database file");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = db_path;
    }
}

/// Recursively chown a directory tree — used for a built git venv so its owning
/// user's sandbox UID can execute it. Shells out to coreutils `chown -R`.
pub fn chown_recursive(path: &str, uid: u32, gid: u32) -> std::io::Result<()> {
    let status = std::process::Command::new("chown")
        .arg("-R")
        .arg(format!("{uid}:{gid}"))
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other("chown -R failed"));
    }
    Ok(())
}

/// Recursively make a tree world readable/traversable (`a+rX`: read for all,
/// search on directories, execute on already-executable files). Used for the
/// shared managed-Python interpreter that built git venvs symlink to: the venv
/// itself is chowned to its owner, but the interpreter is shared read-only
/// across users, so every sandbox UID must be able to read and exec it. Shells
/// out to coreutils `chmod -R`.
pub fn make_world_traversable(path: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("chmod")
        .arg("-R")
        .arg("a+rX")
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other("chmod -R failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::uid_for;

    #[test]
    fn uid_for_requires_a_base() {
        // No base configured → never sandboxed, regardless of slot.
        assert_eq!(uid_for(None, Some(3)), None);
        // With a base, the result depends on running as root; off-root it is None.
        if !super::is_root() {
            assert_eq!(uid_for(Some(20000), Some(3)), None);
        } else {
            assert_eq!(uid_for(Some(20000), Some(3)), Some(20003));
        }
    }
}

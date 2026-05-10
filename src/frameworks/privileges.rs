use std::path::Path;

use anyhow::{bail, Context, Result};
use nix::unistd::{self, Gid, Uid};

/// Configuration for the privilege-dropping sequence.
pub struct PrivilegeDropConfig<'a> {
    pub user: &'a str,
    pub group: &'a str,
    pub chroot_dir: Option<&'a Path>,
}

/// Default user to drop privileges to when none is configured.
pub const DEFAULT_USER: &str = "nobody";

/// Default group to drop privileges to when none is configured.
pub const DEFAULT_GROUP: &str = "nogroup";

/// Default chroot directory when none is configured.
pub const DEFAULT_CHROOT_DIR: &str = "/var/lib/dns-filter";

/// Drops process privileges after sockets have been bound.
///
/// Execution order (security-critical):
/// 1. Resolve user → uid and group → gid (before chroot, needs real `/etc/passwd`)
/// 2. `chroot` into the configured directory (if set), then `chdir("/")`
/// 3. On Linux: `prctl(PR_SET_KEEPCAPS, 1)` to preserve capabilities across setuid
/// 4. `setgroups([gid])` — drop all supplementary groups
/// 5. `setgid(gid)` — drop group privilege
/// 6. `setuid(uid)` — drop user privilege (point of no return)
/// 7. On Linux: retain only `CAP_NET_BIND_SERVICE` in effective+permitted sets
/// 8. On Linux: `prctl(PR_SET_KEEPCAPS, 0)` — prevent further cap manipulation
///
/// If the process is already running as the target user (non-root), this is a
/// no-op and logs an informational message.
pub fn drop_privileges(config: &PrivilegeDropConfig<'_>) -> Result<()> {
    let current_uid = unistd::getuid();

    // If already running as non-root, privilege drop is a no-op.
    if !current_uid.is_root() {
        tracing::info!(
            uid = current_uid.as_raw(),
            "already running as non-root, skipping privilege drop"
        );
        return Ok(());
    }

    // Step 1: Resolve user and group (must happen before chroot — needs real
    // /etc/passwd and /etc/group which are not available inside the chroot).
    let user = unistd::User::from_name(config.user)
        .with_context(|| format!("looking up user '{}'", config.user))?
        .ok_or_else(|| anyhow::anyhow!("user '{}' not found", config.user))?;

    let group = unistd::Group::from_name(config.group)
        .with_context(|| format!("looking up group '{}'", config.group))?
        .ok_or_else(|| anyhow::anyhow!("group '{}' not found", config.group))?;

    let uid = user.uid;
    let gid = group.gid;

    // Step 2: chroot (requires root, must happen before setuid)
    if let Some(chroot_dir) = config.chroot_dir {
        unistd::chroot(chroot_dir)
            .with_context(|| format!("chroot to {}", chroot_dir.display()))?;
        unistd::chdir("/").context("chdir to / after chroot")?;
        tracing::info!(dir = %chroot_dir.display(), "chroot complete");
    }

    // Step 3: On Linux, set PR_SET_KEEPCAPS so capabilities survive setuid
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_keepcaps(true).context("prctl(PR_SET_KEEPCAPS, 1)")?;

    // Step 4: Drop supplementary groups
    unistd::setgroups(&[gid]).context("setgroups")?;

    // Step 5: Drop group privilege
    unistd::setgid(gid).with_context(|| format!("setgid({})", gid))?;

    // Step 6: Drop user privilege (point of no return)
    unistd::setuid(uid).with_context(|| format!("setuid({})", uid))?;

    tracing::info!(
        user = config.user,
        group = config.group,
        uid = uid.as_raw(),
        gid = gid.as_raw(),
        "privileges dropped"
    );

    // Step 7: On Linux, retain only CAP_NET_BIND_SERVICE
    #[cfg(target_os = "linux")]
    retain_net_bind_capability()?;

    // Step 8: On Linux, disable keepcaps
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_keepcaps(false).context("prctl(PR_SET_KEEPCAPS, 0)")?;

    // Verify we actually dropped privileges
    verify_privilege_drop(uid, gid)?;

    Ok(())
}

/// On Linux, clear all capabilities except CAP_NET_BIND_SERVICE in the
/// effective and permitted sets.
#[cfg(target_os = "linux")]
fn retain_net_bind_capability() -> Result<()> {
    use caps::{CapSet, Capability, CapsHashSet};

    let mut keep = CapsHashSet::new();
    keep.insert(Capability::CAP_NET_BIND_SERVICE);

    // Clear and re-set permitted set
    caps::set(None, CapSet::Permitted, &keep).context("setting permitted capabilities")?;
    // Set effective to match
    caps::set(None, CapSet::Effective, &keep).context("setting effective capabilities")?;

    tracing::info!("retained CAP_NET_BIND_SERVICE, dropped all other capabilities");
    Ok(())
}

/// Verify that privileges were actually dropped by checking current uid/gid.
fn verify_privilege_drop(expected_uid: Uid, expected_gid: Gid) -> Result<()> {
    let actual_uid = unistd::getuid();
    let actual_gid = unistd::getgid();

    if actual_uid != expected_uid {
        bail!(
            "privilege drop verification failed: expected uid {}, got {}",
            expected_uid,
            actual_uid
        );
    }
    if actual_gid != expected_gid {
        bail!(
            "privilege drop verification failed: expected gid {}, got {}",
            expected_gid,
            actual_gid
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_privileges_is_noop_when_non_root() {
        // CI typically runs as non-root, so this should succeed as a no-op.
        let config = PrivilegeDropConfig {
            user: "nobody",
            group: "nogroup",
            chroot_dir: None,
        };
        let result = drop_privileges(&config);
        assert!(result.is_ok(), "expected no-op for non-root: {result:?}");
    }
}

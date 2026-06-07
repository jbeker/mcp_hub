//! Git-sourced backends: build a repo into a prebuilt virtualenv once, then run
//! it directly so connecting never fetches or installs. Updates are explicit.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sqlx::SqlitePool;
use tokio::process::Command;

use crate::instances::{self, Instance, ServerDef};

const LS_REMOTE_TIMEOUT: Duration = Duration::from_secs(30);
const BUILD_TIMEOUT: Duration = Duration::from_secs(600);

/// Result of an update request.
pub struct UpdateReport {
    pub changed: bool,
    pub previous_commit: Option<String>,
    pub commit: String,
}

/// The on-disk virtualenv path for an instance.
pub fn env_path(env_dir: &str, instance_id: &str) -> PathBuf {
    Path::new(env_dir).join(instance_id)
}

/// True if `def` is a git-sourced backend (a stdio server with a repo).
pub fn is_git_source(def: &ServerDef) -> bool {
    def.is_git()
}

/// The exact `(program, args)` a stdio or git backend will be launched with,
/// for display in the UI. Returns `None` for http backends and for a git source
/// that has not been built yet (its launch path does not exist).
pub fn resolved_command(
    env_dir: &str,
    inst: &Instance,
    def: &ServerDef,
) -> Option<(String, Vec<String>)> {
    if def.is_git() {
        let ready = inst.build_status == "ready" && env_path(env_dir, &inst.id).exists();
        if !ready {
            return None;
        }
        launch_command(env_dir, &inst.id, def).ok()
    } else if def.transport == "stdio" {
        Some((def.command.clone()?, def.args.clone()))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Validation (these values become process arguments, so keep them tight)
// ---------------------------------------------------------------------------

fn validate_repo(repo: &str) -> Result<()> {
    let url = url::Url::parse(repo).context("repo must be a valid URL")?;
    if url.scheme() != "https" && url.scheme() != "git+https" {
        bail!("repo must be an https git URL");
    }
    Ok(())
}

fn validate_ref(git_ref: &str) -> Result<()> {
    if git_ref.is_empty() || git_ref.len() > 100 {
        bail!("invalid git ref");
    }
    if !git_ref
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
    {
        bail!("git ref may only contain letters, digits, and . _ - /");
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("entry/module name contains invalid characters");
    }
    Ok(())
}

/// Resolve the program and args to launch a built git backend: the command's
/// first token resolves to `<venv>/bin/<command>` so console scripts and
/// `python` come from the built environment; the rest of the command line is
/// passed through unchanged.
pub fn launch_command(env_dir: &str, instance_id: &str, def: &ServerDef) -> Result<(String, Vec<String>)> {
    let bin = env_path(env_dir, instance_id).join("bin");
    let command = def
        .command
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("git source has no command"))?;
    validate_name(command)?;
    let program = bin.join(command);
    Ok((program.to_string_lossy().into_owned(), def.args.clone()))
}

// ---------------------------------------------------------------------------
// Build pipeline
// ---------------------------------------------------------------------------

/// Resolve a branch/tag to a commit SHA via `git ls-remote`. A value that is
/// already a commit SHA is accepted as-is.
async fn resolve_commit(repo: &str, git_ref: &str) -> Result<String> {
    let out = tokio::time::timeout(
        LS_REMOTE_TIMEOUT,
        Command::new("git")
            .args(["ls-remote", repo, git_ref])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output(),
    )
    .await
    .context("git ls-remote timed out")?
    .context("running git ls-remote")?;

    if !out.status.success() {
        bail!(
            "git ls-remote failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if let Some(sha) = stdout.split_whitespace().next() {
        return Ok(sha.to_string());
    }
    // No matching ref; accept a raw commit SHA.
    if git_ref.len() >= 7 && git_ref.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(git_ref.to_string());
    }
    bail!("ref '{git_ref}' not found in {repo}")
}

/// Build `git+<repo>@<commit>` into a fresh virtualenv, swapping it in
/// atomically on success. Slow; only ever called from an update.
async fn build_env(env_dir: &str, instance_id: &str, repo: &str, commit: &str) -> Result<()> {
    std::fs::create_dir_all(env_dir).context("creating env directory")?;
    let final_path = env_path(env_dir, instance_id);
    let tmp = Path::new(env_dir).join(format!(".{instance_id}.building"));
    let _ = std::fs::remove_dir_all(&tmp);

    let python = tmp.join("bin").join("python");
    let spec = format!("git+{repo}@{commit}");

    // 1) Create the venv. `--relocatable` is essential: we build under a temp
    //    path and rename it into place, and a non-relocatable venv hardcodes its
    //    build-time path into console-script shebangs, which the move breaks.
    run_uv(&["venv", "--relocatable", &tmp.to_string_lossy()], env_dir).await?;
    // 2) Install the package + deps into it.
    run_uv(
        &[
            "pip",
            "install",
            "--python",
            &python.to_string_lossy(),
            &spec,
        ],
        env_dir,
    )
    .await?;

    // 3) Swap in atomically.
    let _ = std::fs::remove_dir_all(&final_path);
    std::fs::rename(&tmp, &final_path).context("installing built environment")?;

    // 4) The venv's interpreter is a managed CPython installed under
    //    `<env_dir>/.uv-python` (see `run_uv`), shared read-only across users and
    //    symlinked from each venv's `bin/python`. The venv gets chowned to its
    //    owner, but the interpreter must be readable+executable by *every*
    //    sandbox UID, so relax its permissions to `a+rX`. Best-effort.
    let py_dir = python_install_dir(env_dir);
    if py_dir.exists() {
        if let Err(e) = crate::sandbox::make_world_traversable(&py_dir) {
            tracing::warn!(error = %e, "could not relax permissions on shared python dir");
        }
    }
    Ok(())
}

/// The shared directory uv installs managed Python interpreters into. Kept on
/// the data volume (not root's home) so unprivileged sandbox UIDs can reach the
/// interpreter a built venv symlinks to.
fn python_install_dir(env_dir: &str) -> PathBuf {
    Path::new(env_dir).join(".uv-python")
}

/// Whether an instance's built venv resolves its interpreter to the shared
/// managed-Python directory (rather than an old build under root's home). Used
/// to force a one-time rebuild of venvs created before the relocation.
fn venv_python_is_shared(env_dir: &str, instance_id: &str) -> bool {
    let link = env_path(env_dir, instance_id).join("bin").join("python");
    match (
        std::fs::canonicalize(&link),
        std::fs::canonicalize(python_install_dir(env_dir)),
    ) {
        (Ok(target), Ok(shared)) => target.starts_with(shared),
        _ => false,
    }
}

async fn run_uv(args: &[&str], env_dir: &str) -> Result<()> {
    let uv_cache = Path::new(env_dir).join(".uv-cache");
    let out = tokio::time::timeout(
        BUILD_TIMEOUT,
        Command::new("uv")
            .args(args)
            .env("UV_CACHE_DIR", uv_cache)
            // Install managed interpreters under the data volume rather than
            // root's home, so the venv's `bin/python` symlink resolves to a path
            // that sandbox UIDs can traverse and execute.
            .env("UV_PYTHON_INSTALL_DIR", python_install_dir(env_dir))
            .env("GIT_TERMINAL_PROMPT", "0")
            .output(),
    )
    .await
    .context("uv command timed out")?
    .context("running uv")?;
    if !out.status.success() {
        bail!(
            "uv {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Resolve the configured ref, and (re)build the environment if the resolved
/// commit differs from what is currently built. Records build state.
pub async fn update_instance(
    pool: &SqlitePool,
    env_dir: &str,
    inst: &Instance,
    def: &ServerDef,
    owner_uid: Option<u32>,
) -> Result<UpdateReport> {
    if !is_git_source(def) {
        bail!("'{}' is not a git-sourced server", inst.namespace);
    }
    let repo = def
        .repo
        .as_deref()
        .ok_or_else(|| anyhow!("git source has no repo URL"))?;
    validate_repo(repo)?;
    let git_ref = def.git_ref.as_deref().unwrap_or("main");
    validate_ref(git_ref)?;
    // Validate the launch target up front so a bad entry fails before building.
    let _ = launch_command(env_dir, &inst.id, def)?;

    let commit = resolve_commit(repo, git_ref).await?;
    let already_built = inst.built_commit.as_deref() == Some(commit.as_str())
        && inst.build_status == "ready"
        && env_path(env_dir, &inst.id).exists()
        // A venv built before the interpreter was relocated points `bin/python`
        // into root's home, which sandbox UIDs cannot exec — force a rebuild so
        // it relinks to the shared, world-readable interpreter.
        && venv_python_is_shared(env_dir, &inst.id);
    if already_built {
        return Ok(UpdateReport {
            changed: false,
            previous_commit: inst.built_commit.clone(),
            commit,
        });
    }

    match build_env(env_dir, &inst.id, repo, &commit).await {
        Ok(()) => {
            // Hand the built venv to the owner's sandbox UID so it can run it.
            if let Some(uid) = owner_uid {
                let path = env_path(env_dir, &inst.id);
                if let Err(e) = crate::sandbox::chown_recursive(&path.to_string_lossy(), uid, uid) {
                    tracing::warn!(error = %e, "could not chown built venv to sandbox uid");
                }
            }
            instances::set_build_state(pool, &inst.id, "ready", Some(&commit)).await?;
            Ok(UpdateReport {
                changed: true,
                previous_commit: inst.built_commit.clone(),
                commit,
            })
        }
        Err(e) => {
            // Keep the previously-built commit (if any) usable.
            instances::set_build_state(pool, &inst.id, "error", inst.built_commit.as_deref())
                .await?;
            Err(e)
        }
    }
}

/// Remove an instance's built environment (called when the instance is deleted).
pub fn remove_env(env_dir: &str, instance_id: &str) {
    let _ = std::fs::remove_dir_all(env_path(env_dir, instance_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_def(command: Option<&str>, args: &[&str]) -> ServerDef {
        ServerDef {
            name: "x".into(),
            description: String::new(),
            transport: "stdio".into(),
            command: command.map(String::from),
            args: args.iter().map(|s| s.to_string()).collect(),
            url: None,
            runtime: "python".into(),
            repo: Some("https://github.com/o/r".into()),
            git_ref: Some("main".into()),
            entry: None,
            module: None,
        }
    }

    #[test]
    fn launch_resolves_command_in_the_venv() {
        let (p, a) = launch_command("/envs", "abc", &git_def(Some("my-mcp"), &[])).unwrap();
        assert!(p.ends_with("/envs/abc/bin/my-mcp"));
        assert!(a.is_empty());

        let (p, a) =
            launch_command("/envs", "abc", &git_def(Some("python"), &["-m", "pkg.server"])).unwrap();
        assert!(p.ends_with("/envs/abc/bin/python"));
        assert_eq!(a, vec!["-m".to_string(), "pkg.server".to_string()]);
    }

    #[test]
    fn launch_rejects_bad_names_and_missing_command() {
        assert!(launch_command("/envs", "abc", &git_def(Some("../evil"), &[])).is_err());
        assert!(launch_command("/envs", "abc", &git_def(Some("a b"), &[])).is_err());
        assert!(launch_command("/envs", "abc", &git_def(None, &[])).is_err());
    }

    #[test]
    fn validation_rules() {
        assert!(validate_repo("https://github.com/o/r").is_ok());
        assert!(validate_repo("ssh://git@github.com/o/r").is_err());
        assert!(validate_repo("file:///tmp/r").is_err());
        assert!(validate_ref("main").is_ok());
        assert!(validate_ref("release/1.2").is_ok());
        assert!(validate_ref("bad ref;rm").is_err());
    }

    /// Full build → relocate → run, against a local git repo. Ignored by
    /// default because building the package fetches its build backend
    /// (hatchling) from PyPI. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "needs network for the Python build backend"]
    async fn build_env_produces_a_runnable_relocated_entry() {
        use std::process::Command as Sync;
        let root = std::env::temp_dir().join(format!("mcp_hub_buildtest_{}", uuid::Uuid::new_v4()));
        let repo = root.join("repo");
        let envs = root.join("envs");
        std::fs::create_dir_all(repo.join("echo_mcp")).unwrap();
        std::fs::write(
            repo.join("pyproject.toml"),
            "[project]\nname='echo-mcp'\nversion='0.1.0'\n[project.scripts]\necho-mcp='echo_mcp:main'\n[build-system]\nrequires=['hatchling']\nbuild-backend='hatchling.build'\n",
        )
        .unwrap();
        std::fs::write(repo.join("echo_mcp/__init__.py"), "def main():\n    print('ok')\n").unwrap();
        let g = |args: &[&str]| Sync::new("git").args(args).current_dir(&repo).output().unwrap();
        g(&["init", "-q", "-b", "main"]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        g(&["add", "-A"]);
        g(&["commit", "-qm", "v1"]);
        let sha = String::from_utf8(g(&["rev-parse", "HEAD"]).stdout).unwrap().trim().to_string();

        let repo_url = format!("file://{}", repo.display());
        let env_dir = envs.to_string_lossy().into_owned();
        build_env(&env_dir, "inst1", &repo_url, &sha).await.unwrap();

        // The built env survived the relocation and the entry point runs.
        let def = git_def(Some("echo-mcp"), &[]);
        let (program, args) = launch_command(&env_dir, "inst1", &def).unwrap();
        let out = Sync::new(&program).args(&args).output().unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn resolve_commit_reads_a_local_repo() {
        use std::process::Command as Sync;
        let dir = std::env::temp_dir().join(format!("mcp_hub_gittest_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let git = |args: &[&str]| {
            Sync::new("git")
                .args(args)
                .current_dir(&dir)
                .output()
                .unwrap()
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        std::fs::write(dir.join("f"), "x").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-qm", "init"]);
        let head = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_string();

        let repo = format!("file://{}", dir.display());
        let sha = resolve_commit(&repo, "main").await.unwrap();
        assert_eq!(sha, head);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

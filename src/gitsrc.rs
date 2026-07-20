//! Git-sourced backends: build a repo into a prebuilt environment once (a
//! virtualenv for Python via uv, a `bin/` of compiled binaries for Go), then
//! run it directly so connecting never fetches or installs. Updates are
//! explicit. The language is detected from the repo root: `go.mod` → Go,
//! `pyproject.toml`/`setup.py` → Python.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sqlx::SqlitePool;
use tokio::process::Command;

use crate::instances::{self, Instance, ServerDef};
use crate::sandbox::Sandbox;

const LS_REMOTE_TIMEOUT: Duration = Duration::from_secs(30);
// Generous enough for a cold Go build (module downloads + compile) as well as
// a uv install.
const BUILD_TIMEOUT: Duration = Duration::from_secs(900);

/// Result of an update request.
pub struct UpdateReport {
    pub changed: bool,
    pub previous_commit: Option<String>,
    pub commit: String,
}

/// The on-disk built-environment path for an instance.
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
/// first token resolves to `<env>/bin/<command>` so console scripts, `python`,
/// and compiled Go binaries all come from the built environment; the rest of
/// the command line is passed through unchanged.
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

/// Language of a git source, detected from files at the checkout root.
enum Lang {
    Python,
    Go,
}

fn detect_lang(checkout: &Path) -> Result<Lang> {
    if checkout.join("go.mod").is_file() {
        return Ok(Lang::Go);
    }
    if checkout.join("pyproject.toml").is_file() || checkout.join("setup.py").is_file() {
        return Ok(Lang::Python);
    }
    bail!("cannot determine how to build this repo: no go.mod or pyproject.toml/setup.py at its root")
}

/// Check out `commit` from `repo` into `dest`. No repo code executes here —
/// git never runs hooks from a fetched repository. Tries a shallow
/// fetch-by-SHA first (GitHub and most hosts allow it), falling back to a
/// full clone for hosts that reject it.
async fn clone_at_commit(repo: &str, commit: &str, dest: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest).context("creating source checkout dir")?;
    let dest_s = dest.to_string_lossy().into_owned();
    let shallow: Result<()> = async {
        run_git(&["init", "-q", &dest_s]).await?;
        run_git(&["-C", &dest_s, "fetch", "-q", "--depth", "1", repo, commit]).await?;
        run_git(&["-C", &dest_s, "checkout", "-q", "--detach", "FETCH_HEAD"]).await
    }
    .await;
    if let Err(e) = shallow {
        tracing::debug!(error = %e, repo, "shallow fetch-by-sha failed; falling back to a full clone");
        let _ = std::fs::remove_dir_all(dest);
        run_git(&["clone", "-q", repo, &dest_s]).await?;
        run_git(&["-C", &dest_s, "checkout", "-q", "--detach", commit]).await?;
    }
    Ok(())
}

async fn run_git(args: &[&str]) -> Result<()> {
    let out = tokio::time::timeout(
        BUILD_TIMEOUT,
        Command::new("git")
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output(),
    )
    .await
    .context("git command timed out")?
    .context("running git")?;
    if !out.status.success() {
        let verb = args
            .iter()
            .find(|a| matches!(**a, "init" | "fetch" | "checkout" | "clone"))
            .copied()
            .unwrap_or("command");
        bail!(
            "git {verb} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Build `git+<repo>@<commit>` into a fresh virtualenv, swapping it in
/// atomically on success. Slow; only ever called from an update.
///
/// Installing the package runs its build backend — i.e. **arbitrary code** from
/// the repo — so when `sandbox` is set that step is dropped to the owner's
/// unprivileged UID. Without this it would run as the hub's (root) identity and
/// could read the master key and the secrets DB, defeating the runtime sandbox.
async fn build_env(
    env_dir: &str,
    instance_id: &str,
    repo: &str,
    commit: &str,
    sandbox: Option<&Sandbox>,
) -> Result<()> {
    std::fs::create_dir_all(env_dir).context("creating env directory")?;
    let final_path = env_path(env_dir, instance_id);
    let tmp = Path::new(env_dir).join(format!(".{instance_id}.building"));
    let _ = std::fs::remove_dir_all(&tmp);

    let python = tmp.join("bin").join("python");
    let spec = format!("git+{repo}@{commit}");

    // 1) Create the venv as the hub (no sandbox): this only links the shared
    //    managed interpreter and runs no repo code. `--relocatable` is essential:
    //    we build under a temp path and rename it into place, and a
    //    non-relocatable venv hardcodes its build-time path into console-script
    //    shebangs, which the move breaks.
    run_uv(&["venv", "--relocatable", &tmp.to_string_lossy()], env_dir, None).await?;

    // The shared interpreter must be readable/executable by the sandbox UID
    // before that UID uses it to install (step 3). Best-effort.
    let py_dir = python_install_dir(env_dir);
    if py_dir.exists() {
        if let Err(e) = crate::sandbox::make_world_traversable(&py_dir) {
            tracing::warn!(error = %e, "could not relax permissions on shared python dir");
        }
    }

    // 2) Hand the temp venv to the sandbox UID so the install can write into it.
    if let Some(sb) = sandbox {
        crate::sandbox::chown_recursive(&tmp.to_string_lossy(), sb.uid, sb.gid)
            .context("handing build dir to sandbox uid")?;
    }

    // 3) Install the package + deps — running its build backend — as the sandbox
    //    UID when one is set, so a malicious repo cannot execute code as root.
    run_uv(
        &["pip", "install", "--python", &python.to_string_lossy(), &spec],
        env_dir,
        sandbox,
    )
    .await?;

    // 4) Swap in atomically (as the hub; root may rename the UID-owned tree).
    let _ = std::fs::remove_dir_all(&final_path);
    std::fs::rename(&tmp, &final_path).context("installing built environment")?;

    // 5) Ensure the whole venv is owned by the sandbox UID that will run it.
    if let Some(sb) = sandbox {
        if let Err(e) =
            crate::sandbox::chown_recursive(&final_path.to_string_lossy(), sb.uid, sb.gid)
        {
            tracing::warn!(error = %e, "could not chown built venv to sandbox uid");
        }
    }
    Ok(())
}

/// Build a Go checkout into an env whose `bin/` holds the compiled binaries,
/// swapping it in atomically on success. Slow; only ever called from an update.
///
/// `go build` evaluates repo-controlled inputs (module fetches, go.mod
/// toolchain directives), so like the Python install it runs as the owner's
/// unprivileged UID when `sandbox` is set.
async fn build_go_env(
    env_dir: &str,
    instance_id: &str,
    src: &Path,
    def: &ServerDef,
    sandbox: Option<&Sandbox>,
) -> Result<()> {
    std::fs::create_dir_all(env_dir).context("creating env directory")?;
    let final_path = env_path(env_dir, instance_id);
    let tmp = Path::new(env_dir).join(format!(".{instance_id}.building"));
    let _ = std::fs::remove_dir_all(&tmp);
    let bin = tmp.join("bin");
    std::fs::create_dir_all(&bin).context("creating build output dir")?;

    // 1) The build reads the checkout (go.sum verification, embeds) and writes
    //    bin/, both as the sandbox UID.
    if let Some(sb) = sandbox {
        crate::sandbox::chown_recursive(&src.to_string_lossy(), sb.uid, sb.gid)
            .context("handing source checkout to sandbox uid")?;
        crate::sandbox::chown_recursive(&tmp.to_string_lossy(), sb.uid, sb.gid)
            .context("handing build dir to sandbox uid")?;
    }

    // 2) Build the conventional cmd/<name> package when the command names one;
    //    otherwise build every package (`./...` fails if anything in the repo
    //    fails to compile, so prefer the narrow target).
    let entry = def.command.as_deref().map(str::trim).unwrap_or("");
    let target = if !entry.is_empty() && src.join("cmd").join(entry).is_dir() {
        format!("./cmd/{entry}")
    } else {
        "./...".to_string()
    };
    let out_dir = format!("{}/", bin.to_string_lossy());
    run_go(&["build", "-o", &out_dir, &target], env_dir, src, sandbox).await?;

    // 3) The command's first token must name one of the built binaries, or the
    //    launch path resolved by `launch_command` will not exist.
    if entry.is_empty() || !bin.join(entry).is_file() {
        let mut built: Vec<String> = std::fs::read_dir(&bin)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        built.sort();
        bail!(
            "command '{entry}' does not name a built binary; the build produced: {}",
            if built.is_empty() { "(nothing)".to_string() } else { built.join(", ") }
        );
    }

    // 4) Swap in atomically (as the hub; root may rename the UID-owned tree).
    let _ = std::fs::remove_dir_all(&final_path);
    std::fs::rename(&tmp, &final_path).context("installing built environment")?;

    // 5) Ensure the env is owned by the sandbox UID that will run it. The
    //    binaries are static and 0755, so no relocation or permission dance.
    if let Some(sb) = sandbox {
        if let Err(e) =
            crate::sandbox::chown_recursive(&final_path.to_string_lossy(), sb.uid, sb.gid)
        {
            tracing::warn!(error = %e, "could not chown built env to sandbox uid");
        }
    }
    Ok(())
}

async fn run_go(
    args: &[&str],
    env_dir: &str,
    workdir: &Path,
    sandbox: Option<&Sandbox>,
) -> Result<()> {
    let mut cmd = Command::new("go");
    cmd.args(args)
        .current_dir(workdir)
        // Static binaries: the runtime image has no C toolchain, and static
        // output keeps working after the env is renamed into place.
        .env("CGO_ENABLED", "0")
        .env("GOFLAGS", "-trimpath")
        // Let a go.mod `go`/`toolchain` directive fetch a newer, sumdb-verified
        // toolchain into the (per-user) cache when the image's Go is too old.
        // Costs reproducibility against the image pin; buys not rebuilding the
        // image every time a repo bumps its Go requirement.
        .env("GOTOOLCHAIN", "auto")
        .env("GIT_TERMINAL_PROMPT", "0");
    match sandbox {
        // Run as the owner's unprivileged UID with the module/build caches in
        // that user's own writable sandbox directory (never shared/writable
        // across users, so one user cannot poison another's build cache).
        Some(sb) => {
            cmd.uid(sb.uid)
                .gid(sb.gid)
                .env("HOME", &sb.cache_dir)
                .env("USER", "mcp-sandbox")
                .env("GOPATH", format!("{}/go", sb.cache_dir))
                .env("GOMODCACHE", format!("{}/go-mod", sb.cache_dir))
                .env("GOCACHE", format!("{}/go-build", sb.cache_dir));
        }
        None => {
            let cache = Path::new(env_dir).join(".go-cache");
            cmd.env("GOPATH", cache.join("gopath"))
                .env("GOMODCACHE", cache.join("mod"))
                .env("GOCACHE", cache.join("build"));
        }
    }
    let out = tokio::time::timeout(BUILD_TIMEOUT, cmd.output())
        .await
        .context("go build timed out")?
        .context("running go (is the Go toolchain installed?)")?;
    if !out.status.success() {
        // Compiler output is long and the errors are at the end; keep the tail.
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "go {} failed: {}",
            args.first().copied().unwrap_or(""),
            tail_str(stderr.trim(), 3000)
        );
    }
    Ok(())
}

/// The trailing `max` bytes of `s`, trimmed forward to a char boundary.
fn tail_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut idx = s.len() - max;
    while !s.is_char_boundary(idx) {
        idx += 1;
    }
    &s[idx..]
}

/// The shared directory uv installs managed Python interpreters into. Kept on
/// the data volume (not root's home) so unprivileged sandbox UIDs can reach the
/// interpreter a built venv symlinks to.
fn python_install_dir(env_dir: &str) -> PathBuf {
    Path::new(env_dir).join(".uv-python")
}

/// Whether a *built* git venv must be rebuilt to run under the current layout:
/// its `bin/python` still resolves outside the shared interpreter dir (an old
/// build under root's home, which sandbox UIDs cannot exec). False for non-git
/// instances and for ones not yet built. Callers use this to transparently
/// re-build venvs created before the interpreter was relocated.
pub fn venv_is_stale(env_dir: &str, inst: &Instance, def: &ServerDef) -> bool {
    def.is_git()
        && inst.build_status == "ready"
        && env_path(env_dir, &inst.id).exists()
        && env_is_python_venv(env_dir, &inst.id)
        && !venv_python_is_shared(env_dir, &inst.id)
}

/// Whether a built env is a Python virtualenv (vs. a Go env, whose `bin/`
/// holds only compiled binaries). Uses `symlink_metadata` so a *dangling*
/// legacy `bin/python` symlink still counts as Python and still takes the
/// stale-venv heal path above.
fn env_is_python_venv(env_dir: &str, instance_id: &str) -> bool {
    let link = env_path(env_dir, instance_id).join("bin").join("python");
    std::fs::symlink_metadata(link).is_ok()
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

async fn run_uv(args: &[&str], env_dir: &str, sandbox: Option<&Sandbox>) -> Result<()> {
    let mut cmd = Command::new("uv");
    cmd.args(args)
        // Install managed interpreters under the data volume rather than root's
        // home, so the venv's `bin/python` symlink resolves to a path sandbox
        // UIDs can traverse and execute.
        .env("UV_PYTHON_INSTALL_DIR", python_install_dir(env_dir))
        .env("GIT_TERMINAL_PROMPT", "0");
    match sandbox {
        // Run as the owner's unprivileged UID, with HOME and the package cache in
        // that user's own writable sandbox directory (never shared/writable
        // across users, so one user cannot poison another's build cache).
        Some(sb) => {
            cmd.uid(sb.uid)
                .gid(sb.gid)
                .env("HOME", &sb.cache_dir)
                .env("USER", "mcp-sandbox")
                .env("UV_CACHE_DIR", format!("{}/uv", sb.cache_dir));
        }
        None => {
            cmd.env("UV_CACHE_DIR", Path::new(env_dir).join(".uv-cache"));
        }
    }
    let out = tokio::time::timeout(BUILD_TIMEOUT, cmd.output())
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
    sandbox: Option<&Sandbox>,
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
        // it relinks to the shared, world-readable interpreter. Go envs have no
        // interpreter and never take this heal path.
        && (!env_is_python_venv(env_dir, &inst.id) || venv_python_is_shared(env_dir, &inst.id));
    if already_built {
        return Ok(UpdateReport {
            changed: false,
            previous_commit: inst.built_commit.clone(),
            commit,
        });
    }

    // Check the repo out once to detect its language; the Go build compiles
    // from this checkout, while the Python path lets uv re-fetch the repo.
    std::fs::create_dir_all(env_dir).context("creating env directory")?;
    let src = Path::new(env_dir).join(format!(".{}.src", inst.id));
    let build_result: Result<()> = async {
        clone_at_commit(repo, &commit, &src).await?;
        match detect_lang(&src)? {
            Lang::Python => {
                let _ = std::fs::remove_dir_all(&src);
                build_env(env_dir, &inst.id, repo, &commit, sandbox).await
            }
            Lang::Go => build_go_env(env_dir, &inst.id, &src, def, sandbox).await,
        }
    }
    .await;
    let _ = std::fs::remove_dir_all(&src);

    match build_result {
        Ok(()) => {
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

    fn instance(id: &str, build_status: &str) -> Instance {
        Instance {
            id: id.into(),
            user_id: "u".into(),
            catalog_server_id: None,
            custom_def: None,
            namespace: "ns".into(),
            display_name: "ns".into(),
            enabled: true,
            config: Default::default(),
            built_commit: Some("abc".into()),
            build_status: build_status.into(),
        }
    }

    #[test]
    fn detects_language_from_checkout_root() {
        let root = std::env::temp_dir().join(format!("mcp_hub_langtest_{}", uuid::Uuid::new_v4()));

        let go = root.join("go");
        std::fs::create_dir_all(&go).unwrap();
        std::fs::write(go.join("go.mod"), "module example.com/x\n").unwrap();
        assert!(matches!(detect_lang(&go), Ok(Lang::Go)));

        let py = root.join("py");
        std::fs::create_dir_all(&py).unwrap();
        std::fs::write(py.join("pyproject.toml"), "[project]\n").unwrap();
        assert!(matches!(detect_lang(&py), Ok(Lang::Python)));

        // go.mod wins if both are present (a Go repo may vendor Python tooling).
        std::fs::write(py.join("go.mod"), "module example.com/y\n").unwrap();
        assert!(matches!(detect_lang(&py), Ok(Lang::Go)));

        let neither = root.join("none");
        std::fs::create_dir_all(&neither).unwrap();
        assert!(detect_lang(&neither).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A built Go env has no `bin/python`; it must be neither "stale" (which
    /// would flag a rebuild forever) nor rebuilt when already at the commit.
    #[test]
    fn go_env_is_not_python_and_never_stale() {
        let root = std::env::temp_dir().join(format!("mcp_hub_stalttest_{}", uuid::Uuid::new_v4()));
        let env_dir = root.to_string_lossy().into_owned();
        let bin = root.join("go-inst").join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("my-mcp"), "").unwrap();

        assert!(!env_is_python_venv(&env_dir, "go-inst"));
        let inst = instance("go-inst", "ready");
        let def = git_def(Some("my-mcp"), &[]);
        assert!(!venv_is_stale(&env_dir, &inst, &def));

        // A venv whose bin/python dangles (legacy build) still reads as Python
        // and still takes the stale-heal path.
        let pybin = root.join("py-inst").join("bin");
        std::fs::create_dir_all(&pybin).unwrap();
        std::os::unix::fs::symlink("/nonexistent/python", pybin.join("python")).unwrap();
        assert!(env_is_python_venv(&env_dir, "py-inst"));
        let inst = instance("py-inst", "ready");
        assert!(venv_is_stale(&env_dir, &inst, &def));

        let _ = std::fs::remove_dir_all(&root);
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
        build_env(&env_dir, "inst1", &repo_url, &sha, None).await.unwrap();

        // The built env survived the relocation and the entry point runs.
        let def = git_def(Some("echo-mcp"), &[]);
        let (program, args) = launch_command(&env_dir, "inst1", &def).unwrap();
        let out = Sync::new(&program).args(&args).output().unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Full Go clone → build → run against a local git repo. Ignored by
    /// default because it needs the Go toolchain (and go may fetch a newer
    /// toolchain per go.mod). Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "needs the Go toolchain"]
    async fn build_go_env_produces_a_runnable_binary() {
        use std::process::Command as Sync;
        let root = std::env::temp_dir().join(format!("mcp_hub_gobuildtest_{}", uuid::Uuid::new_v4()));
        let repo = root.join("repo");
        let envs = root.join("envs");
        std::fs::create_dir_all(repo.join("cmd/echo-mcp")).unwrap();
        std::fs::write(repo.join("go.mod"), "module example.com/echo\n\ngo 1.21\n").unwrap();
        std::fs::write(
            repo.join("cmd/echo-mcp/main.go"),
            "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"ok\") }\n",
        )
        .unwrap();
        let g = |args: &[&str]| Sync::new("git").args(args).current_dir(&repo).output().unwrap();
        g(&["init", "-q", "-b", "main"]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        g(&["add", "-A"]);
        g(&["commit", "-qm", "v1"]);
        let sha = String::from_utf8(g(&["rev-parse", "HEAD"]).stdout).unwrap().trim().to_string();

        let repo_url = format!("file://{}", repo.display());
        let env_dir = envs.to_string_lossy().into_owned();
        let src = envs.join(".inst1.src");
        std::fs::create_dir_all(&envs).unwrap();
        clone_at_commit(&repo_url, &sha, &src).await.unwrap();
        assert!(matches!(detect_lang(&src), Ok(Lang::Go)));

        // The command must name a built binary.
        let bad = git_def(Some("no-such-binary"), &[]);
        let err = build_go_env(&env_dir, "inst1", &src, &bad, None).await.unwrap_err();
        assert!(err.to_string().contains("does not name a built binary"), "{err}");

        let def = git_def(Some("echo-mcp"), &[]);
        build_go_env(&env_dir, "inst1", &src, &def, None).await.unwrap();

        // A Go env resolves and runs through the same launch path as a venv,
        // and reads as neither Python nor stale.
        let (program, args) = launch_command(&env_dir, "inst1", &def).unwrap();
        let out = Sync::new(&program).args(&args).output().unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
        assert!(!env_is_python_venv(&env_dir, "inst1"));
        assert!(!venv_is_stale(&env_dir, &instance("inst1", "ready"), &def));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn clone_at_commit_checks_out_a_local_repo() {
        use std::process::Command as Sync;
        let root = std::env::temp_dir().join(format!("mcp_hub_clonetest_{}", uuid::Uuid::new_v4()));
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let g = |args: &[&str]| Sync::new("git").args(args).current_dir(&repo).output().unwrap();
        g(&["init", "-q", "-b", "main"]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        std::fs::write(repo.join("go.mod"), "module example.com/x\n").unwrap();
        g(&["add", "-A"]);
        g(&["commit", "-qm", "v1"]);
        let sha = String::from_utf8(g(&["rev-parse", "HEAD"]).stdout).unwrap().trim().to_string();

        let dest = root.join("checkout");
        clone_at_commit(&format!("file://{}", repo.display()), &sha, &dest)
            .await
            .unwrap();
        assert!(dest.join("go.mod").is_file());

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

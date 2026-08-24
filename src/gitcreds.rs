//! Per-user git credentials, keyed by git host.
//!
//! One HTTPS token per (user, host), so a single personal access token covers
//! every private repo on that host and rotating it is one edit. At build time
//! the credential matching a git source's repo host is decrypted and handed to
//! git through the environment (see [`crate::gitsrc::credential_env`]).
//! Plaintext exists in memory only for the duration of a build; it is never
//! returned to the UI, never logged, and never placed on a command line.

use anyhow::{anyhow, bail, Context, Result};
use sqlx::SqlitePool;
use url::Url;

use crate::crypto::{Sealed, SecretBox};
use crate::util::{new_id, now_unix};

/// The username sent when the user left it blank. Every major host accepts an
/// arbitrary username with a token as the password; this is GitHub's convention
/// (GitLab uses `oauth2`, Bitbucket `x-token-auth`).
pub const DEFAULT_USERNAME: &str = "x-access-token";

/// Longest token we will store. Comfortably above any real PAT.
const MAX_TOKEN_LEN: usize = 512;

/// Metadata about a stored credential. Never carries the token.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GitCredential {
    pub id: String,
    pub host: String,
    pub username: String,
    pub label: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}

/// Columns selected into [`GitCredential`] — deliberately not `SELECT *`, so a
/// future column cannot accidentally carry the ciphertext into a listing.
const CRED_COLS: &str = "id, host, username, label, created_at, updated_at, last_used_at";

/// A decrypted credential, alive only for the duration of one build.
#[derive(Clone)]
pub struct ResolvedCredential {
    pub id: String,
    /// Normalised host, exactly as git's `credential.<url>` matcher needs it:
    /// `github.com`, `gl.example.com:8443`.
    pub host: String,
    /// Always non-empty — [`DEFAULT_USERNAME`] when the user left it blank.
    pub username: String,
    pub token: String,
}

/// Redacts the token, so a stray `{:?}` in a log or an error cannot leak it.
impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("host", &self.host)
            .field("username", &self.username)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Normalise a user-typed host, or a full repo URL, into the storage/lookup
/// key: lowercase, no scheme, no path, and the default port 443 dropped —
/// matching how git itself normalises a `credential.<url>` key.
///
/// Accepts `github.com`, `github.com:8443`, `https://github.com`,
/// `https://github.com/owner/repo.git` and `git+https://github.com/owner/repo`.
pub fn normalize_host(input: &str) -> Result<String> {
    let raw = input.trim();
    let raw = raw.strip_prefix("git+").unwrap_or(raw);
    if raw.is_empty() {
        bail!("a git host is required");
    }
    // A bare host (optionally with a port or a path) is parsed as https so the
    // url crate applies the same lowercasing and default-port rules either way.
    let parsed = if raw.contains("://") {
        Url::parse(raw).with_context(|| format!("'{input}' is not a valid git host or URL"))?
    } else {
        Url::parse(&format!("https://{raw}"))
            .with_context(|| format!("'{input}' is not a valid git host or URL"))?
    };
    if parsed.scheme() != "https" {
        bail!(
            "only https git hosts are supported (got '{}://'); ssh keys are not handled yet",
            parsed.scheme()
        );
    }
    // A token pasted into the URL must be a loud error rather than a silently
    // stored host — it would otherwise sit in plaintext in the repo field.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("remove the credentials from the URL: enter the host on its own and put the token in the token field");
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("'{input}' has no host"))?;
    // `port()` is None for the scheme's default (443), which is exactly the
    // form git matches against.
    Ok(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// The normalised host of a [`crate::instances::ServerDef::repo`] value, or
/// `None` if it has none (or is not a form we can authenticate).
pub fn host_of_repo(repo: &str) -> Option<String> {
    normalize_host(repo).ok()
}

/// Validate a token before sealing it. The control-character rule is a security
/// check, not hygiene: git's credential protocol is line-oriented, so a `\n`
/// inside a token would inject an extra field into the helper's reply.
pub fn validate_token(token: &str) -> Result<()> {
    if token.is_empty() {
        bail!("a token is required");
    }
    if token.len() > MAX_TOKEN_LEN {
        bail!("token is too long (max {MAX_TOKEN_LEN} bytes)");
    }
    if token.chars().any(|c| c.is_control()) {
        bail!("token contains a control character — paste it without line breaks");
    }
    Ok(())
}

/// The same rule for the username, which travels the same protocol.
fn validate_username(username: &str) -> Result<()> {
    if username.len() > MAX_TOKEN_LEN {
        bail!("username is too long");
    }
    if username.chars().any(|c| c.is_control()) {
        bail!("username contains a control character");
    }
    Ok(())
}

/// A user's credentials, by host.
pub async fn list_for_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<GitCredential>> {
    let rows = sqlx::query_as::<_, GitCredential>(&format!(
        "SELECT {CRED_COLS} FROM git_credentials WHERE user_id = ? ORDER BY host"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// One host's credential metadata, if the user has stored one. `host` is
/// normalised here, so callers may pass a repo URL.
pub async fn find(pool: &SqlitePool, user_id: &str, host: &str) -> Result<Option<GitCredential>> {
    let host = normalize_host(host)?;
    let row = sqlx::query_as::<_, GitCredential>(&format!(
        "SELECT {CRED_COLS} FROM git_credentials WHERE user_id = ? AND host = ?"
    ))
    .bind(user_id)
    .bind(&host)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Store (or replace) the token for one host. `host_input` may be a bare host
/// or a full repo URL; an empty `username` means [`DEFAULT_USERNAME`].
///
/// The token is trimmed first: a paste almost always carries a trailing
/// newline, and rejecting that as a control character would be baffling.
pub async fn upsert(
    pool: &SqlitePool,
    secrets: &SecretBox,
    user_id: &str,
    host_input: &str,
    username: &str,
    label: &str,
    token: &str,
) -> Result<GitCredential> {
    let host = normalize_host(host_input)?;
    let username = username.trim();
    let token = token.trim();
    validate_username(username)?;
    validate_token(token)?;

    let sealed = secrets.seal(token.as_bytes())?;
    let now = now_unix();
    sqlx::query(
        "INSERT INTO git_credentials (id, user_id, host, username, nonce, ciphertext, label, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, host) DO UPDATE SET
             username = excluded.username,
             nonce = excluded.nonce,
             ciphertext = excluded.ciphertext,
             label = excluded.label,
             updated_at = excluded.updated_at",
    )
    .bind(new_id())
    .bind(user_id)
    .bind(&host)
    .bind(username)
    .bind(&sealed.nonce)
    .bind(&sealed.ciphertext)
    .bind(label.trim())
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .context("storing git credential")?;

    find(pool, user_id, &host)
        .await?
        .ok_or_else(|| anyhow!("git credential vanished right after it was stored"))
}

/// Remove a host's credential. Ownership-scoped so a user can only delete their
/// own. Returns whether a row was deleted.
pub async fn delete(pool: &SqlitePool, user_id: &str, host: &str) -> Result<bool> {
    let host = normalize_host(host)?;
    let res = sqlx::query("DELETE FROM git_credentials WHERE user_id = ? AND host = ?")
        .bind(user_id)
        .bind(&host)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Decrypt the credential for `repo`'s host, if this user has one.
///
/// `Ok(None)` means "no credential" — the build proceeds anonymously, as it
/// always has. A credential that exists but cannot be decrypted is a hard,
/// actionable error rather than a silent fall-through to an anonymous build,
/// which would surface as a confusing 404 from the host.
pub async fn for_repo(
    pool: &SqlitePool,
    secrets: &SecretBox,
    user_id: &str,
    repo: &str,
) -> Result<Option<ResolvedCredential>> {
    let Some(host) = host_of_repo(repo) else {
        return Ok(None);
    };
    let row: Option<(String, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, username, nonce, ciphertext FROM git_credentials WHERE user_id = ? AND host = ?",
    )
    .bind(user_id)
    .bind(&host)
    .fetch_optional(pool)
    .await?;
    let Some((id, username, nonce, ciphertext)) = row else {
        return Ok(None);
    };

    let plain = secrets.open(&Sealed { nonce, ciphertext }).with_context(|| {
        format!("the git credential for {host} could not be decrypted — re-enter it on your Account page")
    })?;
    let token = String::from_utf8(plain).context("git credential was not UTF-8")?;
    let username = if username.trim().is_empty() {
        DEFAULT_USERNAME.to_string()
    } else {
        username
    };
    Ok(Some(ResolvedCredential {
        id,
        host,
        username,
        token,
    }))
}

/// Record that a credential was just used for a build. Best-effort: callers
/// ignore the result so a build never fails on a bookkeeping write.
pub async fn touch(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE git_credentials SET last_used_at = ? WHERE id = ?")
        .bind(now_unix())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        for (id, handle) in [("u1", "alice"), ("u2", "bob")] {
            sqlx::query("INSERT INTO users (id, handle, display_name, is_admin, created_at) VALUES (?,?,?,0,0)")
                .bind(id)
                .bind(handle)
                .bind(handle)
                .execute(&pool)
                .await
                .unwrap();
        }
        pool
    }

    fn secrets() -> SecretBox {
        SecretBox::new(&[7u8; 32])
    }

    #[test]
    fn normalizes_hosts() {
        for (input, want) in [
            ("github.com", "github.com"),
            ("GitHub.com", "github.com"),
            ("  github.com  ", "github.com"),
            ("https://github.com", "github.com"),
            ("https://github.com/owner/repo.git", "github.com"),
            ("git+https://github.com/owner/repo", "github.com"),
            // git normalises away the default port, so we must too.
            ("https://github.com:443/x", "github.com"),
            ("gl.example.com:8443", "gl.example.com:8443"),
            ("https://gl.example.com:8443/x/y", "gl.example.com:8443"),
            // Deliberately NOT stripped: git matches the literal host, so a
            // credential stored as github.com would never be offered here.
            ("www.github.com", "www.github.com"),
        ] {
            assert_eq!(normalize_host(input).unwrap(), want, "input {input:?}");
        }

        for bad in [
            "",
            "   ",
            "ssh://git@github.com/x",
            "git@github.com:owner/repo.git",
            "http://github.com",
            "file:///tmp/repo",
            // A token pasted into the URL must be rejected, not quietly kept.
            "https://user:ghp_secret@github.com/o/r",
            "https://ghp_secret@github.com/o/r",
            "not a host",
        ] {
            assert!(
                normalize_host(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn token_validation_rejects_control_characters() {
        // git's credential protocol is line-oriented: a newline in a token
        // would inject a field into the helper's reply.
        for bad in ["", "ghp_a\nb", "ghp_a\rb", "ghp_a\tb", "ghp_a\0b"] {
            assert!(
                validate_token(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        assert!(validate_token(&"x".repeat(MAX_TOKEN_LEN + 1)).is_err());
        assert!(validate_token(&"x".repeat(MAX_TOKEN_LEN)).is_ok());
        assert!(validate_token("ghp_abc123").is_ok());
    }

    #[tokio::test]
    async fn upsert_encrypts_and_replaces() {
        let pool = pool().await;
        let sb = secrets();
        let token = "ghp_super_secret_value";

        let cred = upsert(
            &pool,
            &sb,
            "u1",
            "https://github.com/o/r",
            "",
            "laptop",
            token,
        )
        .await
        .unwrap();
        assert_eq!(cred.host, "github.com");
        assert_eq!(cred.username, "");
        assert_eq!(cred.label, "laptop");

        // The plaintext appears nowhere in the stored row.
        let (nonce, ct): (Vec<u8>, Vec<u8>) =
            sqlx::query_as("SELECT nonce, ciphertext FROM git_credentials WHERE id = ?")
                .bind(&cred.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!ct.windows(token.len()).any(|w| w == token.as_bytes()));
        assert_eq!(nonce.len(), crate::crypto::NONCE_LEN);

        // Re-saving the same host replaces rather than duplicating.
        upsert(
            &pool,
            &sb,
            "u1",
            "github.com",
            "oauth2",
            "rotated",
            "ghp_new",
        )
        .await
        .unwrap();
        let all = list_for_user(&pool, "u1").await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].username, "oauth2");
        assert_eq!(all[0].label, "rotated");
        let resolved = for_repo(&pool, &sb, "u1", "https://github.com/o/r")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.token, "ghp_new");
        assert_eq!(resolved.username, "oauth2");

        // A trailing newline from a paste is trimmed, not rejected.
        upsert(&pool, &sb, "u1", "github.com", "", "", "ghp_pasted\n")
            .await
            .unwrap();
        let resolved = for_repo(&pool, &sb, "u1", "https://github.com/o/r")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.token, "ghp_pasted");
        // A blank username resolves to the default.
        assert_eq!(resolved.username, DEFAULT_USERNAME);
    }

    #[tokio::test]
    async fn credentials_are_per_user() {
        let pool = pool().await;
        let sb = secrets();
        upsert(&pool, &sb, "u1", "github.com", "", "", "token-alice")
            .await
            .unwrap();
        upsert(&pool, &sb, "u2", "github.com", "", "", "token-bob")
            .await
            .unwrap();

        let repo = "https://github.com/o/r";
        assert_eq!(
            for_repo(&pool, &sb, "u1", repo)
                .await
                .unwrap()
                .unwrap()
                .token,
            "token-alice"
        );
        assert_eq!(
            for_repo(&pool, &sb, "u2", repo)
                .await
                .unwrap()
                .unwrap()
                .token,
            "token-bob"
        );

        // Deleting is ownership-scoped.
        assert!(delete(&pool, "u1", "github.com").await.unwrap());
        assert!(!delete(&pool, "u1", "github.com").await.unwrap());
        assert!(for_repo(&pool, &sb, "u1", repo).await.unwrap().is_none());
        assert!(for_repo(&pool, &sb, "u2", repo).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn for_repo_matches_only_the_exact_host() {
        let pool = pool().await;
        let sb = secrets();
        upsert(&pool, &sb, "u1", "github.com", "", "", "tok")
            .await
            .unwrap();

        for repo in [
            "https://github.com/o/r",
            "https://GITHUB.COM/O/R",
            "git+https://github.com/o/r",
            "https://github.com:443/o/r",
        ] {
            assert!(
                for_repo(&pool, &sb, "u1", repo).await.unwrap().is_some(),
                "expected {repo} to match"
            );
        }
        for repo in [
            "https://evil.com/o/r",
            // A suffix match here would hand the token to an attacker's host.
            "https://github.com.evil.net/o/r",
            "https://www.github.com/o/r",
            "https://github.com:8443/o/r",
            "",
        ] {
            assert!(
                for_repo(&pool, &sb, "u1", repo).await.unwrap().is_none(),
                "expected {repo} not to match"
            );
        }
    }

    #[tokio::test]
    async fn undecryptable_credential_is_an_actionable_error() {
        let pool = pool().await;
        upsert(&pool, &secrets(), "u1", "github.com", "", "", "tok")
            .await
            .unwrap();
        // Master key rotated out from under the row.
        let other = SecretBox::new(&[9u8; 32]);
        let err = for_repo(&pool, &other, "u1", "https://github.com/o/r")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("github.com"),
            "message should name the host: {err}"
        );
        assert!(
            err.contains("re-enter"),
            "message should say what to do: {err}"
        );
    }

    #[tokio::test]
    async fn touch_sets_last_used() {
        let pool = pool().await;
        let cred = upsert(&pool, &secrets(), "u1", "github.com", "", "", "tok")
            .await
            .unwrap();
        assert!(cred.last_used_at.is_none());
        touch(&pool, &cred.id).await.unwrap();
        assert!(find(&pool, "u1", "github.com")
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .is_some());
    }

    #[test]
    fn resolved_credential_debug_redacts_the_token() {
        let cred = ResolvedCredential {
            id: "c1".into(),
            host: "github.com".into(),
            username: "x-access-token".into(),
            token: "ghp_super_secret".into(),
        };
        let rendered = format!("{cred:?}");
        assert!(!rendered.contains("ghp_super_secret"), "{rendered}");
        assert!(rendered.contains("github.com"));
    }
}

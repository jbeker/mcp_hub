//! ES256 signing key for OAuth access tokens, plus JWT issue/verify.
//!
//! A single active EC P-256 key is generated on first boot and persisted
//! (PKCS#8 PEM) in `oauth_signing_keys`. Access tokens are stateless JWTs the
//! MCP resource server validates in-process; the public key is published as a
//! JWKS so any standards-compliant client can verify too.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::crypto::{Sealed, SecretBox, NONCE_LEN};
use crate::util::now_unix;

/// Claims carried by an access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
    pub client_id: String,
    /// Whether the subject is an administrator (used by the management tools).
    #[serde(default)]
    pub admin: bool,
}

/// Holds the active signing key and derived verification material.
pub struct Signer {
    kid: String,
    issuer: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
    public_jwk: serde_json::Value,
}

impl Signer {
    /// Load the active signing key, generating and persisting one if none exists.
    ///
    /// The private key is encrypted at rest with the master key (`secrets`), so a
    /// database compromise alone cannot forge tokens.
    pub async fn load_or_create(pool: &SqlitePool, secrets: &SecretBox, issuer: &str) -> Result<Self> {
        if let Some((kid, stored)) = load_active(pool).await? {
            let pem = unseal_pem(secrets, &stored)?;
            Self::from_pem(&kid, issuer, &pem)
        } else {
            let (kid, pem) = generate_pem()?;
            let stored = seal_pem(secrets, &pem)?;
            sqlx::query(
                "INSERT INTO oauth_signing_keys (kid, private_pkcs8_b64, created_at, active) VALUES (?, ?, ?, 1)",
            )
            .bind(&kid)
            .bind(&stored)
            .bind(now_unix())
            .execute(pool)
            .await
            .context("persisting signing key")?;
            tracing::info!(kid = %kid, "generated new ES256 signing key");
            Self::from_pem(&kid, issuer, &pem)
        }
    }

    fn from_pem(kid: &str, issuer: &str, pem: &str) -> Result<Self> {
        let secret = p256::SecretKey::from_pkcs8_pem(pem).context("parsing stored signing key")?;
        let public = secret.public_key();

        let encoding = EncodingKey::from_ec_pem(pem.as_bytes())
            .context("building JWT encoding key from EC PEM")?;
        let public_pem = public
            .to_public_key_pem(LineEnding::LF)
            .context("encoding public key PEM")?;
        let decoding = DecodingKey::from_ec_pem(public_pem.as_bytes())
            .context("building JWT decoding key")?;

        // Build the published JWK from the public key coordinates.
        let jwk = public.to_jwk();
        let mut jwk_value = serde_json::to_value(&jwk).context("serializing JWK")?;
        if let Some(obj) = jwk_value.as_object_mut() {
            obj.insert("kid".into(), kid.into());
            obj.insert("alg".into(), "ES256".into());
            obj.insert("use".into(), "sig".into());
        }

        Ok(Self {
            kid: kid.to_string(),
            issuer: issuer.to_string(),
            encoding,
            decoding,
            public_jwk: jwk_value,
        })
    }

    /// The JWKS document (`{ "keys": [ ... ] }`).
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({ "keys": [ self.public_jwk ] })
    }

    /// Issue a signed access token.
    pub fn issue_access_token(
        &self,
        subject: &str,
        client_id: &str,
        audience: &str,
        scope: &str,
        admin: bool,
        ttl_secs: i64,
    ) -> Result<(String, i64)> {
        let now = now_unix();
        let claims = AccessClaims {
            iss: self.issuer.clone(),
            sub: subject.to_string(),
            aud: audience.to_string(),
            exp: now + ttl_secs,
            iat: now,
            jti: crate::util::new_id(),
            scope: scope.to_string(),
            client_id: client_id.to_string(),
            admin,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding)
            .context("signing access token")?;
        Ok((token, ttl_secs))
    }

    /// Verify an access token and check the audience binding.
    pub fn verify_access_token(&self, token: &str, expected_audience: &str) -> Result<AccessClaims> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        validation.set_audience(&[expected_audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = jsonwebtoken::decode::<AccessClaims>(token, &self.decoding, &validation)
            .map_err(|e| anyhow!("invalid token: {e}"))?;
        Ok(data.claims)
    }
}

async fn load_active(pool: &SqlitePool) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT kid, private_pkcs8_b64 FROM oauth_signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Encrypt a PKCS#8 PEM for storage: base64(nonce || ciphertext).
fn seal_pem(secrets: &SecretBox, pem: &str) -> Result<String> {
    let sealed = secrets.seal(pem.as_bytes())?;
    let mut blob = sealed.nonce;
    blob.extend_from_slice(&sealed.ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

/// Decrypt a stored signing key. Accepts a legacy plaintext PEM for forward
/// compatibility with databases created before keys were encrypted.
fn unseal_pem(secrets: &SecretBox, stored: &str) -> Result<String> {
    if stored.starts_with("-----BEGIN") {
        return Ok(stored.to_string());
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(stored.trim())
        .context("decoding stored signing key")?;
    if blob.len() <= NONCE_LEN {
        return Err(anyhow!("stored signing key is truncated"));
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let plain = secrets.open(&Sealed {
        nonce: nonce.to_vec(),
        ciphertext: ciphertext.to_vec(),
    })?;
    String::from_utf8(plain).context("signing key was not valid UTF-8")
}

/// Generate a new ES256 key and return `(kid, pkcs8_pem)`.
fn generate_pem() -> Result<(String, String)> {
    use rand::rngs::OsRng;
    let secret = p256::SecretKey::random(&mut OsRng);
    let pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .context("encoding PKCS#8 PEM")?
        .to_string();
    let kid = crate::util::new_id();
    Ok((kid, pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        let (kid, pem) = generate_pem().unwrap();
        Signer::from_pem(&kid, "https://hub.example.com", &pem).unwrap()
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let s = signer();
        let aud = "https://hub.example.com/mcp";
        let (token, ttl) = s
            .issue_access_token("user-1", "client-1", aud, "mcp", true, 3600)
            .unwrap();
        assert_eq!(ttl, 3600);
        let claims = s.verify_access_token(&token, aud).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.client_id, "client-1");
        assert!(claims.admin);
        assert_eq!(claims.aud, aud);
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let s = signer();
        let (token, _) = s
            .issue_access_token("u", "c", "https://hub.example.com/mcp", "mcp", false, 3600)
            .unwrap();
        assert!(s
            .verify_access_token(&token, "https://evil.example.com/mcp")
            .is_err());
    }

    #[test]
    fn sealed_key_round_trips_and_resists_wrong_master() {
        let (_kid, pem) = generate_pem().unwrap();
        let good = SecretBox::new(&[7u8; 32]);
        let stored = seal_pem(&good, &pem).unwrap();
        assert!(!stored.contains("BEGIN"), "stored key must be ciphertext");
        assert_eq!(unseal_pem(&good, &stored).unwrap(), pem);

        // A different master key cannot recover the signing key.
        let bad = SecretBox::new(&[8u8; 32]);
        assert!(unseal_pem(&bad, &stored).is_err());
    }

    #[test]
    fn legacy_plaintext_pem_still_loads() {
        let (_kid, pem) = generate_pem().unwrap();
        let secrets = SecretBox::new(&[1u8; 32]);
        // A pre-encryption database stored the raw PEM.
        assert_eq!(unseal_pem(&secrets, &pem).unwrap(), pem);
    }

    #[test]
    fn jwks_has_public_fields() {
        let s = signer();
        let jwks = s.jwks();
        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert!(key["x"].is_string() && key["y"].is_string());
        assert!(key["kid"].is_string());
    }
}

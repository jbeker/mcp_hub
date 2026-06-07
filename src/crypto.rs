//! Encryption of user secrets at rest.
//!
//! Each secret is sealed independently with XChaCha20-Poly1305 using a fresh
//! random 24-byte nonce. The 32-byte master key comes from the `HUB_MASTER_KEY`
//! environment variable (see [`crate::config`]). Plaintext only ever exists in
//! memory at the moment a backend is spawned — it is never logged.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, XChaCha20Poly1305, XNonce,
};

/// Length of the XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;

/// A sealed (encrypted) secret: the random nonce plus the ciphertext+tag.
#[derive(Clone, Debug)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Encrypts and decrypts secrets using a process-wide master key.
#[derive(Clone)]
pub struct SecretBox {
    cipher: XChaCha20Poly1305,
}

impl SecretBox {
    /// Construct from the 32-byte master key.
    pub fn new(master_key: &[u8; 32]) -> Self {
        let cipher = XChaCha20Poly1305::new(master_key.into());
        Self { cipher }
    }

    /// Seal a plaintext value, producing a fresh nonce and ciphertext.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Sealed> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow!("failed to seal secret"))?;
        Ok(Sealed {
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    /// Open a previously sealed value. Returns an error if the nonce length is
    /// wrong or the authentication tag does not verify.
    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>> {
        if sealed.nonce.len() != NONCE_LEN {
            return Err(anyhow!("invalid nonce length"));
        }
        let nonce = XNonce::from_slice(&sealed.nonce);
        self.cipher
            .decrypt(nonce, sealed.ciphertext.as_ref())
            .map_err(|_| anyhow!("failed to open secret (wrong key or tampered data)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let sb = SecretBox::new(&[42u8; 32]);
        let secret = b"super-secret-zabbix-token";
        let sealed = sb.seal(secret).unwrap();
        assert_eq!(sealed.nonce.len(), NONCE_LEN);
        assert_ne!(sealed.ciphertext, secret);
        let opened = sb.open(&sealed).unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn distinct_nonces_per_seal() {
        let sb = SecretBox::new(&[1u8; 32]);
        let a = sb.seal(b"same").unwrap();
        let b = sb.seal(b"same").unwrap();
        assert_ne!(a.nonce, b.nonce, "each seal must use a fresh nonce");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let a = SecretBox::new(&[1u8; 32]);
        let b = SecretBox::new(&[2u8; 32]);
        let sealed = a.seal(b"hello").unwrap();
        assert!(b.open(&sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let sb = SecretBox::new(&[9u8; 32]);
        let mut sealed = sb.seal(b"hello world").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(sb.open(&sealed).is_err());
    }
}

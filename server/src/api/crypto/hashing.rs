use std::sync::Arc;

use anyhow::anyhow;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub fn parse_hash(hash: &str) -> anyhow::Result<PasswordHash> {
    PasswordHash::new(hash).map_err(|_| anyhow!("Failed to parse hash"))
}

pub fn hash<'a>(salt: &'a SaltString, secret: &[u8]) -> anyhow::Result<Arc<PasswordHash<'a>>> {
    let secret_hash = Argon2::default()
        .hash_password(secret, salt)
        .map_err(|_| anyhow!("Failed to hash secret"))?;

    Ok(Arc::new(secret_hash))
}

pub fn verify(secret: &[u8], hash: &PasswordHash) -> bool {
    Argon2::default().verify_password(secret, &hash).is_ok()
}

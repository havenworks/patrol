use anyhow::anyhow;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rsa::rand_core::OsRng;

pub fn parse_hash(hash: &str) -> anyhow::Result<PasswordHash> {
    PasswordHash::new(hash).map_err(|_| anyhow!("Failed to parse hash"))
}

pub fn hash(secret: &[u8]) -> anyhow::Result<(PasswordHash, SaltString)> {
    let salt = SaltString::generate(OsRng);

    let secret_hash = Argon2::default()
        .hash_password(secret, &salt)
        .map_err(|_| anyhow!("Failed to hash secret"))?;

    Ok((secret_hash, salt))
}

pub fn verify(secret: &[u8], hash: &PasswordHash) -> bool {
    Argon2::default().verify_password(secret, &hash).is_ok()
}

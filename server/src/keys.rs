use jsonwebtoken::jwk::{
    self, CommonParameters, Jwk, JwkSet, KeyOperations, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};
use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::Value;

const BITS: usize = 1024;

#[derive(Clone)]
pub struct PatrolJwkSetValue(pub Value);

#[derive(Clone)]
pub struct PatrolRsaKey(pub RsaPrivateKey);

pub fn generate_keys() -> (PatrolRsaKey, PatrolJwkSetValue) {
    let mut rng = rand::thread_rng();

    let mut jwks = JwkSet { keys: Vec::new() };

    let private_key = RsaPrivateKey::new(&mut rng, BITS).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let jwk = Jwk {
        algorithm: jwk::AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: jwk::RSAKeyType::RSA,
            n: base64_url::encode(&public_key.n().to_string()),
            e: base64_url::encode(&public_key.e().to_string()),
        }),
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Encryption),
            key_operations: Some(vec![KeyOperations::Encrypt]),
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
    };

    jwks.keys.push(jwk);

    (
        PatrolRsaKey(private_key),
        PatrolJwkSetValue(serde_json::to_value(jwks).unwrap()),
    )
}

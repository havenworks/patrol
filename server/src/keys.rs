use jsonwebtoken::jwk::{
    self, CommonParameters, Jwk, JwkSet, KeyOperations, RSAKeyParameters, RSAKeyType,
};
use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde_json::Value;

const BITS: usize = 3072;

#[derive(Clone)]
pub struct PatrolJwkSetValue(pub Value);

#[derive(Clone)]
pub struct PatrolJwkSet(pub JwkSet);

pub fn generate_keys() -> (PatrolJwkSet, PatrolJwkSetValue) {
    let mut rng = rand::thread_rng();
    let mut jwks: Vec<Jwk> = Vec::new();

    for k in 0..6 {
        println!("{}", k);
        let private_key = RsaPrivateKey::new(&mut rng, BITS).unwrap();
        let public_key = RsaPublicKey::from(private_key);

        let jwk = jwk::Jwk {
            algorithm: jwk::AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: jwk::RSAKeyType::RSA,
                n: public_key.n().to_string(),
                e: public_key.e().to_string(),
            }),
            common: CommonParameters {
                public_key_use: None,
                key_operations: Some(vec![if k % 2 == 0 {
                    KeyOperations::Encrypt
                } else {
                    KeyOperations::Verify
                }]),
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
        };

        jwks.push(jwk);
    }

    let jwks = JwkSet { keys: jwks };

    (
        PatrolJwkSet(jwks.clone()),
        PatrolJwkSetValue(serde_json::to_value(jwks).unwrap()),
    )
}

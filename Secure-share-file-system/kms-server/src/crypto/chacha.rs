use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Serialize)]
pub struct WrappedPayload {
    pub server_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn wrap_dek(aes_dek: &[u8], agent_public_key_bytes: &[u8]) -> Result<WrappedPayload, String> {
    if agent_public_key_bytes.len() != 32 {
        return Err("Invalid Agent Public Key length".to_string());
    }
    
    // Parse Agent's Public Key
    let mut agent_key_array = [0u8; 32];
    agent_key_array.copy_from_slice(agent_public_key_bytes);
    let agent_public = PublicKey::from(agent_key_array);

    // Generate Server's Ephemeral Keypair
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);

    // ECDH Key Exchange
    let shared_secret = server_secret.diffie_hellman(&agent_public);

    // Derive 32-byte ChaCha20 Key via HKDF
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut chacha_key = [0u8; 32];
    hkdf.expand(b"kms-dek-wrap", &mut chacha_key)
        .map_err(|_| "Failed to derive locking key via HKDF".to_string())?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(&chacha_key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_dek)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(WrappedPayload {
        server_public_key: server_public.as_bytes().to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_dek_success() {
        let dummy_dek = b"dummy_256bit_aes_key_data_here!!";
        let dummy_agent_pub = [1u8; 32];
        let result = wrap_dek(dummy_dek, &dummy_agent_pub);
        assert!(result.is_ok());

        let payload = result.unwrap();
        assert_eq!(payload.server_public_key.len(), 32);
        assert_eq!(payload.nonce.len(), 12);
        assert!(!payload.ciphertext.is_empty());
    }
}

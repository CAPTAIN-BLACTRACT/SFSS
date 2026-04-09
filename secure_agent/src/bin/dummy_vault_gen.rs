use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use std::fs::File;
use std::io::Write;

fn main() {
    println!("[*] Generating 256-bit AES Data Encryption Key...");
    let mut aes_key = [0u8; 32];
    OsRng.fill_bytes(&mut aes_key);

    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    println!("[*] Encrypting mock 'TOP SECRET' vault content...");
    let plaintext = b"Hello, Zero-Trust World! This payload was physically decrypted out of a real AES vault dynamically derived via ECDH.";
    
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("Encryption failed");

    // Write file prepended with 12 byte nonce
    let mut file = File::create("dummy.enc").expect("Failed to create dummy.enc");
    file.write_all(&nonce_bytes).unwrap();
    file.write_all(&ciphertext).unwrap();

    println!("[+] Successfully generated physical encrypted file `dummy.enc`!\n");
    
    print!(">>> DATABASE DEK (Copy Paste ME): ");
    for byte in &aes_key {
        print!("{:02X}", byte);
    }
    println!("\n");
    
    println!("Paste this into your database setup to mock the KMS Master encrypting this specific DEK:");
    println!("UPDATE Files_Vault SET wrapped_dek = '\\x{}' WHERE file_name = 'dummy.txt';", 
        aes_key.iter().map(|b| format!("{:02X}", b)).collect::<String>()
    );
}

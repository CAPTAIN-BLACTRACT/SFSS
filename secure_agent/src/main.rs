mod telemetry;
use std::alloc::{alloc, dealloc, Layout};
use std::ptr;
use zeroize::{Zeroize, ZeroizeOnDrop};
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::thread;
use std::sync::{Arc, Mutex};
use std::io::{self, Write};
use telemetry::DeviceTelemetry;
use prost::Message;
use reqwest::{Client, Certificate, Identity};
use futures::StreamExt;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use x25519_dalek::EphemeralSecret;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The encrypted vault file to open
    #[arg(short, long)]
    file: Option<String>,

    /// The UUID of the file registered in the backend
    #[arg(long)]
    file_id: Option<String>,
}

// Include the auto-generated Rust structs from our schema.proto
pub mod secure_vault {
    include!(concat!(env!("OUT_DIR"), "/secure_vault.rs"));
}
use secure_vault::{KeyRequest, KeyResponse};

async fn request_decryption_key(telemetry: &DeviceTelemetry, file_id: &str) -> Result<(KeyResponse, ed25519_dalek::Signature, EphemeralSecret), Box<dyn std::error::Error>> {
    println!("[*] Assembling Protobuf Payload...");

    let mut csprng = OsRng;
    
    println!("[*] Generating Ephemeral X25519 Keypair for ECDH...");
    let agent_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut csprng);
    let agent_public = x25519_dalek::PublicKey::from(&agent_secret);

    // 1. Package the telemetry into the strictly typed Protobuf request
    let request = KeyRequest {
        file_id: file_id.to_string(),
        ip_address: "192.168.1.100".to_string(), // In production, grab the real IP
        device_hash: format!("{}-{}-{}", telemetry.cpu_id, telemetry.motherboard_uuid, telemetry.mac_hash),
        tpm_quote: telemetry.tpm_quote.clone(), 
        nonce: vec![1, 2, 3, 4], // Placeholder for server nonce
        agent_public_key: agent_public.as_bytes().to_vec(),
    };

    // 2. Serialize to binary
    let mut payload = Vec::new();
    request.encode(&mut payload)?;

    println!("[*] Generating Ephemeral Ed25519 Keypair...");
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    
    println!("[*] Cryptographically Signing Payload...");
    let signature = signing_key.sign(&payload);

    println!("[*] Establishing mTLS Tunnel to KMS...");
    
    // Load CA root cert
    let ca_cert_bytes = std::fs::read("certs/ca.crt").expect("Failed to read CA Cert from certs/ca.crt");
    let reqwest_ca = Certificate::from_pem(&ca_cert_bytes).expect("Failed to parse CA Cert");

    // Load Client Identity (Certificate + Private Key chained together)
    let mut client_cert = std::fs::read("certs/client.crt").expect("Failed to read client.crt");
    let mut client_key = std::fs::read("certs/client.key").expect("Failed to read client.key");
    client_cert.append(&mut client_key); // Bundle them tightly into memory
    
    let identity = Identity::from_pem(&client_cert).expect("Failed to create Identity from PEM bytes");

    let client = Client::builder()
        .add_root_certificate(reqwest_ca)
        .identity(identity)
        .use_rustls_tls()
        .build()?;

    println!("[*] Transmitting encrypted hardware fingerprint and signature...");

    // 3. Send the Protobuf binary payload to Tanmay's endpoint
    let sig_hex = signature.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let response = client.post("https://127.0.0.1:8000/api/v1/interrogate")
        .body(payload)
        .header("Content-Type", "application/x-protobuf")
        .header("X-Signature", sig_hex)
        .send()
        .await?;

    // 4. Decode the Server's Response
    let response_bytes = response.bytes().await?;
    let key_response = KeyResponse::decode(response_bytes)?;

    Ok((key_response, signature, agent_secret))
}
/// A secure memory buffer that locks its contents in RAM and zeroes itself on drop.
pub struct SecureVault {
    ptr: *mut u8,
    size: usize,
    layout: Layout,
}
unsafe impl Send for SecureVault {}
unsafe impl Sync for SecureVault {}
impl SecureVault {
    pub fn new(size: usize) -> Result<Self, String> {
        let layout = Layout::from_size_align(size, 4096)
            .map_err(|_| "Failed to create memory layout")?;

        unsafe {
            let ptr = alloc(layout);
            if ptr.is_null() {
                return Err("Failed to allocate memory".to_string());
            }

            // Lock the memory to prevent the OS from swapping it to disk
            if libc::mlock(ptr as *const libc::c_void, size) != 0 {
                dealloc(ptr, layout);
                return Err("mlock failed".to_string());
            }

            ptr::write_bytes(ptr, 0, size);
            Ok(SecureVault { ptr, size, layout })
        }
    }
}

// Implement Zeroize to securely wipe the memory
impl Zeroize for SecureVault {
    fn zeroize(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                // Volatile write ensures the compiler cannot optimize this away
                ptr::write_volatile(self.ptr, 0); //not needed
                ptr::write_bytes(self.ptr, 0, self.size);
            }
        }
    }
}

// Ensure zeroize is called automatically when the vault goes out of scope
impl Drop for SecureVault {
    fn drop(&mut self) {
        self.zeroize();
        unsafe {
            libc::munlock(self.ptr as *const libc::c_void, self.size);
            dealloc(self.ptr, self.layout);
        }
    }
}

// Marker trait telling the compiler to enforce Zeroize on Drop
impl ZeroizeOnDrop for SecureVault {}
#[tokio::main]
async fn main(){
    let args = Args::parse();

    let file_target = match args.file {
        Some(f) => f,
        None => {
            print!("Enter the physical path to the .enc file: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        }
    };

    let file_id = match args.file_id {
        Some(id) => id,
        None => {
            print!("Enter the UUID of the file registered in the backend (File ID): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        }
    };

    println!("Initializing secure agent for file: {}...", file_target);
    // 1. Run the Interrogation (Hardware & Network Check)
    let telemetry = DeviceTelemetry::collect();
    
    if telemetry.vpn_detected {
        eprintln!("[!] FATAL: Active VPN tunnel detected. Execution halted.");
        std::process::exit(1);
    }

    println!("[+] CPU Vendor: {}", telemetry.cpu_id);
    println!("[+] Motherboard UUID: {}", telemetry.motherboard_uuid);
    let dev_hash = format!("{}-{}-{}", telemetry.cpu_id, telemetry.motherboard_uuid, telemetry.mac_hash);
    println!("[+] HW DEVICE HASH FOR DB: {}", dev_hash);
    println!("[+] Network Fencing: VPN check passed. MAC Hash ready.");

    let mut dek_wrapper = vec![];
    
    match request_decryption_key(&telemetry, &file_id).await {
        Ok((response, _sig, agent_secret)) => {
            if response.is_approved {
                println!("[+] Server Approved Access! Executing ECDH Key Unwrapping...");
                
                #[derive(serde::Deserialize)]
                struct WrappedPayload {
                    server_public_key: Vec<u8>,
                    nonce: Vec<u8>,
                    ciphertext: Vec<u8>,
                }
                
                let wrapped: WrappedPayload = match serde_json::from_slice(&response.wrapped_dek) {
                    Ok(w) => w,
                    Err(e) => {
                        let raw_json = String::from_utf8_lossy(&response.wrapped_dek);
                        panic!("Failed to parse WrappedPayload! Error: {}\nRaw JSON from server: {}", e, raw_json);
                    }
                };

                let mut server_key_array = [0u8; 32];
                server_key_array.copy_from_slice(&wrapped.server_public_key);
                let server_public = x25519_dalek::PublicKey::from(server_key_array);

                let shared_secret = agent_secret.diffie_hellman(&server_public);
                
                let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret.as_bytes());
                let mut chacha_key = [0u8; 32];
                hkdf.expand(b"kms-dek-wrap", &mut chacha_key).expect("HKDF Failed");

                use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, KeyInit}, Nonce as ChaChaNonce};
                let cipher = ChaCha20Poly1305::new(&chacha_key.into());
                let nonce = ChaChaNonce::from_slice(&wrapped.nonce);
                
                let dek_bytes = cipher.decrypt(nonce, wrapped.ciphertext.as_ref())
                    .expect("Failed to unwrap DEK! ECDH Math or Cryptography Corrupted.");
                
                println!("[+] Successfully unwrapped the 256-bit AES DEK natively via ECDH-HKDF!");
                dek_wrapper = dek_bytes;
            } else {
                eprintln!("[!] Server Denied Access: {}", response.error_message);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[!] Network handshake failed: {}", e);
            std::process::exit(1);
        }
    }
    // Wrap the vault in an Arc<Mutex> so our signal handler can safely access it
    let vault_size = 10 * 1024 * 1024; // 10MB Vault
    let vault = Arc::new(Mutex::new(SecureVault::new(vault_size).expect("Failed to create vault")));
    
    println!("Secure RAM buffer established and locked with mlock().");
    
    // Simulate low-level Decryption straight into the mlock buffer 
    if !dek_wrapper.is_empty() {
        println!("[*] Decrypting payload into Secure Vault using AES-GCM-256...");
        
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&dek_wrapper);
        let cipher = Aes256Gcm::new(key);

        let file_content = std::fs::read(&file_target).unwrap_or_else(|_| {
            eprintln!("[-] Physical Encrypted File not found on disk! Please generate 'dummy.enc' first.");
            std::process::exit(1);
        });

        if file_content.len() < 12 {
            eprintln!("[-] Invalid cipher format. Must contain exactly 12-bytes nonce prepended.");
            std::process::exit(1);
        }

        let (file_nonce, file_ciphertext) = file_content.split_at(12);
        let f_nonce = Nonce::from_slice(file_nonce);
        
        let decrypted_data = cipher.decrypt(f_nonce, file_ciphertext).expect("[!] FATAL Physical AES Decryption Failure! Keys do not match.");
        
        // Write it safely into the vault
        let mut secure_memory = vault.lock().unwrap();
        unsafe {
            if decrypted_data.len() <= secure_memory.size {
                std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), secure_memory.ptr, decrypted_data.len());
            }
        }
        println!("[+] Target payload safely landed inside strictly forbidden page-locked memory.");
        
        let peek_text = String::from_utf8_lossy(&decrypted_data);
        println!("--------------------------------------------------");
        println!("*** SECURE VAULT CLEAR-TEXT READOUT (VOLATILE) ***\n\n{}\n", peek_text);
        println!("--------------------------------------------------");
    }

    // --- THE DEAD MAN'S SWITCH ---
    let mut signals = Signals::new(&[SIGINT, SIGTERM]).expect("Failed to bind signal handlers");//signal hook
                                                                                                
    let vault_clone = Arc::clone(&vault);

    // Spawn a dedicated thread to listen for kill commands
    thread::spawn(move || {
        for sig in signals.forever() { //listen for the given signals
            println!("\n[!] INTERCEPTED KILL SIGNAL: {:?}", sig);
            println!("[!] Executing emergency volatile zeroization...");
            
            // Lock the vault and force the zeroize drop routine immediately
            let secure_memory = vault_clone.lock().unwrap();
            let mut sm = secure_memory;
            sm.zeroize(); 
            
            println!("[!] Memory scrubbed. Exiting safely.");
            std::process::exit(1);
        }
    });

    println!("Agent is connected and running. Listening for remote revocation or kill signals...");
    
    // Connect to the Push Stream
    let stream_url = format!("https://127.0.0.1:8000/api/v1/stream/{}/{}", file_id, dev_hash);
    
    // Create connection again for SSE using same identity
    let ca_cert_bytes = std::fs::read("certs/ca.crt").expect("Failed to read CA Cert from certs/ca.crt");
    let reqwest_ca = Certificate::from_pem(&ca_cert_bytes).expect("Failed to parse CA Cert");
    let mut client_cert = std::fs::read("certs/client.crt").expect("Failed to read client.crt");
    let mut client_key = std::fs::read("certs/client.key").expect("Failed to read client.key");
    client_cert.append(&mut client_key); 
    let identity = Identity::from_pem(&client_cert).expect("Failed to create Identity");
    
    let client = Client::builder()
        .add_root_certificate(reqwest_ca)
        .identity(identity)
        .use_rustls_tls()
        .build().expect("Stream client init failed");

    let vault_clone2 = Arc::clone(&vault);
    match client.get(&stream_url).send().await {
        Ok(res) => {
            let mut stream = res.bytes_stream();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        if text.contains("REVOKE") {
                            println!("\n[!] REMOTE REVOCATION RECEIVED FROM SERVER KMS.");
                            println!("[!] Executing emergency volatile zeroization...");
                            
                            let mut sm = vault_clone2.lock().unwrap();
                            sm.zeroize();
                            
                            // Clear output terminal for safety
                            print!("{}[2J", 27 as char);
                            println!("[!] Session forcefully dropped and memory erased. Returning to initial state.");
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] Stream connection error: {}", e);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to connect to push stream: {}", e);
        }
    }

    println!("[!] Lost connection to KMS server.");
}

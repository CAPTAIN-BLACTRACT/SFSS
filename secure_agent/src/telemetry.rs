use std::fs;
use sha2::{Sha256, Digest};
use mac_address::get_mac_address;

pub struct DeviceTelemetry {
    pub cpu_id: String,
    pub motherboard_uuid: String,
    pub mac_hash: String,
    pub vpn_detected: bool,
    pub tpm_quote: Vec<u8>,
}

impl DeviceTelemetry {
    pub fn collect() -> Self {
        println!("[*] Initiating Hardware Fingerprinting...");

        DeviceTelemetry {
            cpu_id: Self::extract_cpu_id(),
            motherboard_uuid: Self::extract_smbios_uuid(),
            mac_hash: Self::hash_mac_address(),
            vpn_detected: Self::check_for_vpn(),
            tpm_quote: Self::extract_tpm_quote(),
        }
    }

    /// Uses the core architecture intrinsic to get CPU vendor details
    fn extract_cpu_id() -> String {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // Executing the CPUID instruction directly 
            let cpuid = std::arch::x86_64::__cpuid(0);
            
            // Reconstruct the vendor string from registers EBX, EDX, ECX
            let mut vendor = [0u8; 12];
            vendor[0..4].copy_from_slice(&cpuid.ebx.to_le_bytes());
            vendor[4..8].copy_from_slice(&cpuid.edx.to_le_bytes());
            vendor[8..12].copy_from_slice(&cpuid.ecx.to_le_bytes());
            
            String::from_utf8_lossy(&vendor).into_owned()//just formatting the string
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            "UNKNOWN_ARCH".to_string()
        }
    }

    /// Direct OS read for SMBIOS / Motherboard UUID (Linux specific for this example) 
    fn extract_smbios_uuid() -> String {
        // We read directly from the sysfs projection of DMI tables
        match fs::read_to_string("/sys/class/dmi/id/product_uuid") {
            Ok(uuid) => uuid.trim().to_string(),
            Err(_) => "UUID_READ_ERROR".to_string(),
        }
    }

    /// Retrieves the primary MAC address and hashes it.
    /// Note: We removed the nearby Wi-Fi BSSID nmcli scan because radio environments are volatile.
    /// Tanmay's server uses strict string equality (`==`), so a neighbor turning on a hotspot 
    /// would instantly lock the user out of their file.
    fn hash_mac_address() -> String {
        let mut hasher = Sha256::new();
        
        // Primary Physical MAC Address (Static)
        match get_mac_address() {
            Ok(Some(ma)) => {
                hasher.update(ma.bytes());
            }
            _ => hasher.update(b"MAC_UNAVAILABLE"),
        }

        format!("{:x}", hasher.finalize())
    }

    /// Scans network interfaces to detect virtual VPN tunnels 
    fn check_for_vpn() -> bool {
        // In a production environment, we would use netlink 
        // Here we read the OS network interface list directly
        if let Ok(interfaces) = fs::read_dir("/sys/class/net") {
            for entry in interfaces.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    // Typical VPN interface names
                    if name.starts_with("tun") || name.starts_with("tap") || name.starts_with("wg") {
                        return true; 
                    }
                }
            }
        }
        false
    }
    
    /// Requests a cryptographic Quote from the physical TPM 2.0 chip.
    /// Falls back to an empty vector if the component is missing (e.g. for devs)
    fn extract_tpm_quote() -> Vec<u8> {
        // In a real implementation this would invoke a TPM 2.0 command 
        // using tss-esapi interacting with /dev/tpmrm0. 
        // Here we do a basic check if a TPM exists to construct the dummy.
        match fs::read("/sys/class/tpm/tpm0/pcrs") {
            Ok(data) => {
                println!("[+] Active TPM 2.0 detected. Fetching secure quote...");
                // Dummy quote logic derived from PCRs if TPM present
                let mut fake_quote = Vec::new();
                fake_quote.extend_from_slice(b"QUOTE:");
                fake_quote.extend_from_slice(&data[0..std::cmp::min(data.len(), 32)]);
                fake_quote
            }
            Err(_) => {
                println!("[-] No TPM detected on this machine. Using fallback mode.");
                vec![] // Graceful fallback 
            }
        }
    }
}

# Secure File Sharing System (SFSS)

A Zero-Trust, Hardware-Bound Cryptographic File System designed to tightly decouple **File Storage** from **Cryptographic Key Management (KMS)**. This system allows encrypted `.enc` files to be independently distributed anywhere, but they absolutely cannot be decrypted unless the executing machine's physical hardware matches strict Access Control policies authenticated via a secure mutual-TLS (mTLS) tunnel to a central KMS server.

The decrypted payload is forcefully constrained to volatile, page-locked `mlock()` RAM regions to prevent memory dumping and OS swap-file leakage.

---

## 🏗️ Architecture Overview

1. **VaultControl (Dashboard)**: The React + Node.js interface for managing files, uploading binary payloads natively enforcing AES-256-GCM encryption, tracking real-time Audit logs, and adjusting IP/Hardware restriction policies.
2. **KMS Zero-Trust Server**: A bare-metal Rust server utilizing protocol buffers and `axum` to authenticate client hardware identities. It executes advanced Elliptic-Curve Diffie-Hellman (ECDH `X25519`) dynamic key exchange to tunnel the Data Encryption Key (DEK). 
3. **Secure Agent (Client)**: A Rust endpoint binary explicitly designed to run on the target physical machine. It gathers low-level motherboard/CPU topography, generates ephemeral keypairs, decrypts payloads inside locked memory segments, and violently zeroizes data payloads on explicit Kill Signals or `Ctrl+C`.

---

## 🛠 Required Dependencies

To reliably replicate this environment on a fresh Linux machine, install the following dependencies via standard package managers (`apt`, `npm`, `cargo`):

- **Linux OS** (Tested on Debian/Ubuntu derivatives)
- **Rust Toolchain**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js** (v18+) & **npm**: `sudo apt install nodejs npm`
- **Docker** (For spinning up Postgres gracefully)
- **Protobuf Compiler**: `sudo apt install protobuf-compiler libprotobuf-dev` (Critical for Protobuf schema mapping)
- **OpenSSL**: `sudo apt install libssl-dev pkg-config` (Critical for mTLS handshakes)
- **Dmidecode**: `sudo apt install dmidecode` (Used by the agent for fetching raw physical hardware telemetry)

---

## 🚀 Setup & Execution Guide

### Step 1: Database Initialization
The KMS requires a tightly structured Postgres SQL schema.
```bash
# Spin up Postgres using Docker
docker run --name pg_kms -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=secure_kms -p 5432:5432 -d postgres

# Note: You must apply the `01_initial_schema.sql` logic inside your database manually if it’s fresh.
```

### Step 2: Protocol Security (mTLS Certificates)
The KMS Server heavily strictly authenticates connections using mutual TLS. Generate the certificates manually:
```bash
# Assuming you have your generate_certs.sh script locally
chmod +x generate_certs.sh
./generate_certs.sh
```
*(Ensure `ca.crt`, `server.crt`, `server.key` are available and statically accessible to your KMS configuration paths)*

### Step 3: VaultControl Backend
```bash
cd VaultControl/backend
npm install
# Set the environment variable explicitly
DATABASE_URL=postgres://postgres:secret@127.0.0.1:5432/secure_kms npm run dev
```

### Step 4: VaultControl Frontend
In a new terminal:
```bash
cd VaultControl/frontend
npm install
npm run dev
```
*(Access the dashboard at `http://localhost:5173` to mock up policies and upload your first physical encrypted file!)*

### Step 5: Start the KMS Server
In a new terminal:
```bash
cd Secure-share-file-system/kms-server
cargo run
```
*(The Rust web server will bind securely over `mTLS` awaiting incoming protobuf telemetry structures).*

### Step 6: Trigger the Secure Agent
The Endpoint Client must compile properly and be executed dynamically. Because it uses POSIX Memory locks (`mlock`) to shield the unencrypted payload and accesses SMBIOS system records via `dmidecode`, **it must consistently be run as `.sudo`**.

```bash
cd secure_agent
cargo build

# The binary can be run interactively
sudo ./target/debug/secure_agent
```
It will interactively request:
- The path to your encrypted file (e.g., `./secret.enc` or the file explicitly exported from the Dashboard).
- The UUID file-hash listed in the Dashboard.

---

## ⚠️ Known Gotchas & Troubleshooting History

Over the course of integration, these are standard failures we systematically identified and fixed. Keep these in mind!

1. **`protoc` Build Failures** 
   - *Problem:* `cargo run` inside `kms-server` immediately throws linker or syntax parsing errors explicitly tied to `prost_build`.
   - *Fix:* Ensure the binary `protoc` is physically installed on the OS via `sudo apt install protobuf-compiler`. The build compiler also heavily depends on absolute paths in your `build.rs` to find `schema.proto`.

2. **Server Denied Access: Invalid Device Hash**
   - *Problem:* The Secure Agent instantly connects over TCP, passes SSL, but gets fundamentally rejected with an "Invalid Device Hash" error structure.
   - *Fix:* This means the KMS successfully interrogated the machine but you typed the Hardware Fingerprint loosely. You **must guarantee no trailing spaces or newlines** copy over from the terminal (`GenuineIntel-46a...`) into your Dashboard Access Control modal. Empty Device Hashes inside the dash behave as wildcards!

3. **`mlock()` Memory Allocation Crashes**
   - *Problem:* Running the Secure agent gracefully crashes stating `mlock failed` or `Permission Denied`.
   - *Fix:* `mlock` requires OS kernel hardware priority. You must explicitly launch the binary wrapping it with `sudo`. 

4. **Nodemon Syntax Routing / Port 5000**
   - *Problem:* The Dashboard Backend `npm run dev` screams `EADDRINUSE`.
   - *Fix:* If you violently kill the process with `CTRL+Z` instead of `CTRL+C`, Node instances stay active. Kill via `killall node`. Also explicitly install `pg-pool` dependencies if missing.

5. **Where are the Active Sessions?**
   - *Problem:* The Dashboard doesn't show any connections when the agent launches!
   - *Fix:* By mathematically correct Zero-Trust Architecture, the agent does NOT maintain long-standing stateful sessions. It rips keys via mathematical Diffie-Hellman handshakes in <200ms and violently tears down the TLS tunnel immediately explicitly limiting external attack vectors. Your system activity strictly populates the immutable **Audit Ledger**.

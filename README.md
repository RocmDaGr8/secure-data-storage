# secure-data-storage

C++ application for encrypting and decrypting sensitive data using AES-256-CBC via OpenSSL.

## Features

- AES-256-CBC encryption (industry standard)
- Password-based key derivation via PBKDF2-SHA256 (100,000 iterations)
- Random 8-byte salt per encryption — same password produces different output every time
- Random 16-byte IV prepended to output — no IV reuse
- Works on any file type (text, binary, images, etc.)
- Simple CLI interface
- Clear error messages for wrong password / corrupted file

## Security Design

| Component | Implementation |
|-----------|---------------|
| Cipher | AES-256-CBC |
| Key derivation | PBKDF2-SHA256, 100k iterations |
| Salt | 8 bytes, cryptographically random |
| IV | 16 bytes, cryptographically random |
| Output format | `[salt 8B][IV 16B][ciphertext]` |

## Installation

**Prerequisites:** OpenSSL development libraries

```bash
# Ubuntu / Debian
sudo apt install libssl-dev

# macOS
brew install openssl
```

```bash
git clone https://github.com/RocmDaGr8/secure-data-storage.git
cd secure-data-storage
make
```

## Usage

**Encrypt a file:**
```bash
./secure-data-storage -e secret.txt secret.enc "MyStr0ngP@ssword"
```

**Decrypt a file:**
```bash
./secure-data-storage -d secret.enc recovered.txt "MyStr0ngP@ssword"
```

**Demo output:**
```
[+] Encrypted: secret.txt -> secret.enc
    Plaintext size : 42 bytes
    Ciphertext size: 48 bytes

[+] Decrypted: secret.enc -> recovered.txt
    Output size: 42 bytes
```

## How It Works

1. A random 8-byte salt is generated for each encryption session
2. PBKDF2-SHA256 derives a 256-bit AES key from your password + salt (100k iterations adds brute-force resistance)
3. A random 16-byte IV is generated and stored in the output header
4. The plaintext is encrypted with AES-256-CBC using the derived key and IV
5. Output file layout: `[salt][IV][ciphertext]`
6. Decryption reads the salt and IV from the header, re-derives the key, and decrypts

## Roadmap

- [ ] String encryption mode (no file I/O)
- [ ] Authenticated encryption (AES-256-GCM) to detect tampering
- [ ] Encrypt entire directories
- [ ] Secure memory wiping after key use

## License

MIT

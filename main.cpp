/**
 * secure-data-storage
 * AES-256-CBC file encryption/decryption using OpenSSL.
 *
 * Key derivation: PBKDF2-SHA256 (100,000 iterations)
 * IV: 16-byte random, prepended to ciphertext
 * Salt: 8-byte random, prepended before IV
 *
 * Build: make  (or see README)
 * Usage:
 *   ./secure-data-storage -e <input_file> <output_file> <password>
 *   ./secure-data-storage -d <input_file> <output_file> <password>
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// ── Constants ────────────────────────────────────────────────────────────────
static const int AES_KEY_LEN   = 32;   // 256-bit key
static const int AES_IV_LEN    = 16;   // 128-bit IV (AES block size)
static const int SALT_LEN      = 8;    // 64-bit salt
static const int PBKDF2_ITER   = 100000;

// ── Helper: read entire file into a byte vector ───────────────────────────────
static bool read_file(const std::string& path, std::vector<unsigned char>& buf) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "[!] Cannot open file: " << path << std::endl;
        return false;
    }
    buf.assign(std::istreambuf_iterator<char>(f),
               std::istreambuf_iterator<char>());
    return true;
}

// ── Helper: write byte vector to file ────────────────────────────────────────
static bool write_file(const std::string& path, const std::vector<unsigned char>& buf) {
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "[!] Cannot write file: " << path << std::endl;
        return false;
    }
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    return true;
}

// ── Derive AES key + IV from password + salt via PBKDF2-SHA256 ───────────────
static bool derive_key(const std::string& password,
                       const unsigned char* salt,
                       unsigned char* key,
                       unsigned char* iv) {
    // Derive 48 bytes: first 32 = key, last 16 = IV
    unsigned char derived[AES_KEY_LEN + AES_IV_LEN];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(),
                            static_cast<int>(password.size()),
                            salt, SALT_LEN,
                            PBKDF2_ITER,
                            EVP_sha256(),
                            AES_KEY_LEN + AES_IV_LEN,
                            derived)) {
        std::cerr << "[!] PBKDF2 key derivation failed." << std::endl;
        return false;
    }
    std::memcpy(key, derived,              AES_KEY_LEN);
    std::memcpy(iv,  derived + AES_KEY_LEN, AES_IV_LEN);
    return true;
}

// ── Encrypt ───────────────────────────────────────────────────────────────────
// Output layout: [ salt (8) | IV (16) | ciphertext ]
static bool encrypt_file(const std::string& in_path,
                         const std::string& out_path,
                         const std::string& password) {
    // Read plaintext
    std::vector<unsigned char> plaintext;
    if (!read_file(in_path, plaintext)) return false;

    // Generate random salt
    unsigned char salt[SALT_LEN];
    if (!RAND_bytes(salt, SALT_LEN)) {
        std::cerr << "[!] Failed to generate random salt." << std::endl;
        return false;
    }

    // Derive key and IV
    unsigned char key[AES_KEY_LEN], iv[AES_IV_LEN];
    if (!derive_key(password, salt, key, iv)) return false;

    // Encrypt with AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { std::cerr << "[!] Failed to create cipher context." << std::endl; return false; }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_IV_LEN); // +block for padding
    int len = 0, total = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      plaintext.data(), static_cast<int>(plaintext.size()));
    total = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(total);

    // Build output: salt + IV + ciphertext
    std::vector<unsigned char> output;
    output.insert(output.end(), salt, salt + SALT_LEN);
    output.insert(output.end(), iv,   iv  + AES_IV_LEN);
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());

    if (!write_file(out_path, output)) return false;

    std::cout << "[+] Encrypted: " << in_path << " -> " << out_path << std::endl;
    std::cout << "    Plaintext size : " << plaintext.size()  << " bytes" << std::endl;
    std::cout << "    Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
    return true;
}

// ── Decrypt ───────────────────────────────────────────────────────────────────
static bool decrypt_file(const std::string& in_path,
                         const std::string& out_path,
                         const std::string& password) {
    std::vector<unsigned char> input;
    if (!read_file(in_path, input)) return false;

    if (input.size() < static_cast<size_t>(SALT_LEN + AES_IV_LEN + 1)) {
        std::cerr << "[!] Input file too small to be a valid encrypted file." << std::endl;
        return false;
    }

    // Extract salt and IV from header
    unsigned char salt[SALT_LEN], iv[AES_IV_LEN];
    std::memcpy(salt, input.data(),            SALT_LEN);
    std::memcpy(iv,   input.data() + SALT_LEN, AES_IV_LEN);

    // Derive key
    unsigned char key[AES_KEY_LEN];
    unsigned char iv_derived[AES_IV_LEN]; // derived IV ignored — we use stored IV
    if (!derive_key(password, salt, key, iv_derived)) return false;

    // Decrypt
    const unsigned char* cdata  = input.data() + SALT_LEN + AES_IV_LEN;
    int                  csize  = static_cast<int>(input.size()) - SALT_LEN - AES_IV_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { std::cerr << "[!] Failed to create cipher context." << std::endl; return false; }

    std::vector<unsigned char> plaintext(csize);
    int len = 0, total = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, cdata, csize)) {
        std::cerr << "[!] Decryption failed (wrong password or corrupted file?)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "[!] Decryption finalisation failed — bad password or corrupted data." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(total);

    if (!write_file(out_path, plaintext)) return false;

    std::cout << "[+] Decrypted: " << in_path << " -> " << out_path << std::endl;
    std::cout << "    Output size: " << plaintext.size() << " bytes" << std::endl;
    return true;
}

// ── Entry point ───────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage:" << std::endl;
        std::cerr << "  Encrypt: " << argv[0] << " -e <input> <output> <password>" << std::endl;
        std::cerr << "  Decrypt: " << argv[0] << " -d <input> <output> <password>" << std::endl;
        return 1;
    }

    std::string mode     = argv[1];
    std::string in_path  = argv[2];
    std::string out_path = argv[3];
    std::string password = argv[4];

    if (mode == "-e") {
        return encrypt_file(in_path, out_path, password) ? 0 : 1;
    } else if (mode == "-d") {
        return decrypt_file(in_path, out_path, password) ? 0 : 1;
    } else {
        std::cerr << "[!] Unknown mode: " << mode << ". Use -e or -d." << std::endl;
        return 1;
    }
}

# pinlock-img (v9) - Authenticated PNG Vault

A high-security, authenticated image encryption utility. Version 9 implements **Authenticated Encryption** via HMAC-SHA256, ensuring that your password is validated and data integrity is verified before any decryption occurs.

## 🚀 Key Features

*   **Authenticated Encryption:** Unlike standard XOR tools, v9 verifies an HMAC tag stored in the PNG metadata. If the password is wrong or the file is tampered with, it aborts immediately.
*   **Cryptographic Key Stretching:** Uses **PBKDF2-HMAC-SHA256** with **200,000 iterations** and a unique salt (`pinlock-img-v9`) to derive secure keys.
*   **Dual-Key Derivation:** Generates two distinct keys from your password: one for the **XOR stream** (encryption) and one for the **HMAC** (authentication).
*   **Atomic Operations:** Uses temporary files and `shutil.move` to ensure your original data is never corrupted during the process.
*   **Batch Processing:** Recursive directory scanning to encrypt or decrypt entire libraries at once.

---

## 🛠️ How It Works

### 1. Key Derivation
Your password is transformed into a 32-byte master key using PBKDF2. This key is split:
*   **XOR Seed (16 bytes):** Seeds the `numpy.random.default_rng` to create a deterministic noise stream.
*   **Auth Key (16 bytes):** Used to calculate and verify the HMAC-SHA256 tag.

### 2. Encryption (Encrypt-then-MAC)
The image pixels are XORed with the noise stream. An HMAC tag is then computed from the **encrypted** pixel data and stored in the PNG's `tEXt` chunk under the field `pinlock_auth`.

### 3. Decryption (Verify-then-Decrypt)
Before transforming pixels, the script re-calculates the HMAC of the encrypted file and compares it to the stored tag. If they do not match, the script identifies a "Wrong Password" and stops, preventing the creation of corrupted images.

---

## 📦 Installation

This utility requires **Python 3.8+** and two libraries:

```bash
pip install numpy Pillow
```

## 📖 Usage

> **Note:** v9 is strictly optimized for **PNG** files to ensure metadata and authentication integrity.

### Encrypt/Decrypt a Folder or File
Run the script and provide the path to a single PNG or a directory:
```bash
python pinlock-img.py /path/to/your/png_files
```

### Dry Run (Audit Mode)
See what would happen without modifying any files or entering a password:
```bash
python pinlock-img.py /path/to/your/png_files
# Enter 'y' at the Dry Run prompt:
Enable Dry Run? (y/n): y
```

### Password Safety
The script uses `getpass` to ensure your password is never visible on the screen or saved in your shell history. Confirmation is only required when encrypting new files to prevent typos.

```bash
Password: 
Confirm Password: 
```

### Batch Summary & Output
At the end of each session, the script provides a formatted summary of the operations performed.

```bash
✅ Encrypted: image1.lock.png
✅ Decrypted: secret_photo.png
❌ Wrong password (authentication failed): private.lock.png

========================================
📊 Batch Summary
========================================
Total Files Handled : 3
Encrypted           : 1
Decrypted           : 1
========================================
✨ Done!
```

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for the full text.

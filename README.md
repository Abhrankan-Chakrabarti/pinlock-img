# 🔐 pinlock-img (v9) – Authenticated PNG Vault

A password-based image protection utility for PNG files.

Version 9 introduces authenticated encryption behavior using an Encrypt-then-MAC design with HMAC-SHA256. Decryption is only performed after successful password verification, preventing silent corruption.

> ⚠️ Note: This tool uses a deterministic XOR stream cipher for pixel transformation. While authentication is strong, this is not a replacement for modern AEAD cryptography such as AES-GCM.

---

## 🚀 Key Features

### 🔐 Authenticated Encryption (Encrypt-then-MAC)

Before decryption occurs, the script verifies an HMAC-SHA256 tag embedded inside the PNG metadata. If:

* The password is incorrect, or
* The file has been modified,

The operation aborts safely without altering the file.

---

### 🧠 Secure Key Derivation

Uses:

* PBKDF2-HMAC-SHA256
* 200,000 iterations
* Salt: `pinlock-img-v9`

This slows down brute-force attacks and derives cryptographically strong keys from user passwords.

---

### 🔑 Dual-Key Architecture

A single 32-byte master key is derived and split into:

* **XOR Seed (16 bytes)** → Seeds `numpy.random.default_rng()` to produce a deterministic noise stream.
* **Authentication Key (16 bytes)** → Used for HMAC-SHA256 verification.

This cleanly separates encryption and authentication responsibilities.

---

### 🛡️ Atomic File Operations

All writes occur via temporary files followed by `shutil.move()` to prevent partial writes or corruption in case of interruption.

---

### 📂 Batch Processing

Supports recursive directory scanning for processing entire PNG collections in one command.

---

## 🛠️ How It Works

### 1️⃣ Key Derivation

```
password → PBKDF2 → 32-byte master key
```

Split into:

* XOR Seed
* HMAC Key

---

### 2️⃣ Encryption (Encrypt → MAC)

1. Pixel data is XORed with a deterministic noise stream.
2. An HMAC-SHA256 tag is computed from the encrypted pixel bytes.
3. The tag is stored in the PNG `tEXt` chunk under:

```
pinlock_auth
```

---

### 3️⃣ Decryption (Verify → Decrypt)

1. The stored HMAC tag is retrieved.
2. A new HMAC is computed from the encrypted data.
3. If the tags match → decryption proceeds.
4. If they do not match → the script aborts safely.

This prevents:

* Wrong-password corruption
* Silent data damage
* Undetected tampering

---

## 📦 Installation

Requires **Python 3.8+**

Install dependencies:

```bash
pip install numpy Pillow
```

---

## 📖 Usage

> ⚠️ v9 supports **PNG files only** to ensure reliable metadata-based authentication.

### Encrypt / Decrypt

```bash
python pinlock-img.py /path/to/png_or_directory
```

The script automatically determines whether each file should be encrypted or decrypted based on the `.lock` suffix.

---

### Dry Run (Audit Mode)

Preview operations without modifying any files:

```bash
python pinlock-img.py /path/to/files
Enable Dry Run? (y/n): y
```

No password is required in dry run mode.

---

### Password Handling

* Password input uses `getpass`
* Not echoed to terminal
* Not stored in shell history
* Confirmation required only when encrypting new files

Example:

```
Password:
Confirm Password:
```

---

## 📊 Example Output

```
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

---

## 🔎 Security Notes

* Authentication is strong (HMAC-SHA256).
* Key stretching resists brute-force attacks.
* Decryption will never overwrite data on password failure.

However:

* The encryption mechanism uses XOR with a deterministic PRNG.
* This is suitable for controlled vault-style use, but not equivalent to modern cryptographic standards like AES-GCM.

If higher-grade cryptographic guarantees are required, consider upgrading the transformation layer to an AEAD cipher.

---

## 📜 License

Licensed under the **MIT License**.
See the `LICENSE` file for details.

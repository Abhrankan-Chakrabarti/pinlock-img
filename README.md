# 🖼️ pinlock-img v9  
### Authenticated PNG Image Vault  

<p align="center">
  <img src="https://img.shields.io/badge/version-9-blue.svg">
  <img src="https://img.shields.io/badge/python-3.8+-green.svg">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg">
  <img src="https://img.shields.io/badge/status-active-success.svg">
</p>

<p align="center">
  <b>Secure • Deterministic • Authenticated Image Protection</b>
</p>

---

## 📌 Overview

**pinlock-img** is a password-based image protection tool for PNG files.

It combines deterministic encryption with strong authentication to ensure that:
- Files cannot be silently corrupted  
- Wrong passwords never damage data  
- Tampering is always detected  

---

## 🔐 Core Design

### 🔑 Key Derivation
- PBKDF2-HMAC-SHA256  
- 200,000 iterations  
- Salt: `pinlock-img-v9`  

---

### 🧠 Dual-Key Architecture
A single derived key is split into:

- **XOR Seed (16 bytes)** → Generates deterministic noise stream  
- **Authentication Key (16 bytes)** → Used for HMAC-SHA256  

---

### 🛡️ Authenticated Encryption (Encrypt-then-MAC)

- Data is encrypted first  
- HMAC-SHA256 tag is computed on encrypted bytes  
- Tag stored in PNG metadata (`tEXt` → `pinlock_auth`)  

Decryption only proceeds if authentication succeeds.

---

## ⚙️ How It Works

### Encryption
1. XOR transform applied to pixel data  
2. HMAC tag generated  
3. Tag embedded in PNG metadata  
4. File renamed with `.lock` suffix  

---

### Decryption
1. Extract stored HMAC  
2. Recompute tag  
3. Verify integrity  
4. If valid → decrypt  
5. If invalid → abort safely  

---

## 🚀 Features

- 🔐 Password-based protection  
- 🛡️ HMAC-SHA256 authentication  
- 🔄 Encrypt / decrypt in-place  
- 📂 Recursive batch processing  
- 🧪 Dry-run mode (no changes)  
- 💾 Atomic file operations (safe writes)  

---

## 📦 Installation

Requires **Python 3.8+**

```bash
pip install numpy Pillow
````

---

## 📖 Usage

### Encrypt / Decrypt

```bash
python pinlock-img.py /path/to/file_or_directory
```

---

### Dry Run

```bash
python pinlock-img.py /path/to/files
```

Then select:

```
Dry Run? (y/n): y
```

---

## 📊 Example Output

```
✅ Encrypted: image1.lock.png
✅ Decrypted: secret.png
❌ Wrong password (authentication failed)

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

## ⚠️ Security Notes

* Strong authentication via HMAC-SHA256
* Resistant to brute-force via PBKDF2
* Prevents silent corruption and tampering

However:

* Uses deterministic XOR-based transformation
* Not equivalent to modern AEAD (e.g., AES-GCM)

👉 Suitable for controlled vault-style use, not high-security cryptographic applications.

---

## 📜 License

MIT License © 2026 Fox Hackerz

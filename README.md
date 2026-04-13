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

It ensures:
- No silent corruption  
- Safe failure on wrong password  
- Tamper detection via authentication  

---

## 🔐 Core Design

### 🔑 Key Derivation
- PBKDF2-HMAC-SHA256  
- 200,000 iterations  
- Salt: `pinlock-img-v9`  

---

### 🧠 Dual-Key Architecture

- **XOR Seed (16 bytes)** → deterministic noise stream  
- **Authentication Key (16 bytes)** → HMAC-SHA256  

---

### 🛡️ Authenticated Encryption

Encrypt-then-MAC design:
- Encrypt data  
- Generate HMAC  
- Store tag in PNG metadata (`pinlock_auth`)  

Decryption only proceeds after successful verification.

---

## ⚙️ How It Works

### Encryption
1. XOR transform applied  
2. HMAC generated  
3. Tag embedded in PNG  
4. `.lock` suffix added  

---

### Decryption
1. Extract HMAC  
2. Verify integrity  
3. If valid → decrypt  
4. If invalid → abort safely  

---

## 🚀 Features

- 🔐 Password-based protection  
- 🛡️ HMAC-SHA256 authentication  
- 📂 Batch processing  
- 🧪 Dry-run mode  
- 💾 Atomic file writes  

---

## 📦 Installation

Requires **Python 3.8+**

```bash
pip install numpy Pillow
````

---

## 📖 Usage

```bash id="x2m3zc"
python pinlock-img.py /path/to/file_or_directory
```

---

### Dry Run

```bash id="x0l9r1"
python pinlock-img.py /path/to/files
```

Then:

```id="p1d8wa"
Dry Run? (y/n): y
```

---

## ⚠️ Security Notes

* Strong authentication (HMAC-SHA256)
* PBKDF2 protects against brute-force

However:

* Uses deterministic XOR transformation
* Not equivalent to AES-GCM or modern AEAD

---

## 📜 License

MIT License © 2026 Fox Hackerz

---

## 🦊 About Fox Hackerz

We build tools focused on:

* Cybersecurity
* Automation
* Developer tools

📌 GitHub: [https://github.com/foxhackerzdevs](https://github.com/foxhackerzdevs)

---

<p align="center">
  <b>🦊 Join the pack. Build. Break. Secure.</b>
</p>

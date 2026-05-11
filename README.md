# 🔐 Secure File Encryption System

A Python desktop application for encrypting and decrypting files using AES encryption with a password-based key derivation system.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green)
![Cryptography](https://img.shields.io/badge/Encryption-AES%2FFernet-red)

---

## ✨ Features

- 🔒 Password-based file encryption using AES (Fernet)
- 🔑 PBKDF2HMAC SHA-256 key derivation with 100,000 iterations
- 🧂 Random salt generated per file for maximum security
- ✅ HMAC-SHA256 integrity verification
- 🗑️ Delete original file after encryption/decryption
- ⚡ Background threading for smooth UI performance
- 🌙 Dark modern UI

---

## 🛠️ Tech Stack

- Python 3.11+
- Tkinter (GUI)
- Cryptography (Fernet/AES)
- Hashlib (PBKDF2HMAC SHA-256)

---

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Arhamali654/secure-file-encryption.git
cd secure-file-encryption
```

2. Install dependencies:
```bash
pip install cryptography
```

3. Run the app:
```bash
python secure_encryption.py
```

---

## 📸 Screenshots

![Main Window](Screenshots/Screenshot%202026-05-12%20031026.png)
![Encrypting](Screenshots/Screenshot%202026-05-12%20031103.png)
![Decrypting](Screenshots/Screenshot%202026-05-12%20031131.png)

---

## 📌 How to Use

1. Open the app
2. Select a file to encrypt or decrypt
3. Enter a strong password
4. Click Encrypt or Decrypt
5. The output file will be saved in the same directory

---

## 👨‍💻 Author

**Arham Ali**  
BS Computer Science — SZABIST Hyderabad  
[GitHub](https://github.com/Arhamali654)

# Image Vault – AES-GCM Desktop App

A lightweight PySide6 desktop application for encrypting and decrypting images
using AES-256-GCM with PBKDF2 key derivation.

## Features
- Drag & drop or browse files
- AES-256-GCM encryption
- Password-based key derivation (PBKDF2, 200k iterations)
- Background worker (non-blocking UI)
- Clean, minimal UI

## Tech Stack
- Python 3
- PySide6
- cryptography

## Screenshots
(added below)

## Security Notes
- AES-GCM provides confidentiality + integrity
- Salt and nonce are generated per file
- Password never stored

## How to Run
```bash
pip install -r requirements.txt
python vault_clean.py

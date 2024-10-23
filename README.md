# Password Vault

## Overview

Welcome to the **Password Vault** project! This project is a secure password management system written in Python. It allows you to store, manage, and protect your passwords for various websites using encryption to ensure security. With this vault, you can:

- Store multiple website credentials (website, username, and password).
- Encrypt stored passwords with a master password.
- Change your master password using a recovery key.
- Recover your account using the recovery key if you forget your master password.

The project also features an encrypted SQLite database that ensures all your sensitive data is stored securely.

## Features

- **Master Password**: Protect access to the vault with a single master password.
- **Password Encryption**: All passwords are encrypted using cryptography libraries to ensure they are securely stored.
- **Recovery Key**: If you forget your master password, you can use the recovery key to reset it.
- **Password Storage**: Store unlimited website credentials, including the website, username, and password.
- **User-Friendly Interface**: The program uses a Tkinter GUI for ease of use.

## Technologies Used

- **Python 3.12**: The programming language used for this project.
- **Cryptography Libraries**: Used for hashing, key derivation, and encryption.
  - `hashlib` for SHA-256 hashing of passwords.
  - `cryptography.hazmat` for PBKDF2 key derivation and Fernet encryption.
- **SQLite**: A lightweight, encrypted database for storing passwords securely.
- **Tkinter**: A Python library used for creating the graphical user interface (GUI).
- **Pyperclip**: Used to easily copy data (like the recovery key) to the clipboard.

## Project Structure

- **Main Script (`password_vault.py`)**: This is the main script that handles all operations such as encryption, storage, and the user interface.
- **SQLite Database**: The vault's data is stored in an encrypted SQLite database, with tables for storing master passwords and website credentials.

## Getting Started

### Prerequisites

- Python 3.x (Ensure you're using at least Python 3.12)
- Required libraries:
  - `cryptography`
  - `sqlite3` (comes pre-installed with Python)
  - `tkinter` (comes pre-installed with Python)
  - `pyperclip`

You can install any missing dependencies with the following command:

```bash
pip install cryptography pyperclip

Thank you for taking the time to check out this project!
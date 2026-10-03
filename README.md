# Vigil

Vigil is a Windows desktop security showcase combining an intrusion-detection dashboard, local authentication, and a post-quantum hybrid encrypted file vault.

## Security notes

- Authentication state is stored under `%LOCALAPPDATA%\\Vigil`, not in the source tree.
- Master passwords and recovery answers are protected with memory-hard `scrypt` derivation and independent salts.
- Configuration writes use an atomic temporary-file replacement.
- A per-user Windows Registry initialization marker prevents deleting `config.json` from triggering first-run setup.
- The encrypted vault uses **NIST ML-KEM-768 (FIPS 203)** for post-quantum key encapsulation and AES-256-GCM for authenticated file encryption.
- A fresh ML-KEM-768 key pair is generated for every archive. The ML-KEM private key is encrypted with a password-derived `scrypt` key before being stored in the archive.
- The ML-KEM shared secret is expanded with HKDF-SHA3-256 into the AES-256-GCM data-encryption key.
- The project uses the `pqcrypto` package for ML-KEM-768 rather than implementing the cryptographic primitive itself.
- User-selected decrypted files are written to the OS temporary directory so they can be opened by the default application. The opened plaintext remains subject to the operating system and the application that opens it.

## Development

1. Create a virtual environment.
2. Install `requirements.txt` (including the ML-KEM dependency).
3. Run `python main.py`.

Do not commit `%LOCALAPPDATA%\\Vigil\\config.json`, `.vigil` files, credentials, private keys, or build artifacts.


## Installation-specific authentication profiles

Vigil stores authentication data in `%LOCALAPPDATA%\Vigil\instances\<instance-id>`. The instance ID is derived from the directory containing the running application. This means a second copy of Vigil placed in a different folder gets a separate first-run profile instead of inheriting the first copy's password. Moving a copy to another directory creates a new instance by design.

Existing configurations from older Vigil versions are supported where their format can be verified; successful legacy password/recovery authentication is upgraded to the current scrypt format.

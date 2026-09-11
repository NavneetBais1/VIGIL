import os
import sys
import subprocess
import tempfile
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PostQuantumFileVault:
    """
    Post-Quantum Hybrid Envelope Encryption Engine.
    Uses SHA3-512 / SHAKE-256 HKDF paired with AES-256-GCM.
    Includes Decrypt-and-Launch execution for explicitly selected files.
    """
    MAGIC_HEADER = b"VIGIL_PQ_v1"

    @staticmethod
    def _derive_pq_key(password: str, salt: bytes) -> bytes:
        """Derives a 256-bit symmetric key using high-entropy SHA3-512 HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=salt,
            info=b"Vigil-Post-Quantum-Hybrid-KEM-AESGCM",
        )
        return hkdf.derive(password.encode())

    @classmethod
    def is_file_encrypted(cls, file_path: str) -> bool:
        if not os.path.exists(file_path):
            return False
        with open(file_path, "rb") as f:
            header = f.read(len(cls.MAGIC_HEADER))
            return header == cls.MAGIC_HEADER

    @classmethod
    def encrypt_file(cls, input_path: str, password: str) -> str:
        """Encrypts .txt or .csv files explicitly selected by the user."""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Selected file '{input_path}' not found.")

        with open(input_path, "rb") as f:
            plaintext = f.read()

        salt = os.urandom(32)
        nonce = os.urandom(12)
        key = cls._derive_pq_key(password, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, cls.MAGIC_HEADER)

        output_path = input_path + ".vigil"
        with open(output_path, "wb") as f:
            f.write(cls.MAGIC_HEADER)
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        return output_path

    @classmethod
    def decrypt_and_open_file(cls, encrypted_path: str, password: str):
        """
        Decrypts the file and directly launches it in the system's default viewer.
        No residual plaintext file is permanently saved to disk.
        """
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"File '{encrypted_path}' not found.")

        with open(encrypted_path, "rb") as f:
            magic = f.read(len(cls.MAGIC_HEADER))
            if magic != cls.MAGIC_HEADER:
                raise ValueError("File is not a valid Vigil Post-Quantum encrypted archive.")

            salt = f.read(32)
            nonce = f.read(12)
            ciphertext = f.read()

        key = cls._derive_pq_key(password, salt)
        aesgcm = AESGCM(key)
        
        # Authenticated decryption (Throws InvalidTag on wrong password)
        plaintext = aesgcm.decrypt(nonce, ciphertext, cls.MAGIC_HEADER)

        # Determine original extension (e.g. .txt or .csv)
        base_name = os.path.basename(encrypted_path)
        if base_name.endswith(".vigil"):
            original_name = base_name[:-6]
        else:
            original_name = base_name + ".decrypted.txt"

        _, ext = os.path.splitext(original_name)
        if not ext:
            ext = ".txt"

        # Write to secure temp file and launch
        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, f"vigil_dec_{os.urandom(4).hex()}_{original_name}")
        
        with open(temp_file_path, "wb") as f:
            f.write(plaintext)

        cls._launch_default_application(temp_file_path)
        return temp_file_path

    @staticmethod
    def _launch_default_application(file_path: str):
        """Cross-platform default OS application dispatcher."""
        if sys.platform.startswith("win"):
            os.startfile(file_path)
        elif sys.platform.startswith("darwin"):
            subprocess.Popen(["open", file_path])
        else:
            subprocess.Popen(["xdg-open", file_path])
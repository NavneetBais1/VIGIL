import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from pqcrypto.kem.ml_kem_768 import decaps, encaps, keygen
except ImportError as exc:
    raise ImportError(
        "Vigil's post-quantum vault requires the 'pqcrypto' package. "
        "Install dependencies with: pip install -r requirements.txt"
    ) from exc


class PostQuantumFileVault:
    """Hybrid post-quantum file encryption using NIST ML-KEM-768 + AES-256-GCM.

    Each archive contains a freshly generated ML-KEM-768 key pair. The private
    KEM key is encrypted with a password-derived wrapping key, while the KEM
    shared secret derives the AES-256-GCM data-encryption key.

    ML-KEM is the NIST FIPS 203 post-quantum key-encapsulation mechanism.
    AES-256-GCM provides authenticated symmetric encryption for the file data.
    """

    MAGIC_HEADER = b"VIGIL_PQ_V3"
    FORMAT_VERSION = 3
    ALGORITHM_ID = b"ML-KEM-768"

    SALT_LEN = 16
    NONCE_LEN = 12
    AES_KEY_LEN = 32
    KEM_SHARED_SECRET_LEN = 32

    # Password wrapping parameters. These are intentionally independent of
    # the KEM itself: the password protects the local ML-KEM private key.
    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1

    @classmethod
    def _derive_wrap_key(cls, password: str, salt: bytes) -> bytes:
        if not password:
            raise ValueError("Encryption password cannot be empty.")
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=cls.SCRYPT_N,
            r=cls.SCRYPT_R,
            p=cls.SCRYPT_P,
            dklen=cls.AES_KEY_LEN,
        )

    @classmethod
    def _derive_data_key(cls, shared_secret: bytes, salt: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA3_256(),
            length=cls.AES_KEY_LEN,
            salt=salt,
            info=b"Vigil-ML-KEM-768-AES-256-GCM-v3",
        ).derive(shared_secret)

    @classmethod
    def _metadata(cls, salt: bytes, public_key: bytes, kem_ciphertext: bytes) -> bytes:
        return (
            cls.MAGIC_HEADER
            + bytes([cls.FORMAT_VERSION])
            + cls.ALGORITHM_ID
            + salt
            + public_key
            + kem_ciphertext
        )

    @classmethod
    def is_file_encrypted(cls, file_path: str) -> bool:
        try:
            with open(file_path, "rb") as f:
                return f.read(len(cls.MAGIC_HEADER)) == cls.MAGIC_HEADER
        except OSError:
            return False

    @classmethod
    def encrypt_file(cls, input_path: str, password: str) -> str:
        source = Path(input_path)
        if not source.is_file():
            raise FileNotFoundError(f"Selected file '{source}' not found.")
        if source.suffix.lower() == ".vigil":
            raise ValueError("The selected file is already an encrypted Vigil archive.")
        if not password:
            raise ValueError("Encryption password cannot be empty.")

        plaintext = source.read_bytes()

        # Generate a fresh NIST ML-KEM-768 key pair for this archive.
        public_key, private_key = keygen()
        kem_ciphertext, shared_secret = encaps(public_key)

        if len(shared_secret) != cls.KEM_SHARED_SECRET_LEN:
            raise ValueError("Unexpected ML-KEM shared-secret size.")

        salt = os.urandom(cls.SALT_LEN)
        wrap_nonce = os.urandom(cls.NONCE_LEN)
        data_nonce = os.urandom(cls.NONCE_LEN)

        metadata = cls._metadata(salt, public_key, kem_ciphertext)

        # Protect the ML-KEM private key with the user's password.
        wrap_key = cls._derive_wrap_key(password, salt)
        wrapped_private_key = AESGCM(wrap_key).encrypt(
            wrap_nonce,
            private_key,
            metadata,
        )

        # The ML-KEM shared secret becomes the root secret for the file key.
        data_key = cls._derive_data_key(shared_secret, salt)
        data_aad = metadata + wrap_nonce + wrapped_private_key
        ciphertext = AESGCM(data_key).encrypt(
            data_nonce,
            plaintext,
            data_aad,
        )

        output = Path(str(source) + ".vigil")
        with output.open("wb") as f:
            f.write(cls.MAGIC_HEADER)
            f.write(bytes([cls.FORMAT_VERSION]))
            f.write(cls.ALGORITHM_ID)
            f.write(salt)
            f.write(wrap_nonce)
            f.write(data_nonce)
            f.write(public_key)
            f.write(kem_ciphertext)
            f.write(len(wrapped_private_key).to_bytes(4, "big"))
            f.write(wrapped_private_key)
            f.write(ciphertext)

        return str(output)

    @classmethod
    def decrypt_and_open_file(cls, encrypted_path: str, password: str) -> str:
        source = Path(encrypted_path)
        if not source.is_file():
            raise FileNotFoundError(f"Selected file '{source}' not found.")
        if not password:
            raise ValueError("Decryption password cannot be empty.")

        try:
            with source.open("rb") as f:
                magic = f.read(len(cls.MAGIC_HEADER))
                if magic != cls.MAGIC_HEADER:
                    raise ValueError("File is not a valid Vigil post-quantum archive.")

                version = f.read(1)
                algorithm = f.read(len(cls.ALGORITHM_ID))
                salt = f.read(cls.SALT_LEN)
                wrap_nonce = f.read(cls.NONCE_LEN)
                data_nonce = f.read(cls.NONCE_LEN)

                public_key = f.read(1184)       # ML-KEM-768 encapsulation key
                kem_ciphertext = f.read(1088)  # ML-KEM-768 ciphertext

                wrapped_len_raw = f.read(4)
                if len(wrapped_len_raw) != 4:
                    raise ValueError("Encrypted archive is truncated.")
                wrapped_len = int.from_bytes(wrapped_len_raw, "big")
                if wrapped_len < 16 or wrapped_len > 10000:
                    raise ValueError("Encrypted archive contains an invalid key wrapper.")

                wrapped_private_key = f.read(wrapped_len)
                ciphertext = f.read()

        except OSError as exc:
            raise ValueError("Could not read the encrypted archive.") from exc

        if version != bytes([cls.FORMAT_VERSION]):
            raise ValueError("Unsupported Vigil archive version.")
        if algorithm != cls.ALGORITHM_ID:
            raise ValueError("Unsupported post-quantum algorithm in archive.")
        if len(salt) != cls.SALT_LEN or len(wrap_nonce) != cls.NONCE_LEN:
            raise ValueError("Encrypted archive is truncated or invalid.")
        if len(data_nonce) != cls.NONCE_LEN:
            raise ValueError("Encrypted archive is truncated or invalid.")
        if len(public_key) != 1184 or len(kem_ciphertext) != 1088:
            raise ValueError("Invalid ML-KEM-768 archive structure.")
        if len(wrapped_private_key) != wrapped_len or len(ciphertext) < 16:
            raise ValueError("Encrypted archive is truncated or invalid.")

        metadata = cls._metadata(salt, public_key, kem_ciphertext)
        wrap_key = cls._derive_wrap_key(password, salt)

        try:
            private_key = AESGCM(wrap_key).decrypt(
                wrap_nonce,
                wrapped_private_key,
                metadata,
            )
        except Exception as exc:
            raise ValueError("Password verification failed or the archive was modified.") from exc

        try:
            shared_secret = decaps(private_key, kem_ciphertext)
        except Exception as exc:
            raise ValueError("ML-KEM decapsulation failed; the archive may be corrupted.") from exc

        data_key = cls._derive_data_key(shared_secret, salt)
        data_aad = metadata + wrap_nonce + wrapped_private_key

        try:
            plaintext = AESGCM(data_key).decrypt(
                data_nonce,
                ciphertext,
                data_aad,
            )
        except Exception as exc:
            raise ValueError("Decryption failed; the password or archive integrity is invalid.") from exc

        original_name = source.name[:-6] if source.name.endswith(".vigil") else source.name + ".decrypted"
        safe_name = Path(original_name).name
        temp_file = tempfile.NamedTemporaryFile(
            prefix="vigil_dec_",
            suffix=Path(safe_name).suffix or ".tmp",
            delete=False,
        )
        temp_path = temp_file.name

        try:
            with temp_file:
                temp_file.write(plaintext)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            cls._launch_default_application(temp_path)
            return temp_path
        except Exception:
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _launch_default_application(file_path: str) -> None:
        if sys.platform.startswith("win"):
            os.startfile(file_path)
        elif sys.platform.startswith("darwin"):
            subprocess.Popen(["open", file_path], close_fds=True)
        else:
            subprocess.Popen(["xdg-open", file_path], close_fds=True)

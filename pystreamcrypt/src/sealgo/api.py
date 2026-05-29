"""Pythonic wrapper around the SealGo CLI binary."""

import subprocess
import sys
from pathlib import Path


def _binary():
    """Return path to bundled SealGo binary."""
    here = Path(__file__).parent
    if sys.platform == "win32":
        return str(here / "SealGo.exe")
    return str(here / "SealGo")


def generate_keypair():
    """Generate a new X25519 keypair.

    Returns:
        (public_hex: str, private_hex: str) — both 64 hex chars each.
    """
    result = subprocess.run(
        [_binary(), "genpair"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    pub = None
    priv = None
    for line in result.stderr.splitlines():
        if line.startswith("public:"):
            pub = line.split("public:")[1].strip()
        elif line.startswith("private:"):
            priv = line.split("private:")[1].strip()
    if not pub or not priv:
        raise RuntimeError("failed to parse keypair output")
    return pub, priv


def encrypt(data_hex: str, pubkey_hex: str) -> str:
    """Encrypt hex-encoded data to a recipient public key.

    Args:
        data_hex: Hex-encoded plaintext.
        pubkey_hex: Hex-encoded X25519 public key (64 hex chars).

    Returns:
        Hex-encoded ciphertext.

    Raises:
        RuntimeError: On encryption failure.
    """
    result = subprocess.run(
        [_binary(), "encrypt", "-r", pubkey_hex],
        input=data_hex, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def encrypt_str(data: str, pubkey_hex: str) -> str:
    """Encrypt a UTF-8 string to a recipient public key.

    Args:
        data: Plaintext string (will be UTF-8 encoded).
        pubkey_hex: Hex-encoded X25519 public key (64 hex chars).

    Returns:
        Hex-encoded ciphertext string.
    """
    return encrypt(data.encode("utf-8").hex(), pubkey_hex)


def decrypt(data_hex: str, privkey_hex: str) -> str:
    """Decrypt hex-encoded data with an identity private key.

    Args:
        data_hex: Hex-encoded ciphertext.
        privkey_hex: Hex-encoded X25519 private key (64 hex chars).

    Returns:
        Hex-encoded plaintext.

    Raises:
        RuntimeError: On decryption failure.
    """
    result = subprocess.run(
        [_binary(), "decrypt", "-I", privkey_hex],
        input=data_hex, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def decrypt_str(data: str, privkey_hex: str) -> str:
    """Decrypt a hex-encoded ciphertext back to a UTF-8 string.

    Args:
        data: Hex-encoded ciphertext.
        privkey_hex: Hex-encoded X25519 private key (64 hex chars).

    Returns:
        Decoded UTF-8 plaintext string.
    """
    raw = decrypt(data, privkey_hex)
    return bytes.fromhex(raw).decode("utf-8")


def encrypt_file(input_path: str, output_path: str, pubkey_hex: str) -> None:
    """Encrypt a file to a recipient public key.

    Args:
        input_path: Path to input file.
        output_path: Path for encrypted output.
        pubkey_hex: Hex-encoded X25519 public key (64 hex chars).

    Raises:
        RuntimeError: On encryption failure.
    """
    result = subprocess.run(
        [_binary(), "encrypt", "-r", pubkey_hex, "-i", input_path, "-o", output_path],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())


def decrypt_file(input_path: str, output_path: str, privkey_hex: str) -> None:
    """Decrypt a file with an identity private key.

    Args:
        input_path: Path to encrypted file.
        output_path: Path for decrypted output.
        privkey_hex: Hex-encoded X25519 private key (64 hex chars).

    Raises:
        RuntimeError: On decryption failure.
    """
    result = subprocess.run(
        [_binary(), "decrypt", "-I", privkey_hex, "-i", input_path, "-o", output_path],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())


def version():
    """Return the CLI version string."""
    result = subprocess.run(
        [_binary(), "version"],
        capture_output=True, text=True,
    )
    return result.stdout.strip()
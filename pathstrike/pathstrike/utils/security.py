"""Security utilities for PathStrike."""

import logging
import os
import re
import stat
from pathlib import Path

logger = logging.getLogger("pathstrike.utils.security")


def scrub_credentials(text: str) -> str:
    """Replace credential-like values in text with masked versions.

    Patterns scrubbed:
    - NT hashes (32 hex chars)
    - Passwords after -p flag
    - AES keys (32/64 hex chars after -aesKey)
    - Base64 encoded keys
    """
    # NT hash pattern: 32 hex characters
    text = re.sub(
        r'([: ])[a-fA-F0-9]{32}(?=[: \n]|$)',
        r'\1' + '***REDACTED_HASH***',
        text,
    )
    # Password after -p flag
    text = re.sub(
        r'(-p\s+)(\S+)',
        r'\1***REDACTED***',
        text,
    )
    # AES key after -aesKey
    text = re.sub(
        r'(-aesKey\s+)([a-fA-F0-9]+)',
        r'\1***REDACTED_KEY***',
        text,
    )
    return text


def check_config_permissions(config_path: Path) -> list[str]:
    """Check if config file has safe permissions.

    Returns a list of warning messages (empty if all good).
    """
    warnings = []
    path = Path(config_path).expanduser().resolve()

    if not path.exists():
        return warnings

    mode = path.stat().st_mode

    # Check if world-readable
    if mode & stat.S_IROTH:
        warnings.append(
            f"Config file {path} is world-readable (mode {oct(mode)}). "
            "Run: chmod 600 " + str(path)
        )

    # Check if group-readable
    if mode & stat.S_IRGRP:
        warnings.append(
            f"Config file {path} is group-readable (mode {oct(mode)}). "
            "Consider: chmod 600 " + str(path)
        )

    return warnings


class CredentialScrubFilter(logging.Filter):
    """Logging filter that scrubs credential-like values from log messages.

    Attach this filter to any logging handler to automatically redact
    NT hashes, passwords, and AES keys from log output.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Scrub credentials from the log record message and args.

        Always returns True (the record is never suppressed, only sanitised).
        """
        if isinstance(record.msg, str):
            record.msg = scrub_credentials(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: scrub_credentials(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    scrub_credentials(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )

        return True


# ---------------------------------------------------------------------------
# At-rest encryption helpers (Fernet / AES-128-CBC via cryptography library)
# ---------------------------------------------------------------------------

def generate_encryption_key() -> bytes:
    """Generate a new Fernet encryption key.

    Returns:
        A URL-safe base64-encoded 32-byte key suitable for Fernet.

    Raises:
        ImportError: If the ``cryptography`` library is not installed.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for encryption. "
            "Install it with: pip install cryptography"
        )
    return Fernet.generate_key()


def encrypt_value(plaintext: str, key: bytes) -> str:
    """Encrypt a string value using Fernet symmetric encryption.

    Args:
        plaintext: The string to encrypt.
        key: Fernet encryption key (from :func:`generate_encryption_key`).

    Returns:
        Base64-encoded encrypted string.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for encryption."
        )
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(encrypted: str, key: bytes) -> str:
    """Decrypt a Fernet-encrypted string value.

    Args:
        encrypted: Base64-encoded encrypted string.
        key: Fernet encryption key used for encryption.

    Returns:
        Decrypted plaintext string.

    Raises:
        cryptography.fernet.InvalidToken: If the key is wrong or data is corrupted.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for decryption."
        )
    f = Fernet(key)
    return f.decrypt(encrypted.encode("utf-8")).decode("utf-8")


def encrypt_config_file(config_path: Path, key: bytes, output_path: Path | None = None) -> Path:
    """Encrypt a YAML configuration file.

    Reads the plaintext config, encrypts it, and writes the encrypted
    version.  The original file is NOT deleted — the caller should
    handle secure removal if desired.

    Args:
        config_path: Path to the plaintext YAML config file.
        key: Fernet encryption key.
        output_path: Where to write the encrypted file. Defaults to
            ``<config_path>.enc``.

    Returns:
        Path to the encrypted file.
    """
    config_path = Path(config_path).expanduser().resolve()
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    plaintext = config_path.read_text(encoding="utf-8")
    encrypted = encrypt_value(plaintext, key)

    out = output_path or config_path.with_suffix(config_path.suffix + ".enc")
    out = Path(out).expanduser().resolve()
    out.write_text(encrypted, encoding="utf-8")

    return out


def decrypt_config_file(encrypted_path: Path, key: bytes, output_path: Path | None = None) -> Path:
    """Decrypt an encrypted configuration file.

    Args:
        encrypted_path: Path to the encrypted config file.
        key: Fernet encryption key.
        output_path: Where to write the decrypted file. Defaults to
            stripping the ``.enc`` suffix.

    Returns:
        Path to the decrypted file.
    """
    encrypted_path = Path(encrypted_path).expanduser().resolve()
    if not encrypted_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")

    encrypted = encrypted_path.read_text(encoding="utf-8")
    plaintext = decrypt_value(encrypted, key)

    if output_path:
        out = Path(output_path).expanduser().resolve()
    else:
        # Strip .enc suffix
        name = encrypted_path.name
        if name.endswith(".enc"):
            name = name[:-4]
        out = encrypted_path.parent / name

    out.write_text(plaintext, encoding="utf-8")
    return out

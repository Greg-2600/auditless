"""Envelope encryption for stored secrets (SSH keys, webhook URLs).

Master key comes from AUDITLESS_MASTER_KEY (a Fernet key string). Behavior:
    - key set + valid   -> encrypt on write; decrypt transparently.
    - key set + invalid -> refusing to boot is the caller's job
      (see require_master_key); never guess.
    - key unset         -> legacy plaintext mode (read + write), so
      existing deployments keep working until they opt in.

Values already encrypted (Fernet tokens start with gAAAAA) are passed
through untouched, which makes migration idempotent. Plaintext values
read while a key is configured decrypt-fail and fall back to plaintext,
so mixed stores keep working during rollout.
"""

from __future__ import annotations

import os

FERNET_PREFIX = "gAAAAA"


class SecretBox:
    """Encrypt/decrypt helper bound to one master key (or none)."""

    def __init__(self, master_key: str | None) -> None:
        self._fernet = None
        if master_key:
            from cryptography.fernet import Fernet, InvalidToken

            self._fernet = Fernet(master_key.encode("utf-8"))
            self._invalid_token = InvalidToken

    @property
    def enabled(self) -> bool:
        """Whether a master key is configured."""
        return self._fernet is not None

    def encrypt(self, plaintext: str) -> str:
        """Encrypt (requires a key); passthrough when unconfigured."""
        if self._fernet is None:
            return plaintext
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, stored: str) -> str:
        """Decrypt, tolerating legacy plaintext and passthrough values."""
        if self._fernet is None or not stored.startswith(FERNET_PREFIX):
            return stored
        try:
            return self._fernet.decrypt(stored.encode("ascii")).decode("utf-8")
        except self._invalid_token:
            # Not ours (or corrupted): surface as-is rather than bricking.
            return stored

    def is_encrypted(self, stored: str) -> bool:
        """Heuristic: looks like a Fernet token we could own."""
        return stored.startswith(FERNET_PREFIX)


def load_master_key() -> str | None:
    """Read AUDITLESS_MASTER_KEY (None when unset)."""
    return os.environ.get("AUDITLESS_MASTER_KEY") or None


def require_master_key() -> SecretBox:
    """Build the box, refusing to boot on a configured-but-invalid key."""
    raw = load_master_key()
    if not raw:
        return SecretBox(None)
    try:
        box = SecretBox(raw)
        # Round-trip proves the key parses before anything depends on it.
        assert (
            box.decrypt(box.encrypt("auditless-boot-check")) == "auditless-boot-check"
        )
    except Exception as exc:
        raise RuntimeError(
            "AUDITLESS_MASTER_KEY is set but invalid (need a Fernet key, "
            "e.g. from `python -c 'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())'`). Refusing to boot."
        ) from exc
    return box

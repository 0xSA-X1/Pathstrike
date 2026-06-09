"""Bulk credential loading for validation runs.

For a comprehensive edge-validation pass (as opposed to a realistic single-foothold
campaign) it helps to pre-load every known credential in the lab, so each edge can
be exercised as its *true source principal*.  This module parses common credential
artefacts — primarily ``secretsdump`` / NTDS dumps — into :class:`Credential`
objects that seed the :class:`CredentialStore`.

Supported input formats (auto-detected per line):

* **secretsdump NTLM** — ``[DOMAIN\\]user:rid:lmhash:nthash:::``
* **secretsdump Kerberos keys** — ``[DOMAIN\\]user:aes256-cts-hmac-sha1-96:<hex>``
  (also ``aes128``)
* **simple** — ``user:nthash`` (32 hex)
* **YAML/JSON list** — ``[{username, domain?, nt_hash|password|aes_key}]``
  (used when the file extension is ``.yaml``/``.yml``/``.json``)

All parsed credentials are assigned the supplied *domain* (the config target
domain) so that lookups by ``sAMAccountName@domain`` resolve — which is how the
handlers authenticate as an edge's source.  Run once per target domain.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from pathstrike.models import Credential, CredentialType

logger = logging.getLogger("pathstrike.credential_vault")

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


def _sam_from_principal(raw: str) -> str:
    """Extract the bare sAMAccountName from ``DOMAIN\\user``, ``user@dom`` or ``user``."""
    name = raw.strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip()


def _parse_structured(data: object, domain: str) -> list[Credential]:
    """Parse a YAML/JSON list of credential mappings."""
    if not isinstance(data, list):
        raise ValueError("Structured credential file must be a list of mappings.")
    creds: list[Credential] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict) or "username" not in item:
            raise ValueError(f"credentials[{i}] must be a mapping with 'username'.")
        user = _sam_from_principal(str(item["username"]))
        dom = str(item.get("domain") or domain)
        if item.get("nt_hash"):
            creds.append(Credential(cred_type=CredentialType.nt_hash, value=str(item["nt_hash"]),
                                    username=user, domain=dom, obtained_from="vault"))
        if item.get("password"):
            creds.append(Credential(cred_type=CredentialType.password, value=str(item["password"]),
                                    username=user, domain=dom, obtained_from="vault"))
        if item.get("aes_key"):
            creds.append(Credential(cred_type=CredentialType.aes_key, value=str(item["aes_key"]),
                                    username=user, domain=dom, obtained_from="vault"))
    return creds


def _parse_line(line: str, domain: str) -> Credential | None:
    """Parse a single secretsdump-style line into a Credential, or None to skip."""
    line = line.strip()
    if not line or line.startswith(("#", "[", "Impacket", "secretsdump")):
        return None

    parts = line.split(":")

    # secretsdump NTLM: user:rid:lm:nt:::
    if len(parts) >= 4 and _HEX32.match(parts[3]) and _HEX32.match(parts[2]):
        user = _sam_from_principal(parts[0])
        if not user:
            return None
        return Credential(cred_type=CredentialType.nt_hash, value=parts[3].lower(),
                          username=user, domain=domain, obtained_from="vault")

    # secretsdump Kerberos key: user:aes256-cts-hmac-sha1-96:<hex>
    if len(parts) == 3 and parts[1].lower().startswith(("aes256", "aes128")):
        user = _sam_from_principal(parts[0])
        if not user or not parts[2]:
            return None
        return Credential(cred_type=CredentialType.aes_key, value=parts[2].strip(),
                          username=user, domain=domain, obtained_from="vault")

    # simple: user:nthash
    if len(parts) == 2 and _HEX32.match(parts[1]):
        user = _sam_from_principal(parts[0])
        if not user:
            return None
        return Credential(cred_type=CredentialType.nt_hash, value=parts[1].lower(),
                          username=user, domain=domain, obtained_from="vault")

    return None


def parse_credentials_file(path: Path, domain: str) -> list[Credential]:
    """Parse a credential file into a list of :class:`Credential` objects.

    Args:
        path: Path to the credential artefact (NTDS dump, hash list, or YAML/JSON).
        domain: Domain to assign to every parsed credential (the config target
            domain), so store lookups by ``sAMAccountName@domain`` resolve.

    Returns:
        Parsed credentials (deduplication is handled by the store on insert).
    """
    text = path.read_text(encoding="utf-8", errors="replace")

    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        import yaml
        return _parse_structured(yaml.safe_load(text), domain)
    if suffix == ".json":
        import json
        return _parse_structured(json.loads(text), domain)

    creds: list[Credential] = []
    skipped = 0
    for line in text.splitlines():
        cred = _parse_line(line, domain)
        if cred is not None:
            creds.append(cred)
        elif line.strip():
            skipped += 1

    logger.info(
        "Parsed %d credential(s) from %s (%d unparsable line(s) skipped)",
        len(creds), path, skipped,
    )
    return creds


def load_into_store(store, path: Path, domain: str) -> int:
    """Parse *path* and add every credential to *store*. Returns count added."""
    creds = parse_credentials_file(path, domain)
    for cred in creds:
        store.add_credential(cred)
    return len(creds)

"""Input validation utilities for PathStrike."""

import re
import ipaddress
from pathlib import Path

def validate_domain_name(name: str) -> str:
    """Validate and normalize an AD domain name. Raises ValueError if invalid."""
    # Strip whitespace, convert to upper for comparison
    # Valid AD domain: alphanumeric + hyphens + dots, at least one dot
    name = name.strip()
    if not name:
        raise ValueError("Domain name cannot be empty")
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
    if not re.match(pattern, name):
        raise ValueError(f"Invalid domain name format: {name}")
    return name.upper()

def validate_username(username: str) -> str:
    """Validate AD username format (SAMAccountName or UPN)."""
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty")
    # Allow SAMAccountName (no @) or UPN (user@domain)
    if "@" in username:
        parts = username.split("@")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"Invalid UPN format: {username}")
    elif "\\" in username:
        parts = username.split("\\")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"Invalid DOMAIN\\user format: {username}")
    return username

def validate_ip_or_hostname(value: str) -> str:
    """Validate that value is a valid IP address or hostname."""
    value = value.strip()
    if not value:
        raise ValueError("Host cannot be empty")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    # Check hostname format
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'
    if not re.match(hostname_pattern, value):
        raise ValueError(f"Invalid IP address or hostname: {value}")
    return value

def validate_object_id(oid: str) -> str:
    """Validate BloodHound object ID format (SID or UUID)."""
    oid = oid.strip()
    # SID format: S-1-5-21-...
    if oid.startswith("S-1-"):
        if re.match(r'^S-1-\d+(-\d+)+$', oid):
            return oid
    # UUID format
    uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if re.match(uuid_pattern, oid):
        return oid
    raise ValueError(f"Invalid object ID format (expected SID or UUID): {oid}")

def validate_config_file(path: str | Path) -> Path:
    """Validate config file path exists and is readable."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise ValueError(f"Config file not found: {p}")
    if not p.is_file():
        raise ValueError(f"Config path is not a file: {p}")
    if p.suffix not in ('.yaml', '.yml'):
        raise ValueError(f"Config file must be YAML (.yaml/.yml): {p}")
    return p

def validate_edge_type(edge_type: str) -> str:
    """Normalize edge type string."""
    return edge_type.strip()

def validate_nt_hash(hash_value: str) -> str:
    """Validate NT hash format (32 hex chars)."""
    hash_value = hash_value.strip().lower()
    if not re.match(r'^[0-9a-f]{32}$', hash_value):
        raise ValueError(f"Invalid NT hash format (expected 32 hex characters): {hash_value}")
    return hash_value

def validate_port(port: int) -> int:
    """Validate network port number."""
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port number (must be 1-65535): {port}")
    return port

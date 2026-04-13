"""YAML configuration loader with Pydantic validation."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from pathstrike.models import ExecutionMode


class BloodHoundConfig(BaseModel):
    """BloodHound CE API connection settings."""

    base_url: str
    token_id: str
    token_key: str


class DomainConfig(BaseModel):
    """Target Active Directory domain settings."""

    name: str
    dc_host: str
    dc_fqdn: str | None = None


class CredentialsConfig(BaseModel):
    """Initial credential set for starting the attack chain."""

    username: str
    password: str | None = None
    nt_hash: str | None = None
    ccache_path: str | None = None


class TargetConfig(BaseModel):
    """Target specification for path discovery."""

    group: str = "DOMAIN ADMINS"
    custom_target: str | None = None


class ExecutionConfig(BaseModel):
    """Runtime behavior settings."""

    mode: ExecutionMode = ExecutionMode.interactive
    timeout: int = 30
    max_paths: int = 5
    max_retries: int = 3
    auto_time_sync: bool = True


class CampaignConfig(BaseModel):
    """Autonomous campaign behavior settings."""

    max_targets: int = 10
    trust_escalation: bool = True
    rescan_after_escalation: bool = True
    max_total_paths: int = 50


class PathStrikeConfig(BaseModel):
    """Root configuration object aggregating all sub-configs."""

    bloodhound: BloodHoundConfig
    domain: DomainConfig
    credentials: CredentialsConfig
    target: TargetConfig = Field(default_factory=TargetConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    campaign: CampaignConfig = Field(default_factory=CampaignConfig)


# Default config search order (checked when ``-c`` is not supplied).
DEFAULT_CONFIG_SEARCH: list[Path] = [
    Path("pathstrike.yaml"),
    Path("pathstrike.yml"),
    Path(".pathstrike.yaml"),
    Path("~/.config/pathstrike/config.yaml").expanduser(),
    Path("~/.pathstrike.yaml").expanduser(),
]


def find_config() -> Path | None:
    """Search well-known locations for a config file.

    Returns:
        The first existing config path, or ``None`` if nothing is found.
    """
    for candidate in DEFAULT_CONFIG_SEARCH:
        resolved = candidate.expanduser().resolve()
        if resolved.is_file():
            return resolved
    return None


def load_config(path: Path) -> PathStrikeConfig:
    """Load and validate a YAML configuration file.

    Args:
        path: Filesystem path to the YAML config file.

    Returns:
        Validated PathStrikeConfig instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file contains invalid YAML.
        pydantic.ValidationError: If the parsed data fails validation.
    """
    config_path = Path(path).expanduser().resolve()

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"Expected YAML mapping at top level, got {type(raw).__name__}")

    return PathStrikeConfig.model_validate(raw)

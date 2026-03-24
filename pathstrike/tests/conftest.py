"""Shared test fixtures for PathStrike test suite."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathstrike.config import (
    PathStrikeConfig, BloodHoundConfig, DomainConfig,
    CredentialsConfig, TargetConfig, ExecutionConfig,
)
from pathstrike.models import (
    NodeInfo, EdgeInfo, PathStep, AttackPath, Credential,
    CredentialType, RollbackAction, ExecutionMode,
)
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.rollback import RollbackManager
from pathstrike.engine.error_handler import RetryPolicy


@pytest.fixture
def sample_config():
    """Minimal valid PathStrike configuration."""
    return PathStrikeConfig(
        bloodhound=BloodHoundConfig(
            base_url="https://bh.corp.local:8080",
            token_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            token_key="dGVzdC1rZXktZm9yLXVuaXQtdGVzdHM=",
        ),
        domain=DomainConfig(
            name="corp.local",
            dc_host="10.0.0.1",
            dc_fqdn="dc01.corp.local",
        ),
        credentials=CredentialsConfig(
            username="jdoe",
            password="P@ssw0rd!",
        ),
        target=TargetConfig(group="DOMAIN ADMINS"),
        execution=ExecutionConfig(mode=ExecutionMode.auto, timeout=30, max_retries=2),
    )


@pytest.fixture
def sample_config_hash(sample_config):
    """Config using NT hash authentication instead of password."""
    sample_config.credentials.password = None
    sample_config.credentials.nt_hash = "aad3b435b51404eeaad3b435b51404ee"
    return sample_config


@pytest.fixture
def sample_config_ccache(sample_config):
    """Config using Kerberos ccache authentication."""
    sample_config.credentials.password = None
    sample_config.credentials.ccache_path = "/tmp/krb5cc_jdoe"
    return sample_config


@pytest.fixture
def cred_store():
    """Empty credential store."""
    return CredentialStore()


@pytest.fixture
def seeded_cred_store():
    """Credential store seeded with a password credential."""
    store = CredentialStore()
    store.add_credential(Credential(
        cred_type=CredentialType.password,
        value="P@ssw0rd!",
        username="jdoe",
        domain="corp.local",
        obtained_from="config",
    ))
    return store


@pytest.fixture
def rollback_mgr(sample_config):
    """Empty rollback manager."""
    return RollbackManager(sample_config)


@pytest.fixture
def retry_policy():
    """Default retry policy."""
    return RetryPolicy(max_retries=2)


@pytest.fixture
def make_node():
    """Factory fixture for creating NodeInfo objects."""
    def _make(name="USER1@CORP.LOCAL", label="User", object_id="node-001", domain="corp.local", **props):
        return NodeInfo(object_id=object_id, name=name, label=label, domain=domain, properties=props)
    return _make


@pytest.fixture
def make_edge(make_node):
    """Factory fixture for creating EdgeInfo objects."""
    def _make(edge_type="GenericAll", source_name="JDOE@CORP.LOCAL", target_name="ADMIN@CORP.LOCAL",
              source_label="User", target_label="User", **edge_props):
        source = make_node(name=source_name, label=source_label, object_id=f"src-{source_name}")
        target = make_node(name=target_name, label=target_label, object_id=f"tgt-{target_name}")
        return EdgeInfo(edge_type=edge_type, source=source, target=target, properties=edge_props)
    return _make


@pytest.fixture
def make_path(make_edge):
    """Factory fixture for creating AttackPath objects with multiple steps."""
    def _make(edges=None):
        if edges is None:
            edges = [
                ("GenericAll", "JDOE@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"),
                ("DCSync", "SVC_SQL@CORP.LOCAL", "CORP.LOCAL"),
            ]
        steps = []
        for i, (etype, src, tgt) in enumerate(edges):
            edge = make_edge(edge_type=etype, source_name=src, target_name=tgt)
            steps.append(PathStep(index=i, edge=edge))
        source = steps[0].edge.source
        target = steps[-1].edge.target
        return AttackPath(steps=steps, source=source, target=target)
    return _make


@pytest.fixture
def mock_tool_success():
    """Standard successful tool result dict."""
    return {
        "success": True,
        "output": "Operation completed successfully",
        "parsed": None,
        "error": None,
        "tool": "mock_tool",
        "command": "mock_tool --test",
        "return_code": 0,
    }


@pytest.fixture
def mock_tool_failure():
    """Standard failed tool result dict."""
    return {
        "success": False,
        "output": "",
        "parsed": None,
        "error": "STATUS_LOGON_FAILURE",
        "tool": "mock_tool",
        "command": "mock_tool --test",
        "return_code": 1,
    }

"""Tests for PathStrike data models."""

import pytest
from datetime import datetime
from pathstrike.models import (
    Credential, CredentialType, NodeInfo, EdgeInfo,
    PathStep, AttackPath, RollbackAction, ExecutionMode,
)

class TestCredential:
    def test_create_password_credential(self):
        cred = Credential(
            cred_type=CredentialType.password,
            value="Summer2024!",
            username="jsmith",
            domain="INTERNAL.LOCAL",
        )
        assert cred.cred_type == CredentialType.password
        assert cred.value == "Summer2024!"
        assert cred.username == "jsmith"
        assert cred.domain == "INTERNAL.LOCAL"
        assert cred.obtained_from is None
        assert isinstance(cred.obtained_at, datetime)

    def test_create_hash_credential(self):
        cred = Credential(
            cred_type=CredentialType.nt_hash,
            value="aad3b435b51404eeaad3b435b51404ee",
            username="admin",
            domain="INTERNAL.LOCAL",
            obtained_from="DCSync",
        )
        assert cred.cred_type == CredentialType.nt_hash
        assert cred.obtained_from == "DCSync"

class TestNodeInfo:
    def test_create_user_node(self):
        node = NodeInfo(
            object_id="S-1-5-21-123-456-789-1001",
            name="JSMITH@INTERNAL.LOCAL",
            label="User",
            domain="INTERNAL.LOCAL",
        )
        assert node.label == "User"
        assert node.properties == {}

    def test_create_group_node(self):
        node = NodeInfo(
            object_id="S-1-5-21-123-456-789-512",
            name="DOMAIN ADMINS@INTERNAL.LOCAL",
            label="Group",
            domain="INTERNAL.LOCAL",
        )
        assert node.label == "Group"

class TestEdgeInfo:
    def test_create_edge(self):
        source = NodeInfo(object_id="s1", name="USER@DOM", label="User", domain="DOM")
        target = NodeInfo(object_id="s2", name="GROUP@DOM", label="Group", domain="DOM")
        edge = EdgeInfo(edge_type="GenericAll", source=source, target=target)
        assert edge.edge_type == "GenericAll"
        assert edge.source.name == "USER@DOM"
        assert edge.target.name == "GROUP@DOM"

class TestAttackPath:
    def test_path_cost(self):
        source = NodeInfo(object_id="s1", name="A@D", label="User", domain="D")
        mid = NodeInfo(object_id="s2", name="B@D", label="Group", domain="D")
        target = NodeInfo(object_id="s3", name="C@D", label="Group", domain="D")

        steps = [
            PathStep(
                index=0,
                edge=EdgeInfo(edge_type="MemberOf", source=source, target=mid),
            ),
            PathStep(
                index=1,
                edge=EdgeInfo(edge_type="GenericAll", source=mid, target=target),
            ),
        ]
        path = AttackPath(steps=steps, source=source, target=target)
        assert path.total_cost == 2

class TestRollbackAction:
    def test_create_rollback(self):
        action = RollbackAction(
            step_index=0,
            action_type="remove_group_member",
            description="Remove jsmith from Domain Admins",
            command="bloodyAD ... remove groupMember 'DOMAIN ADMINS' jsmith",
        )
        assert action.reversible is True
        assert action.executed is False

class TestExecutionMode:
    def test_modes(self):
        assert ExecutionMode.interactive == "interactive"
        assert ExecutionMode.auto == "auto"
        assert ExecutionMode.dry_run == "dry_run"

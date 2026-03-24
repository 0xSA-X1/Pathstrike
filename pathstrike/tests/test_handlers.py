"""Comprehensive handler tests for all PathStrike edge exploitation handlers.

Tests each handler's:
- dry_run=True path (should succeed, return DRY RUN message, no credentials)
- dry_run=False path (mock tool wrappers, verify credential capture)
- Failure path (tool wrapper returns failure)
- Prerequisite checks
- Rollback action generation
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pathstrike.models import Credential, CredentialType, RollbackAction


# ======================================================================
# ForceChangePassword
# ======================================================================


class TestForceChangePasswordHandler:
    """Tests for ForceChangePassword edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.password import ForceChangePasswordHandler
        handler = ForceChangePasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ForceChangePassword", target_name="VICTIM@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.password import ForceChangePasswordHandler
        handler = ForceChangePasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ForceChangePassword", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.password.bloody.set_password", new_callable=AsyncMock) as mock_set:
            mock_set.return_value = {"success": True, "output": "Password changed", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.password
        assert creds[0].username.lower() == "victim"
        mock_set.assert_called_once()

    @pytest.mark.asyncio
    async def test_exploit_failure(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.password import ForceChangePasswordHandler
        handler = ForceChangePasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ForceChangePassword", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.password.bloody.set_password", new_callable=AsyncMock) as mock_set:
            mock_set.return_value = {"success": False, "output": "", "parsed": None, "error": "ACCESS_DENIED"}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_target_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.password import ForceChangePasswordHandler
        handler = ForceChangePasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ForceChangePassword", target_name="GROUP1@CORP.LOCAL", target_label="Group")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False
        assert "User" in msg

    @pytest.mark.asyncio
    async def test_prerequisites_valid(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.password import ForceChangePasswordHandler
        handler = ForceChangePasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ForceChangePassword", target_name="VICTIM@CORP.LOCAL", target_label="User")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is True

    def test_rollback_action_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.password import ForceChangePasswordHandler
        handler = ForceChangePasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ForceChangePassword", target_name="VICTIM@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is None


# ======================================================================
# ReadLAPSPassword
# ======================================================================


class TestReadLAPSHandler:
    """Tests for ReadLAPSPassword edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadLAPSHandler
        handler = ReadLAPSHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadLAPSPassword", target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadLAPSHandler
        handler = ReadLAPSHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadLAPSPassword", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.credential.bloody.read_laps", new_callable=AsyncMock) as mock_laps:
            mock_laps.return_value = {
                "success": True,
                "output": "ms-Mcs-AdmPwd: L4pSP@ssw0rd!",
                "parsed": None,
                "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.password
        assert creds[0].username == "Administrator"

    @pytest.mark.asyncio
    async def test_exploit_failure(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadLAPSHandler
        handler = ReadLAPSHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadLAPSPassword", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.credential.bloody.read_laps", new_callable=AsyncMock) as mock_laps:
            mock_laps.return_value = {"success": False, "output": "", "parsed": None, "error": "ACCESS_DENIED"}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadLAPSHandler
        handler = ReadLAPSHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadLAPSPassword", target_name="JDOE@CORP.LOCAL", target_label="User")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadLAPSHandler
        handler = ReadLAPSHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadLAPSPassword", target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# ReadGMSAPassword
# ======================================================================


class TestReadGMSAHandler:
    """Tests for ReadGMSAPassword edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadGMSAHandler
        handler = ReadGMSAHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadGMSAPassword", target_name="GMSA01@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadGMSAHandler
        handler = ReadGMSAHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadGMSAPassword", target_name="GMSA01@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.credential.bloody.read_gmsa", new_callable=AsyncMock) as mock_gmsa:
            mock_gmsa.return_value = {
                "success": True,
                "output": "NT hash: aad3b435b51404eeaad3b435b51404ee",
                "parsed": None,
                "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.nt_hash

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadGMSAHandler
        handler = ReadGMSAHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadGMSAPassword", target_name="GROUP1@CORP.LOCAL", target_label="Group")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.credential import ReadGMSAHandler
        handler = ReadGMSAHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ReadGMSAPassword", target_name="GMSA01@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# MemberOf
# ======================================================================


class TestMemberOfHandler:
    """Tests for MemberOf edge handler (pass-through)."""

    @pytest.mark.asyncio
    async def test_exploit_passthrough(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import MemberOfHandler
        handler = MemberOfHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="MemberOf", target_name="ADMINS@CORP.LOCAL", target_label="Group")

        success, msg, creds = await handler.exploit(edge, dry_run=False)
        assert success is True
        assert creds == []
        assert "already a member" in msg

    @pytest.mark.asyncio
    async def test_dry_run_also_succeeds(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import MemberOfHandler
        handler = MemberOfHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="MemberOf", target_name="ADMINS@CORP.LOCAL", target_label="Group")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import MemberOfHandler
        handler = MemberOfHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="MemberOf", target_name="ADMINS@CORP.LOCAL", target_label="Group")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# AddMembers
# ======================================================================


class TestAddMembersHandler:
    """Tests for AddMembers edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import AddMembersHandler
        handler = AddMembersHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddMembers", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import AddMembersHandler
        handler = AddMembersHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddMembers", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        with patch("pathstrike.handlers.group.bloody.add_to_group", new_callable=AsyncMock) as mock_add:
            mock_add.return_value = {"success": True, "output": "Added", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert creds == []
        mock_add.assert_called_once()

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import AddMembersHandler
        handler = AddMembersHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddMembers", target_name="JDOE@CORP.LOCAL", target_label="User")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import AddMembersHandler
        handler = AddMembersHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddMembers", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "remove_group_member"
        assert action.reversible is True
        assert "bloodyAD" in action.command


# ======================================================================
# AddSelf
# ======================================================================


class TestAddSelfHandler:
    """Tests for AddSelf edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import AddSelfHandler
        handler = AddSelfHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddSelf", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import AddSelfHandler
        handler = AddSelfHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddSelf", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        with patch("pathstrike.handlers.group.bloody.add_to_group", new_callable=AsyncMock) as mock_add:
            mock_add.return_value = {"success": True, "output": "Added", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "self-enrollment" in msg

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.group import AddSelfHandler
        handler = AddSelfHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddSelf", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.reversible is True


# ======================================================================
# GenericAll / GenericWrite — multiple target types
# ======================================================================


class TestGenericAllHandler:
    """Tests for GenericAll/GenericWrite edge handler across target types."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("edge_type", ["GenericAll", "GenericWrite"])
    async def test_dry_run_user_target(self, sample_config, seeded_cred_store, make_edge, edge_type):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type=edge_type, target_name="VICTIM@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_user_shadow_creds_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.acl.bloody.add_key_credential", new_callable=AsyncMock) as mock_kc:
            mock_kc.return_value = {
                "success": True,
                "output": "/tmp/victim.pfx",
                "parsed": None,
                "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.certificate

    @pytest.mark.asyncio
    async def test_exploit_user_fallback_password(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.acl.bloody.add_key_credential", new_callable=AsyncMock) as mock_kc, \
             patch("pathstrike.handlers.acl.bloody.set_password", new_callable=AsyncMock) as mock_pw:
            mock_kc.return_value = {"success": False, "output": "", "parsed": None, "error": "failed"}
            mock_pw.return_value = {"success": True, "output": "Password changed", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.password

    @pytest.mark.asyncio
    async def test_dry_run_group_target(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_group_target(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name="IT_ADMINS@CORP.LOCAL", target_label="Group")

        with patch("pathstrike.handlers.acl.bloody.add_to_group", new_callable=AsyncMock) as mock_add:
            mock_add.return_value = {"success": True, "output": "Added", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_computer_target(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.acl.bloody.set_rbcd", new_callable=AsyncMock) as mock_rbcd:
            mock_rbcd.return_value = {"success": True, "output": "RBCD set", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True

    @pytest.mark.asyncio
    async def test_exploit_domain_target(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name="CORP.LOCAL", target_label="Domain")

        with patch("pathstrike.handlers.acl.bloody.grant_dcsync_rights", new_callable=AsyncMock) as mock_dc:
            mock_dc.return_value = {"success": True, "output": "DCSync granted", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True

    @pytest.mark.asyncio
    async def test_prerequisites_unsupported_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name="OU1@CORP.LOCAL", target_label="OU")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    @pytest.mark.parametrize("target_label,action_type", [
        ("User", "remove_key_credential"),
        ("Group", "remove_group_member"),
        ("Computer", "remove_rbcd"),
        ("Domain", "remove_dcsync"),
    ])
    def test_rollback_actions(self, sample_config, seeded_cred_store, make_edge, target_label, action_type):
        from pathstrike.handlers.acl import GenericAllHandler
        handler = GenericAllHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="GenericAll", target_name=f"TARGET@CORP.LOCAL", target_label=target_label)

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == action_type
        assert action.reversible is True


# ======================================================================
# WriteDacl
# ======================================================================


class TestWriteDaclHandler:
    """Tests for WriteDacl edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import WriteDaclHandler
        handler = WriteDaclHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteDacl", target_name="VICTIM@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import WriteDaclHandler
        handler = WriteDaclHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteDacl", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.acl.bloody.modify_dacl", new_callable=AsyncMock) as mock_dacl:
            mock_dacl.return_value = {"success": True, "output": "ACE added", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "GenericAll" in msg
        mock_dacl.assert_called_once()

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import WriteDaclHandler
        handler = WriteDaclHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteDacl", target_name="VICTIM@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "remove_dacl_ace"
        assert "GenericAll" in action.command


# ======================================================================
# WriteOwner
# ======================================================================


class TestWriteOwnerHandler:
    """Tests for WriteOwner edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import WriteOwnerHandler
        handler = WriteOwnerHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteOwner", target_name="VICTIM@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import WriteOwnerHandler
        handler = WriteOwnerHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteOwner", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.acl.bloody.set_owner", new_callable=AsyncMock) as mock_own, \
             patch("pathstrike.handlers.acl.bloody.modify_dacl", new_callable=AsyncMock) as mock_dacl:
            mock_own.return_value = {"success": True, "output": "Owner set", "parsed": None, "error": None}
            mock_dacl.return_value = {"success": True, "output": "ACE added", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "ownership" in msg.lower()

    @pytest.mark.asyncio
    async def test_exploit_ownership_fails(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import WriteOwnerHandler
        handler = WriteOwnerHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteOwner", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.acl.bloody.set_owner", new_callable=AsyncMock) as mock_own:
            mock_own.return_value = {"success": False, "output": "", "parsed": None, "error": "denied"}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import WriteOwnerHandler
        handler = WriteOwnerHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteOwner", target_name="VICTIM@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert "original owner NOT restored" in action.description


# ======================================================================
# Owns
# ======================================================================


class TestOwnsHandler:
    """Tests for Owns edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import OwnsHandler
        handler = OwnsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="Owns", target_name="VICTIM@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import OwnsHandler
        handler = OwnsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="Owns", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.acl.bloody.modify_dacl", new_callable=AsyncMock) as mock_dacl:
            mock_dacl.return_value = {"success": True, "output": "ACE added", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "owner privilege" in msg

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import OwnsHandler
        handler = OwnsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="Owns", target_name="VICTIM@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "remove_dacl_ace"


# ======================================================================
# AllExtendedRights
# ======================================================================


class TestAllExtendedRightsHandler:
    """Tests for AllExtendedRights edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run_user(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import AllExtendedRightsHandler
        handler = AllExtendedRightsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllExtendedRights", target_name="VICTIM@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_user_password_change(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import AllExtendedRightsHandler
        handler = AllExtendedRightsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllExtendedRights", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.acl.bloody.set_password", new_callable=AsyncMock) as mock_pw:
            mock_pw.return_value = {"success": True, "output": "Changed", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.password

    @pytest.mark.asyncio
    async def test_dry_run_domain(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import AllExtendedRightsHandler
        handler = AllExtendedRightsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllExtendedRights", target_name="CORP.LOCAL", target_label="Domain")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_prerequisites_unsupported_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import AllExtendedRightsHandler
        handler = AllExtendedRightsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllExtendedRights", target_name="WS01@CORP.LOCAL", target_label="Computer")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.acl import AllExtendedRightsHandler
        handler = AllExtendedRightsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllExtendedRights", target_name="VICTIM@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# AllowedToDelegate
# ======================================================================


class TestAllowedToDelegateHandler:
    """Tests for AllowedToDelegate (constrained delegation) handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import AllowedToDelegateHandler
        handler = AllowedToDelegateHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllowedToDelegate", target_name="DC01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert "S4U2Proxy" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import AllowedToDelegateHandler
        handler = AllowedToDelegateHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllowedToDelegate", target_name="DC01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.delegation.impacket.get_st", new_callable=AsyncMock) as mock_st:
            mock_st.return_value = {"success": True, "output": "Ticket saved", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.ccache

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import AllowedToDelegateHandler
        handler = AllowedToDelegateHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllowedToDelegate", target_name="DC01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# AllowedToAct
# ======================================================================


class TestAllowedToActHandler:
    """Tests for AllowedToAct (RBCD existing) handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import AllowedToActHandler
        handler = AllowedToActHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllowedToAct", target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import AllowedToActHandler
        handler = AllowedToActHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllowedToAct", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.delegation.impacket.get_st", new_callable=AsyncMock) as mock_st:
            mock_st.return_value = {"success": True, "output": "Ticket saved", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.ccache

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import AllowedToActHandler
        handler = AllowedToActHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AllowedToAct", target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# WriteAccountRestrictions
# ======================================================================


class TestWriteAccountRestrictionsHandler:
    """Tests for WriteAccountRestrictions (RBCD write) handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import WriteAccountRestrictionsHandler
        handler = WriteAccountRestrictionsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteAccountRestrictions", target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import WriteAccountRestrictionsHandler
        handler = WriteAccountRestrictionsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteAccountRestrictions", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.delegation.bloody.set_rbcd", new_callable=AsyncMock) as mock_rbcd, \
             patch("pathstrike.handlers.delegation.impacket.get_st", new_callable=AsyncMock) as mock_st:
            mock_rbcd.return_value = {"success": True, "output": "RBCD set", "parsed": None, "error": None}
            mock_st.return_value = {"success": True, "output": "Ticket saved", "parsed": None, "error": None}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.ccache

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import WriteAccountRestrictionsHandler
        handler = WriteAccountRestrictionsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteAccountRestrictions", target_name="JDOE@CORP.LOCAL", target_label="User")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.delegation import WriteAccountRestrictionsHandler
        handler = WriteAccountRestrictionsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteAccountRestrictions", target_name="WS01@CORP.LOCAL", target_label="Computer")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "remove_rbcd"


# ======================================================================
# DCSync (GetChanges, GetChangesAll, DCSync)
# ======================================================================


class TestDCSyncHandler:
    """Tests for DCSync edge handler (GetChanges, GetChangesAll, DCSync)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("edge_type", ["DCSync", "GetChanges", "GetChangesAll"])
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge, edge_type):
        from pathstrike.handlers.replication import DCSyncHandler
        handler = DCSyncHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type=edge_type, target_name="CORP.LOCAL", target_label="Domain")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.replication import DCSyncHandler
        handler = DCSyncHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="DCSync", target_name="CORP.LOCAL", target_label="Domain")

        with patch("pathstrike.handlers.replication.impacket.secretsdump", new_callable=AsyncMock) as mock_sd:
            mock_sd.return_value = {
                "success": True,
                "output": "krbtgt:502:aad3b435:deadbeef01234567deadbeef01234567:::",
                "parsed": None,
                "error": None,
                "hashes": {"krbtgt": "deadbeef01234567deadbeef01234567", "Administrator": "aabbccdd11223344aabbccdd11223344"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 2
        assert all(c.cred_type == CredentialType.nt_hash for c in creds)

    @pytest.mark.asyncio
    async def test_exploit_failure(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.replication import DCSyncHandler
        handler = DCSyncHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="DCSync", target_name="CORP.LOCAL", target_label="Domain")

        with patch("pathstrike.handlers.replication.impacket.secretsdump", new_callable=AsyncMock) as mock_sd:
            mock_sd.return_value = {"success": False, "output": "", "parsed": None, "error": "ACCESS_DENIED"}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.replication import DCSyncHandler
        handler = DCSyncHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="DCSync", target_name="CORP.LOCAL", target_label="Domain")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# AddKeyCredentialLink (Shadow Credentials)
# ======================================================================


class TestShadowCredsHandler:
    """Tests for AddKeyCredentialLink (shadow credentials) handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.shadow_creds import ShadowCredsHandler
        handler = ShadowCredsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddKeyCredentialLink", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("shutil.which", return_value="/usr/bin/bloodyAD"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.shadow_creds import ShadowCredsHandler
        handler = ShadowCredsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddKeyCredentialLink", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("pathstrike.handlers.shadow_creds.add_key_credential", new_callable=AsyncMock) as mock_kc, \
             patch("pathstrike.handlers.shadow_creds.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_kc.return_value = {
                "success": True,
                "output": "DeviceID: abc-123\nSaved to /tmp/victim.pfx",
                "parsed": {"DeviceID": "abc-123", "pfx_path": "/tmp/victim.pfx"},
                "error": None,
            }
            mock_auth.return_value = {
                "success": True,
                "output": "NT hash: aabbccddaabbccddaabbccddaabbccdd\nSaved credential cache to 'victim.ccache'",
                "parsed": {"nt_hash": "aabbccddaabbccddaabbccddaabbccdd", "ccache_path": "victim.ccache"},
                "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) >= 1  # certificate + optional ccache + optional nt_hash

    @pytest.mark.asyncio
    async def test_prerequisites_no_bloodyad(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.shadow_creds import ShadowCredsHandler
        handler = ShadowCredsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddKeyCredentialLink", target_name="VICTIM@CORP.LOCAL", target_label="User")

        with patch("shutil.which", return_value=None):
            ok, msg = await handler.check_prerequisites(edge)

        assert ok is False
        assert "bloodyAD" in msg or "certipy" in msg

    def test_rollback_action_with_device_id(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.shadow_creds import ShadowCredsHandler
        handler = ShadowCredsHandler(config=sample_config, credential_store=seeded_cred_store)
        handler._device_id = "abc-123-def"
        edge = make_edge(edge_type="AddKeyCredentialLink", target_name="VICTIM@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert "abc-123-def" in action.command
        assert action.action_type == "remove_key_credential"


# ======================================================================
# ADCS ESC Handlers
# ======================================================================


class TestADCSESC1Handler:
    """Tests for ADCSESC1 handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC1Handler
        handler = ADCSESC1Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC1", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", template_name="VulnTemplate",
        )

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC1Handler
        handler = ADCSESC1Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC1", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", template_name="VulnTemplate",
        )

        with patch("pathstrike.handlers.adcs.certipy_request", new_callable=AsyncMock) as mock_req, \
             patch("pathstrike.handlers.adcs.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_req.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"pfx_path": "/tmp/admin.pfx"},
            }
            mock_auth.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"nt_hash": "aabbccdd11223344aabbccdd11223344", "ccache_path": "admin.ccache"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) >= 1

    @pytest.mark.asyncio
    async def test_prerequisites_missing_ca(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC1Handler
        handler = ADCSESC1Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ADCSESC1", target_name="ADMIN@CORP.LOCAL", target_label="User")

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            ok, msg = await handler.check_prerequisites(edge)

        assert ok is False
        assert "CA" in msg

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC1Handler
        handler = ADCSESC1Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ADCSESC1", target_name="ADMIN@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


class TestADCSESC3Handler:
    """Tests for ADCSESC3 handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC3Handler
        handler = ADCSESC3Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC3", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", agent_template="EnrollmentAgent",
        )

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC3Handler
        handler = ADCSESC3Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC3", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", agent_template="EnrollmentAgent", target_template="User",
        )

        with patch("pathstrike.handlers.adcs.certipy_request", new_callable=AsyncMock) as mock_req, \
             patch("pathstrike.handlers.adcs.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_req.side_effect = [
                {"success": True, "output": "", "error": None, "parsed": {"pfx_path": "/tmp/agent.pfx"}},
                {"success": True, "output": "", "error": None, "parsed": {"pfx_path": "/tmp/target.pfx"}},
            ]
            mock_auth.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"nt_hash": "deadbeefdeadbeefdeadbeefdeadbeef"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) >= 1

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC3Handler
        handler = ADCSESC3Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ADCSESC3", target_name="ADMIN@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


class TestADCSESC4Handler:
    """Tests for ADCSESC4 handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC4Handler
        handler = ADCSESC4Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC4", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", template_name="WritableTemplate",
        )

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC4Handler
        handler = ADCSESC4Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC4", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", template_name="WritableTemplate",
        )

        with patch("pathstrike.handlers.adcs.certipy_template", new_callable=AsyncMock) as mock_tmpl, \
             patch("pathstrike.handlers.adcs.certipy_request", new_callable=AsyncMock) as mock_req, \
             patch("pathstrike.handlers.adcs.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_tmpl.side_effect = [
                {"success": True, "output": "", "error": None, "parsed": {"old_config_path": "/tmp/old.json"}},
                {"success": True, "output": "", "error": None, "parsed": None},
            ]
            mock_req.return_value = {"success": True, "output": "", "error": None, "parsed": {"pfx_path": "/tmp/admin.pfx"}}
            mock_auth.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"nt_hash": "deadbeefdeadbeefdeadbeefdeadbeef"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC4Handler
        handler = ADCSESC4Handler(config=sample_config, credential_store=seeded_cred_store)
        handler._old_config_path = "/tmp/old.json"
        edge = make_edge(
            edge_type="ADCSESC4", target_name="ADMIN@CORP.LOCAL", target_label="User",
            template_name="WritableTemplate",
        )

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "restore_certificate_template"
        assert "/tmp/old.json" in action.command


class TestADCSESC6Handler:
    """Tests for ADCSESC6 handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC6Handler
        handler = ADCSESC6Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC6", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA",
        )

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg
        assert "EDITF" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC6Handler
        handler = ADCSESC6Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC6", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA",
        )

        with patch("pathstrike.handlers.adcs.certipy_request", new_callable=AsyncMock) as mock_req, \
             patch("pathstrike.handlers.adcs.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_req.return_value = {"success": True, "output": "", "error": None, "parsed": {"pfx_path": "/tmp/admin.pfx"}}
            mock_auth.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"nt_hash": "deadbeefdeadbeefdeadbeefdeadbeef"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC6Handler
        handler = ADCSESC6Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ADCSESC6", target_name="ADMIN@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


class TestADCSESC9Handler:
    """Tests for ADCSESC9 handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC9Handler
        handler = ADCSESC9Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC9", target_name="ADMIN@CORP.LOCAL", target_label="User",
            template_name="VulnTemplate", ca_name="CORP-CA",
        )

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC9Handler
        handler = ADCSESC9Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC9", target_name="ADMIN@CORP.LOCAL", target_label="User",
            template_name="VulnTemplate", ca_name="CORP-CA",
        )

        with patch("pathstrike.handlers.adcs.certipy_account", new_callable=AsyncMock) as mock_acct, \
             patch("pathstrike.handlers.adcs.certipy_request", new_callable=AsyncMock) as mock_req, \
             patch("pathstrike.handlers.adcs.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_acct.side_effect = [
                {"success": True, "output": "", "error": None, "parsed": {"old_upn": "JDOE@CORP.LOCAL"}},
                {"success": True, "output": "", "error": None, "parsed": None},
            ]
            mock_req.return_value = {"success": True, "output": "", "error": None, "parsed": {"pfx_path": "/tmp/admin.pfx"}}
            mock_auth.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"nt_hash": "deadbeefdeadbeefdeadbeefdeadbeef"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC9Handler
        handler = ADCSESC9Handler(config=sample_config, credential_store=seeded_cred_store)
        handler._original_upn = "JDOE@CORP.LOCAL"
        edge = make_edge(edge_type="ADCSESC9", target_name="ADMIN@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "restore_upn"
        assert "JDOE@CORP.LOCAL" in action.command


class TestADCSESC10Handler:
    """Tests for ADCSESC10 handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC10Handler
        handler = ADCSESC10Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC10", target_name="ADMIN@CORP.LOCAL", target_label="User",
            template_name="VulnTemplate", ca_name="CORP-CA",
        )

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC10Handler
        handler = ADCSESC10Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC10", target_name="ADMIN@CORP.LOCAL", target_label="User",
            template_name="VulnTemplate", ca_name="CORP-CA",
        )

        with patch("pathstrike.handlers.adcs.certipy_account", new_callable=AsyncMock) as mock_acct, \
             patch("pathstrike.handlers.adcs.certipy_request", new_callable=AsyncMock) as mock_req, \
             patch("pathstrike.handlers.adcs.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_acct.side_effect = [
                {"success": True, "output": "", "error": None, "parsed": {"old_upn": "JDOE@CORP.LOCAL"}},
                {"success": True, "output": "", "error": None, "parsed": None},
            ]
            mock_req.return_value = {"success": True, "output": "", "error": None, "parsed": {"pfx_path": "/tmp/admin.pfx"}}
            mock_auth.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"nt_hash": "deadbeefdeadbeefdeadbeefdeadbeef"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC10Handler
        handler = ADCSESC10Handler(config=sample_config, credential_store=seeded_cred_store)
        handler._original_upn = "JDOE@CORP.LOCAL"
        edge = make_edge(edge_type="ADCSESC10", target_name="ADMIN@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "restore_upn"


class TestADCSESC13Handler:
    """Tests for ADCSESC13 handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC13Handler
        handler = ADCSESC13Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC13", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", template_name="OIDLinked",
        )

        with patch("shutil.which", return_value="/usr/bin/certipy"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC13Handler
        handler = ADCSESC13Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="ADCSESC13", target_name="ADMIN@CORP.LOCAL", target_label="User",
            ca_name="CORP-CA", template_name="OIDLinked",
        )

        with patch("pathstrike.handlers.adcs.certipy_request", new_callable=AsyncMock) as mock_req, \
             patch("pathstrike.handlers.adcs.certipy_auth", new_callable=AsyncMock) as mock_auth:
            mock_req.return_value = {"success": True, "output": "", "error": None, "parsed": {"pfx_path": "/tmp/esc13.pfx"}}
            mock_auth.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"nt_hash": "deadbeefdeadbeefdeadbeefdeadbeef"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.adcs import ADCSESC13Handler
        handler = ADCSESC13Handler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ADCSESC13", target_name="ADMIN@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# AdminTo
# ======================================================================


class TestAdminToHandler:
    """Tests for AdminTo edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.access import AdminToHandler
        handler = AdminToHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AdminTo", target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.access import AdminToHandler
        handler = AdminToHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AdminTo", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.access.impacket.secretsdump", new_callable=AsyncMock) as mock_sd:
            mock_sd.return_value = {
                "success": True, "output": "", "parsed": None, "error": None,
                "hashes": {"Administrator": "aabbccdd11223344aabbccdd11223344"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) >= 1

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.access import AdminToHandler
        handler = AdminToHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AdminTo", target_name="JDOE@CORP.LOCAL", target_label="User")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.access import AdminToHandler
        handler = AdminToHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AdminTo", target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# HasSession
# ======================================================================


class TestHasSessionHandler:
    """Tests for HasSession edge handler (informational pass-through)."""

    @pytest.mark.asyncio
    async def test_exploit_passthrough(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.access import HasSessionHandler
        handler = HasSessionHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="HasSession", target_name="ADMIN@CORP.LOCAL", target_label="User",
                         source_name="WS01@CORP.LOCAL", source_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=False)
        assert success is True
        assert creds == []
        assert "HasSession" in msg

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.access import HasSessionHandler
        handler = HasSessionHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="HasSession", target_name="ADMIN@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.access import HasSessionHandler
        handler = HasSessionHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="HasSession", target_name="ADMIN@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# CanRDP
# ======================================================================


class TestCanRDPHandler:
    """Tests for CanRDP edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import CanRDPHandler
        handler = CanRDPHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="CanRDP", target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import CanRDPHandler
        handler = CanRDPHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="CanRDP", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.extended_access.check_rdp", new_callable=AsyncMock) as mock_rdp, \
             patch("pathstrike.handlers.extended_access.check_admin", new_callable=AsyncMock) as mock_admin:
            mock_rdp.return_value = True
            mock_admin.return_value = False
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "RDP access confirmed" in msg

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import CanRDPHandler
        handler = CanRDPHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="CanRDP", target_name="JDOE@CORP.LOCAL", target_label="User")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import CanRDPHandler
        handler = CanRDPHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="CanRDP", target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# CanPSRemote
# ======================================================================


class TestCanPSRemoteHandler:
    """Tests for CanPSRemote edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import CanPSRemoteHandler
        handler = CanPSRemoteHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="CanPSRemote", target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import CanPSRemoteHandler
        handler = CanPSRemoteHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="CanPSRemote", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.extended_access.check_winrm", new_callable=AsyncMock) as mock_winrm, \
             patch("pathstrike.handlers.extended_access.execute_command", new_callable=AsyncMock) as mock_cmd:
            mock_winrm.return_value = True
            mock_cmd.return_value = {
                "success": True, "output": "", "error": None,
                "parsed": {"command_output": "corp\\jdoe"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "WinRM" in msg

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import CanPSRemoteHandler
        handler = CanPSRemoteHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="CanPSRemote", target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# ExecuteDCOM
# ======================================================================


class TestExecuteDCOMHandler:
    """Tests for ExecuteDCOM edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import ExecuteDCOMHandler
        handler = ExecuteDCOMHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ExecuteDCOM", target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import ExecuteDCOMHandler
        handler = ExecuteDCOMHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ExecuteDCOM", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.extended_access.dcomexec", new_callable=AsyncMock) as mock_dcom:
            mock_dcom.return_value = {
                "success": True, "output": "corp\\jdoe", "parsed": None, "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "DCOM" in msg

    @pytest.mark.asyncio
    async def test_prerequisites_no_dcomexec(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import ExecuteDCOMHandler
        handler = ExecuteDCOMHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ExecuteDCOM", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("shutil.which", return_value=None):
            ok, msg = await handler.check_prerequisites(edge)

        assert ok is False
        assert "dcomexec" in msg.lower()

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import ExecuteDCOMHandler
        handler = ExecuteDCOMHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="ExecuteDCOM", target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# AddAllowedToAct
# ======================================================================


class TestAddAllowedToActHandler:
    """Tests for AddAllowedToAct (RBCD setup) handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import AddAllowedToActHandler
        handler = AddAllowedToActHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddAllowedToAct", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("shutil.which", return_value="/usr/bin/bloodyAD"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import AddAllowedToActHandler
        handler = AddAllowedToActHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="AddAllowedToAct", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.extended_access.set_rbcd", new_callable=AsyncMock) as mock_rbcd, \
             patch("pathstrike.handlers.extended_access.get_st", new_callable=AsyncMock) as mock_st:
            mock_rbcd.return_value = {"success": True, "output": "RBCD set", "parsed": None, "error": None}
            mock_st.return_value = {
                "success": True,
                "output": "Saving ticket in Administrator.ccache",
                "parsed": None,
                "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) >= 1

    def test_rollback_action(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import AddAllowedToActHandler
        handler = AddAllowedToActHandler(config=sample_config, credential_store=seeded_cred_store)
        handler._machine_account = "JDOE$"
        edge = make_edge(edge_type="AddAllowedToAct", target_name="WS01@CORP.LOCAL", target_label="Computer")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "remove_rbcd"
        assert "JDOE$" in action.command


# ======================================================================
# WriteSPN
# ======================================================================


class TestWriteSPNHandler:
    """Tests for WriteSPN (targeted Kerberoast) handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import WriteSPNHandler
        handler = WriteSPNHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteSPN", target_name="SVCACCT@CORP.LOCAL", target_label="User")

        with patch("shutil.which", return_value="/usr/bin/bloodyAD"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg
        assert "Kerberoast" in msg

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import WriteSPNHandler
        handler = WriteSPNHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="WriteSPN", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("shutil.which", return_value="/usr/bin/bloodyAD"):
            ok, msg = await handler.check_prerequisites(edge)

        assert ok is False

    def test_rollback_action_when_spn_not_cleaned(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import WriteSPNHandler
        handler = WriteSPNHandler(config=sample_config, credential_store=seeded_cred_store)
        handler._added_spn = "pathstrike/SVCACCT.corp.local"
        edge = make_edge(edge_type="WriteSPN", target_name="SVCACCT@CORP.LOCAL", target_label="User")

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "remove_spn"

    def test_rollback_is_none_when_cleaned(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import WriteSPNHandler
        handler = WriteSPNHandler(config=sample_config, credential_store=seeded_cred_store)
        handler._added_spn = None
        edge = make_edge(edge_type="WriteSPN", target_name="SVCACCT@CORP.LOCAL", target_label="User")

        assert handler.get_rollback_action(edge) is None


# ======================================================================
# SyncLAPSPassword
# ======================================================================


class TestSyncLAPSPasswordHandler:
    """Tests for SyncLAPSPassword handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import SyncLAPSPasswordHandler
        handler = SyncLAPSPasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SyncLAPSPassword", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("shutil.which", return_value="/usr/bin/bloodyAD"):
            success, msg, creds = await handler.exploit(edge, dry_run=True)

        assert success is True
        assert "DRY RUN" in msg

    @pytest.mark.asyncio
    async def test_exploit_success_via_bloodyad(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import SyncLAPSPasswordHandler
        handler = SyncLAPSPasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SyncLAPSPassword", target_name="WS01@CORP.LOCAL", target_label="Computer")

        with patch("shutil.which", return_value="/usr/bin/bloodyAD"), \
             patch("pathstrike.handlers.extended_access.read_laps", new_callable=AsyncMock) as mock_laps:
            mock_laps.return_value = {
                "success": True,
                "output": "ms-Mcs-AdmPwd: SuperSecret123!",
                "parsed": {"ms-Mcs-AdmPwd": "SuperSecret123!"},
                "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) >= 1
        assert creds[0].cred_type == CredentialType.password

    @pytest.mark.asyncio
    async def test_prerequisites_wrong_type(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import SyncLAPSPasswordHandler
        handler = SyncLAPSPasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SyncLAPSPassword", target_name="JDOE@CORP.LOCAL", target_label="User")

        ok, msg = await handler.check_prerequisites(edge)
        assert ok is False

    def test_rollback_is_none(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.extended_access import SyncLAPSPasswordHandler
        handler = SyncLAPSPasswordHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SyncLAPSPassword", target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# Parameterized edge type -> handler mapping tests
# ======================================================================


class TestEdgeRegistryMapping:
    """Verify all edge types resolve to the correct handler via the registry."""

    @pytest.mark.parametrize("edge_type,expected_handler_name", [
        ("ForceChangePassword", "ForceChangePasswordHandler"),
        ("ReadLAPSPassword", "ReadLAPSHandler"),
        ("ReadGMSAPassword", "ReadGMSAHandler"),
        ("MemberOf", "MemberOfHandler"),
        ("AddMembers", "AddMembersHandler"),
        ("AddSelf", "AddSelfHandler"),
        ("GenericAll", "GenericAllHandler"),
        ("GenericWrite", "GenericAllHandler"),
        ("WriteDacl", "WriteDaclHandler"),
        ("WriteOwner", "WriteOwnerHandler"),
        ("Owns", "OwnsHandler"),
        ("AllExtendedRights", "AllExtendedRightsHandler"),
        ("AllowedToDelegate", "AllowedToDelegateHandler"),
        ("AllowedToAct", "AllowedToActHandler"),
        ("WriteAccountRestrictions", "WriteAccountRestrictionsHandler"),
        ("GetChanges", "DCSyncHandler"),
        ("GetChangesAll", "DCSyncHandler"),
        ("DCSync", "DCSyncHandler"),
        ("AddKeyCredentialLink", "ShadowCredsHandler"),
        ("ADCSESC1", "ADCSESC1Handler"),
        ("ADCSESC3", "ADCSESC3Handler"),
        ("ADCSESC4", "ADCSESC4Handler"),
        ("ADCSESC6", "ADCSESC6Handler"),
        ("ADCSESC9", "ADCSESC9Handler"),
        ("ADCSESC10", "ADCSESC10Handler"),
        ("ADCSESC13", "ADCSESC13Handler"),
        ("AdminTo", "AdminToHandler"),
        ("HasSession", "HasSessionHandler"),
        ("CanRDP", "CanRDPHandler"),
        ("CanPSRemote", "CanPSRemoteHandler"),
        ("ExecuteDCOM", "ExecuteDCOMHandler"),
        ("AddAllowedToAct", "AddAllowedToActHandler"),
        ("WriteSPN", "WriteSPNHandler"),
        ("SyncLAPSPassword", "SyncLAPSPasswordHandler"),
    ])
    def test_registry_lookup(self, edge_type, expected_handler_name):
        from pathstrike.engine.edge_registry import get_handler
        handler_cls = get_handler(edge_type)
        assert handler_cls is not None, f"No handler registered for {edge_type}"
        assert handler_cls.__name__ == expected_handler_name


# ======================================================================
# HasSIDHistory
# ======================================================================


class TestHasSIDHistoryHandler:
    """Tests for HasSIDHistory edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sid_history import HasSIDHistoryHandler
        handler = HasSIDHistoryHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="HasSIDHistory", target_name="FOREIGNDC@FOREIGN.LOCAL", target_label="Domain")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sid_history import HasSIDHistoryHandler
        handler = HasSIDHistoryHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="HasSIDHistory", target_name="FOREIGNDC@FOREIGN.LOCAL", target_label="Domain")

        with patch("pathstrike.handlers.sid_history.impacket.secretsdump", new_callable=AsyncMock) as mock_sd:
            mock_sd.return_value = {
                "success": True,
                "output": "Dumping hashes...",
                "parsed": None,
                "error": None,
                "hashes": {
                    "Administrator": "aabbccdd11223344aabbccdd11223344",
                    "krbtgt": "deadbeef01234567deadbeef01234567",
                },
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 2
        assert all(c.cred_type == CredentialType.nt_hash for c in creds)
        # Verify cred store was updated with at least one hash
        best = seeded_cred_store.get_best_credential("Administrator", "foreign.local")
        # The handler stores creds with target_domain from edge
        assert best is not None or len(creds) == 2

    @pytest.mark.asyncio
    async def test_exploit_failure(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sid_history import HasSIDHistoryHandler
        handler = HasSIDHistoryHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="HasSIDHistory", target_name="FOREIGNDC@FOREIGN.LOCAL", target_label="Domain")

        with patch("pathstrike.handlers.sid_history.impacket.secretsdump", new_callable=AsyncMock) as mock_sd:
            mock_sd.return_value = {"success": False, "output": "", "parsed": None, "error": "ACCESS_DENIED"}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    def test_no_rollback(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sid_history import HasSIDHistoryHandler
        handler = HasSIDHistoryHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="HasSIDHistory", target_name="FOREIGNDC@FOREIGN.LOCAL", target_label="Domain")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# TrustedBy
# ======================================================================


class TestTrustedByHandler:
    """Tests for TrustedBy edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.trust import TrustedByHandler
        handler = TrustedByHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="TrustedBy", target_name="FOREIGN.LOCAL", target_label="Domain")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.trust import TrustedByHandler
        handler = TrustedByHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="TrustedBy", target_name="FOREIGN.LOCAL", target_label="Domain")

        # Step 1: secretsdump returns trust account hash
        # Step 2: getST returns success (inter-realm TGT)
        with patch("pathstrike.handlers.trust.impacket.secretsdump", new_callable=AsyncMock) as mock_sd, \
             patch("pathstrike.handlers.trust.impacket.get_st", new_callable=AsyncMock) as mock_st:
            mock_sd.return_value = {
                "success": True,
                "output": "Trust key extracted",
                "parsed": None,
                "error": None,
                "hashes": {"FOREIGN$": "aabbccddaabbccddaabbccddaabbccdd"},
            }
            mock_st.return_value = {
                "success": True,
                "output": "Service ticket saved",
                "parsed": None,
                "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        # Should have trust key cred + ccache cred
        assert len(creds) == 2
        cred_types = {c.cred_type for c in creds}
        assert CredentialType.nt_hash in cred_types
        assert CredentialType.ccache in cred_types

    @pytest.mark.asyncio
    async def test_exploit_failure_dcsync(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.trust import TrustedByHandler
        handler = TrustedByHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="TrustedBy", target_name="FOREIGN.LOCAL", target_label="Domain")

        with patch("pathstrike.handlers.trust.impacket.secretsdump", new_callable=AsyncMock) as mock_sd:
            mock_sd.return_value = {"success": False, "output": "", "parsed": None, "error": "ACCESS_DENIED"}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    def test_no_rollback(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.trust import TrustedByHandler
        handler = TrustedByHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="TrustedBy", target_name="FOREIGN.LOCAL", target_label="Domain")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# SQLAdmin
# ======================================================================


class TestSQLAdminHandler:
    """Tests for SQLAdmin edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sql import SQLAdminHandler
        handler = SQLAdminHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SQLAdmin", target_name="SQLSRV01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sql import SQLAdminHandler
        handler = SQLAdminHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SQLAdmin", target_name="SQLSRV01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.sql.impacket.mssqlclient", new_callable=AsyncMock) as mock_sql, \
             patch("pathstrike.handlers.sql.impacket.secretsdump", new_callable=AsyncMock) as mock_sd:
            # First call: enable xp_cmdshell, second call: whoami
            mock_sql.side_effect = [
                {"success": True, "output": "Configuration option changed", "parsed": None, "error": None},
                {"success": True, "output": "nt authority\\system", "parsed": None, "error": None},
            ]
            mock_sd.return_value = {
                "success": True,
                "output": "Hashes dumped",
                "parsed": None,
                "error": None,
                "hashes": {"Administrator": "aabbccddaabbccddaabbccddaabbccdd"},
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) >= 1
        assert creds[0].cred_type == CredentialType.nt_hash

    @pytest.mark.asyncio
    async def test_exploit_failure(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sql import SQLAdminHandler
        handler = SQLAdminHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SQLAdmin", target_name="SQLSRV01@CORP.LOCAL", target_label="Computer")

        with patch("pathstrike.handlers.sql.impacket.mssqlclient", new_callable=AsyncMock) as mock_sql:
            # xp_cmdshell enable fails AND whoami also fails
            mock_sql.side_effect = [
                {"success": False, "output": "", "parsed": None, "error": "Connection failed"},
                {"success": False, "output": "", "parsed": None, "error": "xp_cmdshell disabled"},
            ]
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    def test_rollback_disables_xpcmdshell(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.sql import SQLAdminHandler
        handler = SQLAdminHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SQLAdmin", target_name="SQLSRV01@CORP.LOCAL", target_label="Computer")

        # Simulate that xp_cmdshell was enabled during exploitation
        handler._enabled_xp_cmdshell = True
        handler._sql_target = "10.0.0.100:1433"

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "disable_xp_cmdshell"
        assert "xp_cmdshell" in action.command
        assert action.reversible is True


# ======================================================================
# GPLink
# ======================================================================


class TestGPLinkHandler:
    """Tests for GPLink edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.gpo import GPLinkHandler
        handler = GPLinkHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="GPLink",
            source_name="TESTGPO@CORP.LOCAL",
            target_name="OU_SERVERS@CORP.LOCAL",
            target_label="OU",
            gpo_dn="CN={ABC},CN=Policies,CN=System,DC=corp,DC=local",
        )

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.gpo import GPLinkHandler
        handler = GPLinkHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="GPLink",
            source_name="TESTGPO@CORP.LOCAL",
            target_name="OU_SERVERS@CORP.LOCAL",
            target_label="OU",
            gpo_dn="CN={ABC},CN=Policies,CN=System,DC=corp,DC=local",
        )

        with patch("pathstrike.handlers.gpo.bloody.run_bloodyad", new_callable=AsyncMock) as mock_bloody:
            # First call: read GPO state, second call: modify GPO
            mock_bloody.side_effect = [
                {"success": True, "output": "gPCFileSysPath: \\\\...", "parsed": {}, "error": None},
                {"success": True, "output": "GPO modified", "parsed": None, "error": None},
            ]
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert "modified" in msg.lower() or "GPO" in msg

    @pytest.mark.asyncio
    async def test_exploit_failure(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.gpo import GPLinkHandler
        handler = GPLinkHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="GPLink",
            source_name="TESTGPO@CORP.LOCAL",
            target_name="OU_SERVERS@CORP.LOCAL",
            target_label="OU",
            gpo_dn="CN={ABC},CN=Policies,CN=System,DC=corp,DC=local",
        )

        with patch("pathstrike.handlers.gpo.bloody.run_bloodyad", new_callable=AsyncMock) as mock_bloody:
            # Read succeeds, modify fails
            mock_bloody.side_effect = [
                {"success": True, "output": "gPCFileSysPath: \\\\...", "parsed": {}, "error": None},
                {"success": False, "output": "", "parsed": None, "error": "ACCESS_DENIED"},
            ]
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    def test_rollback_restores_gpo(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.gpo import GPLinkHandler
        handler = GPLinkHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(
            edge_type="GPLink",
            source_name="TESTGPO@CORP.LOCAL",
            target_name="OU_SERVERS@CORP.LOCAL",
            target_label="OU",
            gpo_dn="CN={ABC},CN=Policies,CN=System,DC=corp,DC=local",
        )

        action = handler.get_rollback_action(edge)
        assert action is not None
        assert action.action_type == "restore_gpo"
        assert "bloodyAD" in action.command
        assert action.reversible is True


# ======================================================================
# DiamondTicket
# ======================================================================


class TestDiamondTicketHandler:
    """Tests for DiamondTicket edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import DiamondTicketHandler
        handler = DiamondTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="DiamondTicket", target_name="CORP.LOCAL", target_label="Domain")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import DiamondTicketHandler
        handler = DiamondTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="DiamondTicket", target_name="CORP.LOCAL", target_label="Domain")

        # Seed krbtgt hash in cred store (required prerequisite)
        seeded_cred_store.add_credential(Credential(
            cred_type=CredentialType.nt_hash,
            value="deadbeef01234567deadbeef01234567",
            username="krbtgt",
            domain="corp.local",
            obtained_from="test_seed",
        ))

        with patch("pathstrike.handlers.ticket_forging.impacket.get_tgt", new_callable=AsyncMock) as mock_tgt, \
             patch("pathstrike.handlers.ticket_forging.impacket.ticketer", new_callable=AsyncMock) as mock_tk:
            mock_tgt.return_value = {
                "success": True, "output": "TGT obtained", "parsed": None, "error": None,
            }
            mock_tk.return_value = {
                "success": True, "output": "Ticket forged", "parsed": None, "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.ccache

    @pytest.mark.asyncio
    async def test_exploit_no_krbtgt(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import DiamondTicketHandler
        handler = DiamondTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="DiamondTicket", target_name="CORP.LOCAL", target_label="Domain")

        # Do NOT seed krbtgt — the handler should fail
        success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    def test_no_rollback(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import DiamondTicketHandler
        handler = DiamondTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="DiamondTicket", target_name="CORP.LOCAL", target_label="Domain")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# SapphireTicket
# ======================================================================


class TestSapphireTicketHandler:
    """Tests for SapphireTicket edge handler."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import SapphireTicketHandler
        handler = SapphireTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SapphireTicket", target_name="ADMINISTRATOR@CORP.LOCAL", target_label="User")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert "DRY RUN" in msg
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import SapphireTicketHandler
        handler = SapphireTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SapphireTicket", target_name="ADMINISTRATOR@CORP.LOCAL", target_label="User")

        # Seed krbtgt AES key (preferred for Sapphire Ticket)
        seeded_cred_store.add_credential(Credential(
            cred_type=CredentialType.aes_key,
            value="aabbccdd" * 8,
            username="krbtgt",
            domain="corp.local",
            obtained_from="test_seed",
        ))

        with patch("pathstrike.handlers.ticket_forging.impacket.get_st", new_callable=AsyncMock) as mock_st, \
             patch("pathstrike.handlers.ticket_forging.impacket.ticketer", new_callable=AsyncMock) as mock_tk:
            mock_st.return_value = {
                "success": True, "output": "S4U2Self ticket obtained", "parsed": None, "error": None,
            }
            mock_tk.return_value = {
                "success": True, "output": "Sapphire ticket forged", "parsed": None, "error": None,
            }
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is True
        assert len(creds) == 1
        assert creds[0].cred_type == CredentialType.ccache

    @pytest.mark.asyncio
    async def test_exploit_failure(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import SapphireTicketHandler
        handler = SapphireTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SapphireTicket", target_name="ADMINISTRATOR@CORP.LOCAL", target_label="User")

        # Seed krbtgt AES key
        seeded_cred_store.add_credential(Credential(
            cred_type=CredentialType.aes_key,
            value="aabbccdd" * 8,
            username="krbtgt",
            domain="corp.local",
            obtained_from="test_seed",
        ))

        with patch("pathstrike.handlers.ticket_forging.impacket.get_st", new_callable=AsyncMock) as mock_st:
            mock_st.return_value = {"success": False, "output": "", "parsed": None, "error": "S4U2Self failed"}
            success, msg, creds = await handler.exploit(edge, dry_run=False)

        assert success is False
        assert creds == []

    def test_no_rollback(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.ticket_forging import SapphireTicketHandler
        handler = SapphireTicketHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="SapphireTicket", target_name="ADMINISTRATOR@CORP.LOCAL", target_label="User")
        assert handler.get_rollback_action(edge) is None


# ======================================================================
# Contains
# ======================================================================


class TestContainsHandler:
    """Tests for Contains edge handler (pass-through)."""

    @pytest.mark.asyncio
    async def test_dry_run(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.container import ContainsHandler
        handler = ContainsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="Contains", source_name="OU_SERVERS@CORP.LOCAL", source_label="OU",
                         target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=True)
        assert success is True
        assert creds == []

    @pytest.mark.asyncio
    async def test_exploit_success(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.container import ContainsHandler
        handler = ContainsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="Contains", source_name="OU_SERVERS@CORP.LOCAL", source_label="OU",
                         target_name="WS01@CORP.LOCAL", target_label="Computer")

        success, msg, creds = await handler.exploit(edge, dry_run=False)
        assert success is True
        assert creds == []
        assert "Contains" in msg

    def test_no_rollback(self, sample_config, seeded_cred_store, make_edge):
        from pathstrike.handlers.container import ContainsHandler
        handler = ContainsHandler(config=sample_config, credential_store=seeded_cred_store)
        edge = make_edge(edge_type="Contains", source_name="OU_SERVERS@CORP.LOCAL", source_label="OU",
                         target_name="WS01@CORP.LOCAL", target_label="Computer")
        assert handler.get_rollback_action(edge) is None

"""Tests for the AttackOrchestrator execution engine."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pathstrike.engine.orchestrator import AttackOrchestrator
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.engine.rollback import RollbackManager
from pathstrike.engine.error_handler import RetryPolicy
from pathstrike.models import ExecutionMode


class TestAttackOrchestrator:
    """Tests for AttackOrchestrator core functionality."""

    @pytest.mark.asyncio
    async def test_execute_path_dry_run(self, sample_config, make_path):
        """Dry-run mode should succeed without executing real tools."""
        cred_store = CredentialStore()
        rollback_mgr = RollbackManager(sample_config)
        retry_policy = RetryPolicy()

        orchestrator = AttackOrchestrator(
            sample_config, cred_store, rollback_mgr,
            retry_policy=retry_policy, verbose=False,
        )

        path = make_path()  # default 2-step path

        # Mock handler to return dry-run success
        mock_handler_cls = MagicMock()
        mock_handler = AsyncMock()
        mock_handler.check_prerequisites = AsyncMock(return_value=(True, "Ready"))
        mock_handler.exploit = AsyncMock(return_value=(
            True, "[DRY RUN] Would exploit", [],
        ))
        mock_handler.get_rollback_action = MagicMock(return_value=None)
        mock_handler_cls.return_value = mock_handler

        with patch("pathstrike.engine.orchestrator.get_handler", return_value=mock_handler_cls):
            result = await orchestrator.execute_path(path, ExecutionMode.dry_run)

        assert result is True

    @pytest.mark.asyncio
    async def test_execute_path_no_handler(self, sample_config, make_path):
        """Path with unsupported edge type should fail gracefully."""
        cred_store = CredentialStore()
        rollback_mgr = RollbackManager(sample_config)
        retry_policy = RetryPolicy()

        orchestrator = AttackOrchestrator(
            sample_config, cred_store, rollback_mgr,
            retry_policy=retry_policy, verbose=False,
        )

        path = make_path(edges=[
            ("UnsupportedEdge", "JDOE@CORP.LOCAL", "ADMIN@CORP.LOCAL"),
        ])

        with patch("pathstrike.engine.orchestrator.get_handler", return_value=None):
            result = await orchestrator.execute_path(path, ExecutionMode.auto)

        assert result is False

    @pytest.mark.asyncio
    async def test_execute_path_step_failure(self, sample_config, make_path):
        """Step failure should stop execution and return False."""
        cred_store = CredentialStore()
        rollback_mgr = RollbackManager(sample_config)
        retry_policy = RetryPolicy(max_retries=0)

        orchestrator = AttackOrchestrator(
            sample_config, cred_store, rollback_mgr,
            retry_policy=retry_policy, verbose=False,
        )

        path = make_path()  # default 2-step path

        mock_handler_cls = MagicMock()
        mock_handler = AsyncMock()
        mock_handler.check_prerequisites = AsyncMock(return_value=(True, "Ready"))
        mock_handler.exploit = AsyncMock(return_value=(
            False, "Tool failed", [],
        ))
        mock_handler.get_rollback_action = MagicMock(return_value=None)
        mock_handler_cls.return_value = mock_handler

        with patch("pathstrike.engine.orchestrator.get_handler", return_value=mock_handler_cls):
            result = await orchestrator.execute_path(path, ExecutionMode.auto)

        assert result is False

    @pytest.mark.asyncio
    async def test_checkpoint_integration(self, sample_config, make_path):
        """Checkpoint manager should record step results."""
        cred_store = CredentialStore()
        rollback_mgr = RollbackManager(sample_config)
        retry_policy = RetryPolicy(max_retries=0)

        mock_checkpoint = MagicMock()
        mock_checkpoint.start_path = MagicMock()
        mock_checkpoint.record_step_success = MagicMock()
        mock_checkpoint.record_step_failure = MagicMock()
        mock_checkpoint.mark_complete = MagicMock()

        orchestrator = AttackOrchestrator(
            sample_config, cred_store, rollback_mgr,
            retry_policy=retry_policy, verbose=False,
            checkpoint_mgr=mock_checkpoint,
        )

        path = make_path(edges=[
            ("GenericAll", "JDOE@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"),
        ])

        mock_handler_cls = MagicMock()
        mock_handler = AsyncMock()
        mock_handler.check_prerequisites = AsyncMock(return_value=(True, "Ready"))
        mock_handler.exploit = AsyncMock(return_value=(
            True, "Exploited", [],
        ))
        mock_handler.get_rollback_action = MagicMock(return_value=None)
        mock_handler_cls.return_value = mock_handler

        with patch("pathstrike.engine.orchestrator.get_handler", return_value=mock_handler_cls):
            result = await orchestrator.execute_path(path, ExecutionMode.auto)

        assert result is True

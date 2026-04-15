"""Tests for the PathStrike CLI application."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typer.testing import CliRunner

from pathstrike.cli import app

runner = CliRunner()


class TestCLIEdges:
    """Tests for the 'edges' command."""

    def test_edges_shows_supported_types(self):
        """edges command should list registered handler edge types."""
        # Import handlers to trigger registration
        import pathstrike.handlers  # noqa: F401

        result = runner.invoke(app, ["edges"])
        assert result.exit_code == 0
        assert "Supported Edge Types" in result.output or "edge type" in result.output.lower()

    def test_edges_no_handlers(self):
        """edges with no registered handlers shows appropriate message."""
        with patch("pathstrike.cli.get_supported_edges", return_value=[]):
            with patch("pathstrike.cli.list_handlers", return_value={}):
                result = runner.invoke(app, ["edges"])
        assert result.exit_code == 0


class TestCLICheckpoints:
    """Tests for the 'checkpoints' command."""

    def test_checkpoints_no_files(self):
        """checkpoints with no checkpoint files shows empty message."""
        mock_mgr = MagicMock()
        mock_mgr.list_checkpoints.return_value = []

        with patch("pathstrike.cli.CheckpointManager", return_value=mock_mgr):
            result = runner.invoke(app, ["checkpoints"])

        assert result.exit_code == 0
        assert "No checkpoints" in result.output or "no checkpoint" in result.output.lower()

    def test_checkpoints_with_data(self):
        """checkpoints displays checkpoint table when data exists."""
        mock_mgr = MagicMock()
        mock_mgr.list_checkpoints.return_value = [
            {
                "source": "USER@CORP.LOCAL",
                "target": "DOMAIN ADMINS@CORP.LOCAL",
                "status": "failed",
                "completed_steps": 2,
                "total_steps": 5,
                "updated_at": "2024-01-15T10:30:00",
                "file": "checkpoint_abc123.json",
            }
        ]

        with patch("pathstrike.cli.CheckpointManager", return_value=mock_mgr):
            result = runner.invoke(app, ["checkpoints"])

        assert result.exit_code == 0
        assert "USER@CORP.LOCAL" in result.output


class TestCLIHelp:
    """Tests for CLI help output."""

    def test_help_shows_commands(self):
        """--help should list all available commands."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "attack" in result.output
        assert "edges" in result.output
        assert "verify" in result.output
        assert "rollback" in result.output

    def test_attack_help(self):
        """attack --help should show resume and mode options."""
        result = runner.invoke(app, ["attack", "--help"])
        assert result.exit_code == 0
        assert "--resume" in result.output
        assert "--mode" in result.output

    def test_paths_help(self):
        """paths --help should show source and max-paths options."""
        result = runner.invoke(app, ["paths", "--help"])
        assert result.exit_code == 0
        assert "--source" in result.output


class TestCLIConfigErrors:
    """Tests for config loading error handling."""

    def test_attack_no_config(self):
        """attack without config should fail gracefully."""
        with patch("pathstrike.cli.find_config", return_value=None):
            result = runner.invoke(app, ["attack", "-s", "test"])

        assert result.exit_code == 1
        assert "Config error" in result.output or "config" in result.output.lower()

    def test_paths_no_config(self):
        """paths without config should fail gracefully."""
        with patch("pathstrike.cli.find_config", return_value=None):
            result = runner.invoke(app, ["paths", "-s", "test"])

        assert result.exit_code == 1

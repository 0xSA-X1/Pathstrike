"""Tests for tool wrapper modules (Impacket, NetExec, Certipy, bloodyAD)."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Impacket wrapper tests
# ---------------------------------------------------------------------------

class TestImpacketWrapper:
    """Tests for pathstrike.tools.impacket_wrapper."""

    @pytest.mark.asyncio
    async def test_run_impacket_tool_success(self):
        """Successful tool execution returns success=True with output."""
        from pathstrike.tools.impacket_wrapper import run_impacket_tool

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"output data", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await run_impacket_tool("test_tool.py", ["arg1"], timeout=10)

        assert result["success"] is True
        assert result["output"] == "output data"
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_run_impacket_tool_failure(self):
        """Failed tool execution returns success=False with error."""
        from pathstrike.tools.impacket_wrapper import run_impacket_tool

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error msg"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await run_impacket_tool("test_tool.py", [], timeout=10)

        assert result["success"] is False
        assert result["error"] == "error msg"

    @pytest.mark.asyncio
    async def test_run_impacket_tool_timeout(self):
        """Timeout raises and is captured in result."""
        from pathstrike.tools.impacket_wrapper import run_impacket_tool

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            result = await run_impacket_tool("test_tool.py", [], timeout=5)

        assert result["success"] is False
        assert "timed out" in result["error"]
        assert result.get("error_type") == "timeout"

    @pytest.mark.asyncio
    async def test_run_impacket_tool_not_found(self):
        """Missing tool reports tool_not_found error."""
        from pathstrike.tools.impacket_wrapper import run_impacket_tool

        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
            result = await run_impacket_tool("nonexistent.py", [], timeout=10)

        assert result["success"] is False
        assert "not found" in result["error"]
        assert result.get("error_type") == "tool_not_found"

    def test_build_impacket_auth_password(self):
        """Password auth returns dc-ip flag only."""
        from pathstrike.tools.impacket_wrapper import build_impacket_auth

        args = build_impacket_auth("corp.local", "admin", password="Pass123", dc_ip="10.0.0.1")
        assert "-dc-ip" in args
        assert "10.0.0.1" in args
        assert "-hashes" not in args

    def test_build_impacket_auth_hash(self):
        """Hash auth returns -hashes flag."""
        from pathstrike.tools.impacket_wrapper import build_impacket_auth

        args = build_impacket_auth("corp.local", "admin", nt_hash="aabbccdd" * 4)
        assert "-hashes" in args

    def test_build_impacket_auth_ccache(self):
        """Ccache auth returns -k -no-pass flags."""
        from pathstrike.tools.impacket_wrapper import build_impacket_auth

        args = build_impacket_auth("corp.local", "admin", ccache_path="/tmp/krb5cc_0")
        assert "-k" in args
        assert "-no-pass" in args

    def test_build_target_string(self):
        """Target string includes domain/user:password@host."""
        from pathstrike.tools.impacket_wrapper import build_target_string

        target = build_target_string("corp.local", "admin", password="Pass", target_host="10.0.0.1")
        assert target == "corp.local/admin:Pass@10.0.0.1"

    def test_build_target_string_hash(self):
        """Hash auth leaves password empty in target string."""
        from pathstrike.tools.impacket_wrapper import build_target_string

        target = build_target_string("corp.local", "admin", nt_hash="aabb" * 8)
        assert target == "corp.local/admin:"

    @pytest.mark.asyncio
    async def test_secretsdump_parses_hashes(self):
        """secretsdump should parse NT hashes from output."""
        from pathstrike.tools.impacket_wrapper import secretsdump

        output = (
            "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
            "corp.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "corp.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:abcdabcdabcdabcdabcdabcdabcdabcd:::\n"
        )
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(output.encode(), b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await secretsdump(
                "10.0.0.1", [], "corp.local", "admin", password="Pass", dc_ip="10.0.0.1"
            )

        assert result["success"] is True
        assert "hashes" in result
        assert "Administrator" in result["hashes"]
        assert result["hashes"]["Administrator"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
        assert result["hashes"]["krbtgt"] == "abcdabcdabcdabcdabcdabcdabcdabcd"


# ---------------------------------------------------------------------------
# NetExec wrapper tests
# ---------------------------------------------------------------------------

class TestNetExecWrapper:
    """Tests for pathstrike.tools.netexec_wrapper."""

    @pytest.mark.asyncio
    async def test_run_netexec_success(self):
        """Successful netexec returns success=True when [+] in output."""
        from pathstrike.tools.netexec_wrapper import run_netexec

        output = b"SMB  10.0.0.1  445  DC01  [+] corp.local\\admin:Pass (Pwn3d!)"
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(output, b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await run_netexec("smb", "10.0.0.1", [], ["-u", "admin", "-p", "Pass"])

        assert result["success"] is True
        assert result["parsed"]["admin"] is True

    @pytest.mark.asyncio
    async def test_run_netexec_auth_failure(self):
        """Auth failure ([-] only) should return success=False."""
        from pathstrike.tools.netexec_wrapper import run_netexec

        output = b"SMB  10.0.0.1  445  DC01  [-] corp.local\\admin:WrongPass STATUS_LOGON_FAILURE"
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(output, b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await run_netexec("smb", "10.0.0.1", [], ["-u", "admin", "-p", "Wrong"])

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_run_netexec_timeout(self):
        """Timeout is captured in result."""
        from pathstrike.tools.netexec_wrapper import run_netexec

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            result = await run_netexec("smb", "10.0.0.1", [], timeout=5)

        assert result["success"] is False
        assert "timed out" in result["error"]

    def test_build_nxc_auth_password(self):
        """Password auth builds -u -p flags."""
        from pathstrike.tools.netexec_wrapper import build_nxc_auth

        args = build_nxc_auth("admin", password="Pass", domain="corp.local")
        assert "-u" in args
        assert "admin" in args
        assert "-p" in args
        assert "Pass" in args
        assert "-d" in args

    def test_build_nxc_auth_hash(self):
        """Hash auth builds -H flag."""
        from pathstrike.tools.netexec_wrapper import build_nxc_auth

        args = build_nxc_auth("admin", nt_hash="aabb" * 8)
        assert "-H" in args

    def test_build_nxc_auth_kerberos(self):
        """Kerberos auth builds --use-kcache flag."""
        from pathstrike.tools.netexec_wrapper import build_nxc_auth

        args = build_nxc_auth("admin", ccache_path="/tmp/krb5cc_0")
        assert "--use-kcache" in args
        assert "-k" in args

    @pytest.mark.asyncio
    async def test_check_admin_true(self):
        """check_admin returns True when Pwn3d! in output."""
        from pathstrike.tools.netexec_wrapper import check_admin

        output = b"SMB  10.0.0.1  445  DC01  [+] admin (Pwn3d!)"
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(output, b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await check_admin("10.0.0.1", ["-u", "admin", "-p", "Pass"])

        assert result is True

    @pytest.mark.asyncio
    async def test_check_admin_false(self):
        """check_admin returns False when no Pwn3d! in output."""
        from pathstrike.tools.netexec_wrapper import check_admin

        output = b"SMB  10.0.0.1  445  DC01  [+] admin"
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(output, b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await check_admin("10.0.0.1", ["-u", "admin", "-p", "Pass"])

        assert result is False

    def test_parse_secretsdump_hashes(self):
        """NTDS/SAM pwdump lines are parsed into user -> NT hash."""
        from pathstrike.tools.netexec_wrapper import _parse_secretsdump_hashes

        out = (
            "SMB  10.0.0.1  445  DC01  Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:" + "ab" * 16 + ":::\n"
            "SMB  10.0.0.1  445  DC01  CORP\\krbtgt:502:"
            "aad3b435b51404eeaad3b435b51404ee:" + "cd" * 16 + ":::"
        )
        hashes = _parse_secretsdump_hashes(out)
        assert hashes["Administrator"] == "ab" * 16
        # DOMAIN\\user is normalised to the bare sAMAccountName
        assert hashes["krbtgt"] == "cd" * 16

    def test_parse_gmsa_hashes(self):
        """gMSA output lines are parsed into account -> NT hash."""
        from pathstrike.tools.netexec_wrapper import _parse_gmsa_hashes

        out = "LDAP  10.0.0.1  389  DC01  Account: svc_gmsa$    NTLM: " + "ef" * 16
        gmsa = _parse_gmsa_hashes(out)
        assert gmsa["svc_gmsa$"] == "ef" * 16

    @pytest.mark.asyncio
    async def test_s4u_delegate_builds_flags(self):
        """s4u_delegate passes --delegate/--delegate-spn/--generate-st through."""
        from pathstrike.tools import netexec_wrapper as nxc

        captured = {}

        async def fake_run(protocol, target, args, auth_args=None, timeout=30):
            captured["protocol"] = protocol
            captured["args"] = args
            return {"success": True, "output": "", "parsed": None, "error": None}

        with patch.object(nxc, "run_netexec", fake_run):
            await nxc.s4u_delegate(
                "host.corp.local",
                ["-u", "svc", "-H", "ab" * 16, "-d", "corp.local"],
                impersonate="Administrator",
                spn="cifs/host.corp.local",
                generate_st="/tmp/st.ccache",
            )

        assert captured["protocol"] == "smb"
        assert captured["args"][:2] == ["--delegate", "Administrator"]
        assert "--delegate-spn" in captured["args"]
        assert "--generate-st" in captured["args"]

    def test_nxc_auth_from_bloodyad_hash(self):
        """The shared bloodyAD->nxc converter rewrites -p :NTHASH to -H."""
        from pathstrike.handlers.base import BaseEdgeHandler

        out = BaseEdgeHandler._nxc_auth_from_bloodyad(
            ["-u", "svc", "-p", ":" + "ab" * 16], "corp.local"
        )
        assert out == ["-u", "svc", "-H", "ab" * 16, "-d", "corp.local"]


# ---------------------------------------------------------------------------
# Auth builder edge cases
# ---------------------------------------------------------------------------

class TestAuthBuilders:
    """Cross-cutting tests for authentication argument builders."""

    def test_impacket_auth_aes_key(self):
        """AES key auth returns -aesKey flag."""
        from pathstrike.tools.impacket_wrapper import build_impacket_auth

        args = build_impacket_auth("corp.local", "admin", aes_key="aabb" * 16, dc_ip="10.0.0.1")
        assert "-aesKey" in args
        assert "-dc-ip" in args

    def test_nxc_auth_no_creds(self):
        """No credentials should use empty password."""
        from pathstrike.tools.netexec_wrapper import build_nxc_auth

        args = build_nxc_auth("admin")
        assert "-p" in args
        idx = args.index("-p")
        assert args[idx + 1] == ""

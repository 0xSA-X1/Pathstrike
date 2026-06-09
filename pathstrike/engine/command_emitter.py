"""Command-emission ("learn") mode for PathStrike.

When emit mode is active, the tool wrappers (``run_certipy``, ``run_bloodyad``,
``run_impacket_tool``, coercer/ntlmrelayx, netexec) build their argv exactly as
they would for a real run — then **record** it and return a synthetic
placeholder result *instead of executing the subprocess*.  Because the real
handler code still runs (it just never spawns a process), multi-step chains
(ESC1 request→pfx→auth, ESC3 agent→on-behalf, shadow-creds, the no-PT bridge)
emit every command in order, with whatever values resolved live (CA host, node
names, SIDs) and placeholders for things only known at run time (issued cert
paths, recovered hashes).

This powers ``pathstrike learn`` and ``pathstrike campaign --learn``: the tool
becomes usable for manual ops, not just automated exploitation.
"""

from __future__ import annotations

import contextvars
import shlex
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EmittedCommand:
    """One recorded command in the order it would have been executed."""

    tool: str
    argv: list[str]
    redacted: str = ""
    note: str | None = None
    branch: str | None = None  # labeled alternative technique, when applicable

    @property
    def line(self) -> str:
        """Real, copy-pasteable command line (shell-quoted)."""
        return " ".join(shlex.quote(a) for a in self.argv)

    def render(self, redact: bool) -> str:
        return self.redacted if (redact and self.redacted) else self.line


@dataclass
class Emitter:
    """Collects emitted commands for the current emit-mode scope."""

    redact: bool = False
    commands: list[EmittedCommand] = field(default_factory=list)
    current_branch: str | None = None

    def record(
        self,
        tool: str,
        argv: list[str],
        *,
        redacted: str | None = None,
        note: str | None = None,
    ) -> None:
        self.commands.append(
            EmittedCommand(
                tool=tool, argv=list(argv), redacted=redacted or "",
                note=note, branch=self.current_branch,
            )
        )


_emitter: contextvars.ContextVar[Emitter | None] = contextvars.ContextVar(
    "pathstrike_emitter", default=None
)


def current_emitter() -> Emitter | None:
    """Return the active :class:`Emitter`, or ``None`` when not in emit mode."""
    return _emitter.get()


class emit_mode:
    """Context manager that activates command emission for its scope.

    Usage::

        with emit_mode(redact=False) as em:
            await handler.exploit(edge, dry_run=False)
        for cmd in em.commands:
            print(cmd.render(em.redact))
    """

    def __init__(self, redact: bool = False) -> None:
        self.emitter = Emitter(redact=redact)
        self._token: contextvars.Token | None = None

    def __enter__(self) -> Emitter:
        self._token = _emitter.set(self.emitter)
        return self.emitter

    def __exit__(self, *exc: object) -> bool:
        if self._token is not None:
            _emitter.reset(self._token)
        return False


def emitting() -> bool:
    """True if emit mode is active (handlers use this to enumerate branches)."""
    return _emitter.get() is not None


def set_branch(label: str | None) -> None:
    """Label subsequent emitted commands as belonging to alternative *label*.

    Branchy handlers (ACL strategy ladder, delegation protocol-transition vs
    RBCD-bridge) call this before each alternative so ``learn`` can show every
    option, grouped and labeled, instead of only the primary one.  No-op when
    not emitting.
    """
    em = _emitter.get()
    if em is not None:
        em.current_branch = label


def record_command(
    tool: str,
    argv: list[str],
    *,
    redacted: str | None = None,
    note: str | None = None,
) -> bool:
    """Record *argv* if emit mode is active.

    Returns ``True`` when emit mode is active — the caller (a tool wrapper)
    should then SKIP executing the subprocess and return a placeholder result
    via :func:`placeholder_result`.  Returns ``False`` for a normal live run.
    """
    em = _emitter.get()
    if em is None:
        return False
    em.record(tool, argv, redacted=redacted, note=note)
    return True


# ---------------------------------------------------------------------------
# Per-tool placeholder results
# ---------------------------------------------------------------------------
#
# Multi-step handlers consume the ``parsed`` dict / ``output`` of an earlier
# step to build the next command (e.g. the issued PFX path, the recovered NT
# hash, a saved template-config backup).  In emit mode the subprocess never
# runs, so we return believable placeholders that keep the chain going and
# read clearly in the printed playbook.

_PLACEHOLDER = {
    "nt_hash": "<NT_HASH>",
    "pfx": "<issued-cert.pfx>",
    "ccache": "<ticket.ccache>",
}


def placeholder_result(
    tool: str,
    argv: list[str],
    *,
    subcommand: str | None = None,
) -> dict[str, Any]:
    """Synthetic success result returned by wrappers while emitting.

    *subcommand* lets certipy/bloodyAD-style tools tailor the placeholder
    ``parsed`` payload to what the calling handler will read next.
    """
    result: dict[str, Any] = {
        "success": True,
        "output": placeholder_output(tool, argv),
        "stderr": "",
        "error": None,
        "return_code": 0,
        "tool": tool,
        "command": " ".join(shlex.quote(c) for c in argv),
        "parsed": {},
        "emitted": True,
    }
    result["parsed"] = _placeholder_parsed(tool, argv, subcommand)
    return result


def _placeholder_parsed(
    tool: str, argv: list[str], subcommand: str | None
) -> dict[str, Any]:
    sub = (subcommand or (argv[0] if argv else "")).lower()
    joined = " ".join(argv).lower()

    if tool == "certipy":
        if sub == "req":
            return {"pfx_path": _PLACEHOLDER["pfx"]}
        if sub == "auth":
            return {
                "nt_hash": _PLACEHOLDER["nt_hash"],
                "ccache_path": _PLACEHOLDER["ccache"],
                "tgt_obtained": True,
            }
        if sub == "template":
            return {"old_config_path": "<template>_backup.json", "modified": True}
        return {}

    if tool == "bloodyAD":
        # shadowCredentials prints the recovered NT hash + a TGT ccache; the
        # shadow-creds handler parses those out of ``output``.
        if "shadowcredentials" in joined:
            return {}
        return {}

    if tool in ("impacket", "secretsdump.py", "getST.py", "getTGT.py"):
        return {}

    return {}


def placeholder_output(tool: str, argv: list[str]) -> str:
    """Synthetic stdout for wrappers whose handlers re-parse ``output``.

    bloodyAD ``add shadowCredentials`` is the notable case: the shadow-creds
    handler scrapes ``NT: <hash>`` and ``TGT stored in ccache file <p>`` out of
    stdout, so we hand it well-formed placeholder lines.
    """
    joined = " ".join(argv).lower()
    if tool == "bloodyAD" and "shadowcredentials" in joined and "add" in joined:
        return (
            "[+] KeyCredential generated with following sha256 of RSA key: <SHA256>\n"
            f"[+] TGT stored in ccache file {_PLACEHOLDER['ccache']}\n"
            f"\nNT: {_PLACEHOLDER['nt_hash']}"
        )
    # impacket getST.py / getTGT.py — handlers parse "Saving ticket in <f>.ccache"
    if tool == "impacket" and any("getst" in a.lower() or "gettgt" in a.lower() for a in argv):
        return f"[*] Saving ticket in {_PLACEHOLDER['ccache']}"
    return "[emit] command recorded; not executed"

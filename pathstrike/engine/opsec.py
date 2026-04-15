"""OPSEC awareness engine for attack path risk assessment.

Maps BloodHound edge types to detection risk profiles, allowing operators
to evaluate the stealth implications of each exploitation step before
execution.

Risk levels:
    - **LOW**: Passive reconnaissance or read-only operations unlikely to
      trigger alerts (e.g., group membership traversal, LAPS reads).
    - **MEDIUM**: ACL modifications or credential changes that may appear
      in security logs but are common in enterprise environments.
    - **HIGH**: Active exploitation techniques that generate distinctive
      event log signatures or network traffic patterns.
    - **CRITICAL**: Domain-wide impact operations that are highly likely
      to trigger advanced detection systems (SIEM, MDR, EDR).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

logger = logging.getLogger("pathstrike.engine.opsec")

console = Console()


class RiskLevel(StrEnum):
    """OPSEC risk classification for edge exploitation."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class OpsecProfile:
    """Detection risk profile for a specific edge type.

    Attributes:
        risk_level: Overall detection risk classification.
        detection_sources: Security controls likely to detect this technique.
        mitigations: Steps the operator can take to reduce detection risk.
        windows_events: Relevant Windows Event IDs that may be generated.
        description: Brief explanation of why this risk level was assigned.
    """

    risk_level: RiskLevel
    detection_sources: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()
    windows_events: tuple[str, ...] = ()
    description: str = ""


# ---------------------------------------------------------------------------
# Edge type → OPSEC profile mapping
# ---------------------------------------------------------------------------

EDGE_OPSEC_MAP: dict[str, OpsecProfile] = {
    # ---- LOW RISK: Read-only / traversal operations ----
    "MemberOf": OpsecProfile(
        risk_level=RiskLevel.LOW,
        description="Group membership traversal — no AD modifications",
        detection_sources=("LDAP query logs",),
        mitigations=("Use existing session tokens to avoid new auth events",),
    ),
    "Contains": OpsecProfile(
        risk_level=RiskLevel.LOW,
        description="OU containment traversal — informational only",
    ),
    "HasSession": OpsecProfile(
        risk_level=RiskLevel.LOW,
        description="Session enumeration — passive check",
        detection_sources=("NetSessionEnum audit logs",),
    ),
    "ReadLAPSPassword": OpsecProfile(
        risk_level=RiskLevel.LOW,
        description="LAPS password read via authorized LDAP query",
        detection_sources=("4662 - Directory Service Access",),
        windows_events=("4662",),
    ),
    "SyncLAPSPassword": OpsecProfile(
        risk_level=RiskLevel.LOW,
        description="LAPS password sync via authorized LDAP query",
        detection_sources=("4662 - Directory Service Access",),
        windows_events=("4662",),
    ),
    "ReadGMSAPassword": OpsecProfile(
        risk_level=RiskLevel.LOW,
        description="gMSA password read via authorized LDAP query",
        detection_sources=("4662 - Directory Service Access",),
        windows_events=("4662",),
    ),
    "HasSIDHistory": OpsecProfile(
        risk_level=RiskLevel.LOW,
        description="SID History attribute check — read-only",
    ),

    # ---- MEDIUM RISK: ACL/permission modifications ----
    "GenericAll": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Full control exploitation — may modify object attributes",
        detection_sources=("4662 - DS Access", "5136 - Directory Object Modified", "EDR/SIEM"),
        mitigations=("Exploit during business hours to blend with normal activity",),
        windows_events=("4662", "5136"),
    ),
    "GenericWrite": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Write property exploitation — modifies specific attributes",
        detection_sources=("5136 - Directory Object Modified",),
        windows_events=("5136",),
    ),
    "WriteDacl": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="DACL modification — changes object permissions",
        detection_sources=("4670 - Permissions Changed", "5136 - DS Modified"),
        mitigations=("Restore original DACL after exploitation",),
        windows_events=("4670", "5136"),
    ),
    "WriteOwner": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Object owner change — modifies security descriptor",
        detection_sources=("4670 - Permissions Changed",),
        mitigations=("Restore original owner after exploitation",),
        windows_events=("4670",),
    ),
    "Owns": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Object ownership exploitation",
        detection_sources=("5136 - DS Modified",),
        windows_events=("5136",),
    ),
    "AllExtendedRights": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Extended rights exploitation (password reset, LAPS read)",
        detection_sources=("4662 - DS Access", "4723/4724 - Password Change"),
        windows_events=("4662", "4723", "4724"),
    ),
    "ForceChangePassword": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Password reset — generates authentication events",
        detection_sources=("4724 - Password Reset Attempt", "4723 - Password Change"),
        mitigations=("Change password back after obtaining access",),
        windows_events=("4723", "4724"),
    ),
    "AddMembers": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Group membership modification",
        detection_sources=("4728/4732/4756 - Member Added to Group",),
        mitigations=("Remove from group after exploitation to reduce exposure window",),
        windows_events=("4728", "4732", "4756"),
    ),
    "AddSelf": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Self-enrollment into group",
        detection_sources=("4728/4732/4756 - Member Added to Group",),
        windows_events=("4728", "4732", "4756"),
    ),
    "WriteAccountRestrictions": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="RBCD configuration — modifies msDS-AllowedToActOnBehalfOfOtherIdentity",
        detection_sources=("5136 - DS Modified", "4624 - Logon with S4U"),
        mitigations=("Remove RBCD delegation after obtaining ticket",),
        windows_events=("5136", "4624"),
    ),
    "AllowedToAct": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="RBCD exploitation via existing delegation",
        detection_sources=("4624 - Logon (S4U2Proxy)", "Kerberos TGS logs"),
        windows_events=("4624", "4769"),
    ),
    "AllowedToDelegate": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Constrained delegation exploitation",
        detection_sources=("4624 - Logon (S4U2Proxy)", "4769 - TGS Request"),
        windows_events=("4624", "4769"),
    ),
    "AddAllowedToAct": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Configure RBCD on target — modifies delegation attribute",
        detection_sources=("5136 - DS Modified",),
        windows_events=("5136",),
    ),
    "WriteSPN": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="SPN modification for targeted Kerberoasting",
        detection_sources=("5136 - DS Modified", "4769 - TGS Request"),
        mitigations=("Remove SPN after obtaining TGS hash",),
        windows_events=("5136", "4769"),
    ),
    "AddKeyCredentialLink": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="Shadow Credentials — adds msDS-KeyCredentialLink",
        detection_sources=("5136 - DS Modified", "4768 - TGT via PKINIT"),
        mitigations=("Remove shadow credential after exploitation",),
        windows_events=("5136", "4768"),
    ),
    "GPLink": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="GPO modification — changes applied at next GP refresh",
        detection_sources=("5136 - DS Modified", "4670 - Permissions Changed", "GPO audit logs"),
        mitigations=("Revert GPO changes immediately after exploitation",),
        windows_events=("5136", "4670"),
    ),
    "GpLink": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="GPO modification — changes applied at next GP refresh",
        detection_sources=("5136 - DS Modified", "GPO audit logs"),
        windows_events=("5136",),
    ),
    "SQLAdmin": OpsecProfile(
        risk_level=RiskLevel.MEDIUM,
        description="MSSQL sysadmin exploitation — enables xp_cmdshell",
        detection_sources=("SQL Server audit logs", "xp_cmdshell detection", "EDR"),
        mitigations=("Disable xp_cmdshell after execution",),
    ),

    # ---- HIGH RISK: Active exploitation with distinctive signatures ----
    "DCSync": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Domain replication request — mimics DC behavior",
        detection_sources=(
            "4662 - DS Access (replication)",
            "Directory Service Replication monitoring",
            "MDI/ATA alerts",
            "Honeypot detection",
        ),
        mitigations=(
            "Target specific accounts with -just-dc-user to minimize replication volume",
            "Execute during DC replication windows",
        ),
        windows_events=("4662",),
    ),
    "GetChanges": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Replication rights (partial DCSync capability)",
        detection_sources=("4662 - DS Replication Access", "MDI alerts"),
        windows_events=("4662",),
    ),
    "GetChangesAll": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Full replication rights (complete DCSync capability)",
        detection_sources=("4662 - DS Replication Access", "MDI alerts"),
        windows_events=("4662",),
    ),
    "AdminTo": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Local admin exploitation — lateral movement via SMB/WMI/DCOM",
        detection_sources=("4624 - Network Logon", "4672 - Special Privileges", "EDR", "Sysmon"),
        mitigations=("Use WMI or DCOM over PsExec for reduced AV detection",),
        windows_events=("4624", "4672"),
    ),
    "CanRDP": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="RDP access — interactive logon generates extensive logging",
        detection_sources=("4624 Type 10 - RemoteInteractive", "RDP connection logs", "NLA logs"),
        windows_events=("4624", "4778", "4779"),
    ),
    "CanPSRemote": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="PowerShell Remoting — WinRM creates detailed transcription logs",
        detection_sources=("4624 - Network Logon", "PowerShell ScriptBlock logging", "WinRM logs"),
        mitigations=("Disable ScriptBlock logging if possible before execution",),
        windows_events=("4624", "4104"),
    ),
    "ExecuteDCOM": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="DCOM execution — COM object instantiation on remote host",
        detection_sources=("4624 - Network Logon", "DCOM event logs", "EDR"),
        windows_events=("4624",),
    ),
    "CoerceAndRelayTo": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Authentication coercion + NTLM relay — generates forced auth events",
        detection_sources=("Honeypot listeners", "NTLM relay detection", "MDI", "Network IDS"),
        mitigations=("Use encrypted channel for relay to avoid network IDS",),
    ),
    "TrustedBy": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Cross-domain trust exploitation — inter-realm TGT forging",
        detection_sources=("4769 - TGS Request (cross-realm)", "Trust monitoring", "MDI"),
        windows_events=("4769",),
    ),

    # ADCS HIGH
    "ADCSESC1": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Certificate template with enrollee-supplied SAN",
        detection_sources=("4886/4887 - Certificate Request/Issue", "CA audit logs"),
        windows_events=("4886", "4887"),
    ),
    "ADCSESC2": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="SubCA certificate abuse for arbitrary certificate issuance",
        detection_sources=("4886/4887 - Certificate Request/Issue", "CA audit logs"),
        windows_events=("4886", "4887"),
    ),
    "ADCSESC3": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Enrollment agent certificate abuse",
        detection_sources=("4886/4887 - Certificate Events", "CA audit logs"),
        windows_events=("4886", "4887"),
    ),
    "ADCSESC4": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Certificate template ACL modification",
        detection_sources=("5136 - DS Modified", "CA audit logs"),
        windows_events=("5136", "4886", "4887"),
    ),
    "ADCSESC5": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="HTTP enrollment endpoint abuse",
        detection_sources=("IIS/HTTP logs", "CA audit logs"),
    ),
    "ADCSESC6": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="EDITF_ATTRIBUTESUBJECTALTNAME2 flag abuse",
        detection_sources=("4886/4887 - Certificate Events", "CA config audit"),
        windows_events=("4886", "4887"),
    ),
    "ADCSESC7": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="CA Officer approval abuse — manage certificates permission",
        detection_sources=("CA audit logs", "4886/4887 - Certificate Events"),
        windows_events=("4886", "4887"),
    ),
    "ADCSESC8": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="NTLM relay to HTTP enrollment endpoint",
        detection_sources=("IIS logs", "NTLM relay detection", "Network IDS"),
    ),
    "ADCSESC9": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="CT_FLAG_NO_SECURITY_EXTENSION template abuse",
        detection_sources=("CA audit logs", "Certificate enrollment logs"),
        windows_events=("4886", "4887"),
    ),
    "ADCSESC10": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="Certificate mapping bypass via weak mapping",
        detection_sources=("CA audit logs", "Certificate mapping logs"),
        windows_events=("4886", "4887"),
    ),
    "ADCSESC11": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="RPC enrollment endpoint relay",
        detection_sources=("RPC audit logs", "NTLM relay detection"),
    ),
    "ADCSESC13": OpsecProfile(
        risk_level=RiskLevel.HIGH,
        description="OID group link abuse for privilege escalation",
        detection_sources=("CA audit logs", "5136 - DS Modified"),
        windows_events=("4886", "4887", "5136"),
    ),

    # ---- CRITICAL RISK: Domain-wide impact ----
    "DiamondTicket": OpsecProfile(
        risk_level=RiskLevel.CRITICAL,
        description="PAC-modified legitimate TGT — harder to detect than Golden Ticket but still domain-impacting",
        detection_sources=(
            "4768 - TGT Request (anomalous PAC)",
            "MDI/ATA behavioral analysis",
            "krbtgt usage anomalies",
        ),
        mitigations=(
            "Use AES256 encryption to match legitimate ticket profile",
            "Limit group SIDs to minimum required",
        ),
        windows_events=("4768", "4769"),
    ),
    "SapphireTicket": OpsecProfile(
        risk_level=RiskLevel.CRITICAL,
        description="S4U2Self PAC extraction + re-encryption — advanced ticket forging",
        detection_sources=(
            "4769 - TGS Request (S4U2Self)",
            "MDI behavioral analysis",
            "Anomalous Kerberos patterns",
        ),
        mitigations=("Target specific services to minimize S4U2Self footprint",),
        windows_events=("4768", "4769"),
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_opsec_profile(edge_type: str) -> OpsecProfile:
    """Look up the OPSEC profile for a given edge type.

    Args:
        edge_type: BloodHound edge type string.

    Returns:
        The matching OpsecProfile, or a default MEDIUM profile if the
        edge type is not in the mapping.
    """
    return EDGE_OPSEC_MAP.get(
        edge_type,
        OpsecProfile(
            risk_level=RiskLevel.MEDIUM,
            description=f"No specific OPSEC profile for '{edge_type}'",
        ),
    )


def check_opsec(
    edge_type: str,
    stealth_mode: bool = False,
    max_risk: RiskLevel = RiskLevel.CRITICAL,
) -> tuple[OpsecProfile, bool]:
    """Check whether an edge type is safe to exploit given OPSEC constraints.

    Args:
        edge_type: BloodHound edge type string.
        stealth_mode: If True, block HIGH and CRITICAL operations.
        max_risk: Maximum acceptable risk level.

    Returns:
        Tuple of (profile, should_proceed). ``should_proceed`` is False if
        the edge's risk exceeds the allowed threshold.
    """
    profile = get_opsec_profile(edge_type)

    risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    profile_idx = risk_order.index(profile.risk_level)
    max_idx = risk_order.index(max_risk)

    if stealth_mode and profile_idx >= risk_order.index(RiskLevel.HIGH):
        return profile, False

    if profile_idx > max_idx:
        return profile, False

    return profile, True


def format_opsec_warning(profile: OpsecProfile, edge_type: str = "") -> str:
    """Format an OPSEC warning as a Rich-compatible string.

    Args:
        profile: The OpsecProfile to format.
        edge_type: Optional edge type name for the header.

    Returns:
        Rich markup string suitable for console.print().
    """
    risk_colors = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold red",
    }
    color = risk_colors.get(profile.risk_level, "white")

    lines = [f"[{color}]⚠ OPSEC Risk: {profile.risk_level.value}[/{color}]"]

    if profile.description:
        lines.append(f"  {profile.description}")

    if profile.detection_sources:
        lines.append("  [bold]Detection sources:[/]")
        for src in profile.detection_sources:
            lines.append(f"    • {src}")

    if profile.windows_events:
        lines.append(f"  [bold]Event IDs:[/] {', '.join(profile.windows_events)}")

    if profile.mitigations:
        lines.append("  [bold]Mitigations:[/]")
        for mit in profile.mitigations:
            lines.append(f"    → {mit}")

    return "\n".join(lines)


def display_opsec_warning(profile: OpsecProfile, edge_type: str = "") -> None:
    """Print an OPSEC warning panel to the console.

    Args:
        profile: The OpsecProfile to display.
        edge_type: Optional edge type name for the panel title.
    """
    risk_colors = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "red",
    }
    color = risk_colors.get(profile.risk_level, "white")
    title = f"OPSEC: {edge_type}" if edge_type else "OPSEC Warning"

    content = format_opsec_warning(profile, edge_type)
    console.print(Panel(content, title=title, border_style=color))

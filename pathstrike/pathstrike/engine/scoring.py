"""Privilege-tier scoring for AD targets and attack paths.

Scores BloodHound nodes and attack paths by privilege value using
Microsoft's built-in AD security model:

- **Well-known SIDs**: Enterprise Admins, Domain Admins, etc.
- **AdminSDHolder protected groups**: adminCount attribute
- **BH CE Tier Zero**: isTierZero / system_tags
- **Edge weights**: feasibility cost per edge type
- **Custom groups**: scored by outbound edges and properties
"""

from __future__ import annotations

import math
from functools import reduce
from typing import Any

from pathstrike.models import AttackPath, NodeInfo

# ---------------------------------------------------------------------------
# Well-known SID suffix → (display_name, base_score)
# These are relative IDs (RIDs) appended to the domain SID.
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/
# ---------------------------------------------------------------------------

WELL_KNOWN_SIDS: dict[str, tuple[str, float]] = {
    # Tier 0 — Domain / Forest sovereignty
    "-519": ("Enterprise Admins", 100.0),
    "-512": ("Domain Admins", 95.0),
    "-518": ("Schema Admins", 95.0),
    "-516": ("Domain Controllers", 90.0),
    "-502": ("krbtgt", 100.0),
    "-500": ("Administrator", 93.0),
    "-521": ("Read-Only Domain Controllers", 50.0),
    "-498": ("Enterprise Read-Only DCs", 50.0),
    # Tier 1 — High privilege / indirect escalation
    "-549": ("Server Operators", 82.0),
    "-548": ("Account Operators", 80.0),
    "-551": ("Backup Operators", 85.0),
    "-550": ("Print Operators", 70.0),
    "-520": ("Group Policy Creator Owners", 75.0),
    "-517": ("Cert Publishers", 75.0),
    # Tier 2 — Medium privilege
    "-555": ("Remote Desktop Users", 45.0),
    "-580": ("Remote Management Users", 45.0),
    "-578": ("Hyper-V Administrators", 65.0),
    "-556": ("Network Configuration Operators", 50.0),
    # Tier 3 — Low privilege
    "-513": ("Domain Users", 15.0),
    "-515": ("Domain Computers", 10.0),
    "-514": ("Domain Guests", 2.0),
}

# Built-in local group SIDs (S-1-5-32-xxx)
BUILTIN_SIDS: dict[str, tuple[str, float]] = {
    "S-1-5-32-544": ("Administrators", 90.0),
    "S-1-5-32-549": ("Server Operators", 82.0),
    "S-1-5-32-548": ("Account Operators", 80.0),
    "S-1-5-32-551": ("Backup Operators", 85.0),
    "S-1-5-32-550": ("Print Operators", 70.0),
    "S-1-5-32-555": ("Remote Desktop Users", 45.0),
    "S-1-5-32-580": ("Remote Management Users", 45.0),
}

# Group name → base score (fallback when SID not available)
KNOWN_GROUP_NAMES: dict[str, float] = {
    "ENTERPRISE ADMINS": 100.0,
    "DOMAIN ADMINS": 95.0,
    "SCHEMA ADMINS": 95.0,
    "ADMINISTRATORS": 90.0,
    "DOMAIN CONTROLLERS": 90.0,
    "BACKUP OPERATORS": 85.0,
    "SERVER OPERATORS": 82.0,
    "DNSADMINS": 82.0,
    "ACCOUNT OPERATORS": 80.0,
    "PRINT OPERATORS": 70.0,
    "GROUP POLICY CREATOR OWNERS": 75.0,
    "CERT PUBLISHERS": 75.0,
    "KEY ADMINS": 80.0,
    "ENTERPRISE KEY ADMINS": 85.0,
    "REMOTE DESKTOP USERS": 45.0,
    "REMOTE MANAGEMENT USERS": 45.0,
    "HYPER-V ADMINISTRATORS": 65.0,
}

# AdminSDHolder protected groups — membership implies high privilege
ADMINSDHOLDER_PROTECTED: set[str] = {
    "ENTERPRISE ADMINS", "DOMAIN ADMINS", "SCHEMA ADMINS",
    "ADMINISTRATORS", "ACCOUNT OPERATORS", "SERVER OPERATORS",
    "BACKUP OPERATORS", "PRINT OPERATORS", "DOMAIN CONTROLLERS",
    "READ-ONLY DOMAIN CONTROLLERS", "REPLICATOR",
}

# Edge type → feasibility weight (0-1, higher = easier/more reliable)
EDGE_WEIGHTS: dict[str, float] = {
    # Tier 0 edges — near-guaranteed
    "DCSync": 0.98,
    "GetChanges": 0.97,
    "GetChangesAll": 0.97,
    "GetChangesInFilteredSet": 0.95,
    "MemberOf": 1.0,  # free traversal
    "Contains": 1.0,
    "GPLink": 1.0,
    # Tier 1 — very reliable
    "GenericAll": 0.95,
    "Owns": 0.93,
    "OwnsRaw": 0.93,
    "WriteDacl": 0.93,
    "WriteOwner": 0.92,
    "WriteOwnerRaw": 0.92,
    "HasSIDHistory": 0.95,
    "AddMembers": 0.92,
    "AddSelf": 0.92,
    # Tier 2 — reliable with caveats
    "AllExtendedRights": 0.90,
    "GenericWrite": 0.88,
    "AddKeyCredentialLink": 0.85,
    "ReadLAPSPassword": 0.85,
    "ReadGMSAPassword": 0.85,
    "DumpSMSAPassword": 0.85,
    "SyncLAPSPassword": 0.85,
    "ForceChangePassword": 0.80,
    "AllowedToDelegate": 0.80,
    "AllowedToAct": 0.80,
    "WriteAccountRestrictions": 0.80,
    "AdminTo": 0.85,
    "CanPSRemote": 0.80,
    "CanRDP": 0.75,
    "ExecuteDCOM": 0.78,
    "WriteSPN": 0.50,  # requires offline cracking
    # Tier 3 — harder / less reliable
    "SQLAdmin": 0.70,
    "SameForestTrust": 0.70,
    "TrustedBy": 0.65,
    "ExternalTrust": 0.55,
    "TrustedForestTrust": 0.55,
    "CoerceAndRelayTo": 0.60,
    "CoerceAndRelayNTLMToSMB": 0.60,
    "CoerceToTGT": 0.60,
    # ADCS — depends on config but generally reliable
    "ADCSESC1": 0.85,
    "ADCSESC2": 0.80,
    "ADCSESC3": 0.75,
    "ADCSESC4": 0.80,
    "ADCSESC5": 0.75,
    "ADCSESC6": 0.70,
    "ADCSESC7": 0.65,
    "ADCSESC8": 0.65,
    "ADCSESC9": 0.75,
    "ADCSESC10": 0.75,
    "ADCSESC11": 0.70,
    "ADCSESC13": 0.75,
}

# Default weight for unknown edge types
DEFAULT_EDGE_WEIGHT: float = 0.50


# ---------------------------------------------------------------------------
# Node scoring
# ---------------------------------------------------------------------------


def score_target_node(node: NodeInfo) -> float:
    """Score a BloodHound node by its privilege value (0-100).

    Checks well-known SIDs, group names, BH CE properties, and node
    type to assign a privilege score.
    """
    score = 0.0

    # 1. Check SID suffix against well-known table
    oid = node.object_id or ""
    if oid.startswith("S-1-5-"):
        # Check built-in SIDs first
        if oid in BUILTIN_SIDS:
            return BUILTIN_SIDS[oid][1]
        # Check domain-relative RID suffix
        for suffix, (_, base_score) in WELL_KNOWN_SIDS.items():
            if oid.endswith(suffix):
                return base_score

    # 2. Check group name
    name_key = node.name.split("@")[0].upper() if "@" in node.name else node.name.upper()
    if name_key in KNOWN_GROUP_NAMES:
        score = max(score, KNOWN_GROUP_NAMES[name_key])

    # 3. Check BH CE properties
    props = node.properties or {}
    if props.get("isTierZero") is True:
        score = max(score, 85.0)
    if props.get("admincount") is True:
        score = max(score, 75.0)

    # 4. Node type heuristics
    label = node.label.lower() if node.label else ""
    if label == "domain":
        score = max(score, 98.0)
    elif label == "computer":
        # DCs are very high value
        if props.get("unconstraineddelegation") is True:
            score = max(score, 70.0)
        if "domain controller" in str(props).lower():
            score = max(score, 92.0)
    elif label in ("enterpriseca", "rootca", "aiaca"):
        score = max(score, 92.0)
    elif label == "gpo":
        # GPOs linked to high-value OUs are valuable
        score = max(score, 60.0)
    elif label == "user":
        # Individual users — check for service accounts, admins
        if props.get("admincount") is True:
            score = max(score, 75.0)
        elif props.get("hasspn") is True:
            score = max(score, 30.0)  # Kerberoastable
        else:
            score = max(score, 20.0)
    elif label == "group" and score == 0:
        # Unknown group — base score
        score = 40.0

    return score


# ---------------------------------------------------------------------------
# Path scoring
# ---------------------------------------------------------------------------


def compute_feasibility(path: AttackPath) -> float:
    """Compute path feasibility as the product of edge weights.

    Returns a value in [0, 1] where 1 means trivially easy and
    values near 0 mean many hard steps.
    """
    if not path.steps:
        return 0.0
    weights = [
        EDGE_WEIGHTS.get(step.edge.edge_type, DEFAULT_EDGE_WEIGHT)
        for step in path.steps
    ]
    return reduce(lambda a, b: a * b, weights)


def score_path(path: AttackPath) -> "ScoredPath":
    """Score an attack path by target value and feasibility.

    Returns a ScoredPath with target_score, feasibility, and
    composite_score fields.
    """
    from pathstrike.models import ScoredPath

    target_score = score_target_node(path.target)
    feasibility = compute_feasibility(path)
    composite = target_score * feasibility

    domain = path.target.domain or ""

    return ScoredPath(
        path=path,
        target_score=target_score,
        feasibility=feasibility,
        composite_score=composite,
        domain=domain,
    )


def rank_paths(paths: list[AttackPath]) -> list["ScoredPath"]:
    """Score and rank a list of attack paths by composite score.

    Returns scored paths sorted by composite_score descending.
    Filters out paths with composite_score <= 0.
    """
    scored = [score_path(p) for p in paths]
    scored = [s for s in scored if s.composite_score > 0]
    scored.sort(key=lambda s: s.composite_score, reverse=True)
    return scored


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def describe_score(score: float) -> str:
    """Human-readable label for a privilege score."""
    if score >= 95:
        return "CRITICAL"
    elif score >= 85:
        return "VERY HIGH"
    elif score >= 70:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    elif score >= 30:
        return "LOW"
    return "MINIMAL"

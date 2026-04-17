"""Edge exploitation handlers for supported BloodHound relationship types.

Importing this package triggers all ``@register_handler`` decorators,
populating the global edge registry with handler classes for every
supported BloodHound edge type.

Supported edge categories:

* **ACL** -- GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, AllExtendedRights
* **Password** -- ForceChangePassword
* **Group** -- MemberOf, AddMembers, AddSelf
* **Delegation** -- AllowedToDelegate, AllowedToAct, WriteAccountRestrictions
* **Replication** -- GetChanges, GetChangesAll, DCSync
* **Credential** -- ReadLAPSPassword, ReadGMSAPassword
* **Access** -- AdminTo, HasSession
* **SID History** -- SID history injection / abuse
* **Trust** -- Domain and forest trust exploitation
* **SQL** -- SQL Server linked-server and xp_cmdshell abuse
* **GPO** -- Group Policy Object manipulation
* **Container** -- OU / Container object exploitation
* **Ticket Forging** -- Golden / Silver ticket forging
* **Coercion** -- Authentication coercion and relay (PetitPotam, PrinterBug, DFSCoerce)

Note: ``kerberos.py`` is a utility module for Kerberoasting/AS-REP CLI commands,
not an edge handler — it is imported by ``cli.py`` directly.
"""

from pathstrike.handlers import (  # noqa: F401 — imported for side-effect registration
    access,
    acl,
    adcs,
    coercion,
    container,
    credential,
    delegation,
    extended_access,
    gpo,
    group,
    password,
    recycle_bin,
    replication,
    shadow_creds,
    sid_history,
    sql,
    ticket_forging,
    trust,
)

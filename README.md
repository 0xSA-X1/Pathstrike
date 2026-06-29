<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-dark.svg" alt="Pathstrike" width="96">
  </picture>
</p>

# PathStrike

**Automated Active Directory and Azure/Entra ID attack path exploitation via BloodHound CE.**

PathStrike discovers and executes privilege escalation paths identified by BloodHound Community Edition, covering both on-premises Active Directory and Azure/Entra ID hybrid environments. Point it at a compromised identity and it will find reachable exploitable targets — or the shortest path to Domain Admin or Global Administrator — then exploit each edge automatically using a variety of tools. It re-queries BloodHound and re-enumerates live after each successful step, so newly created edges are picked up on the fly.

---

## Features

- **Path Discovery** — queries BloodHound CE's Cypher API for attack paths + merges with live-discovered edges
- **Azure / Entra ID Support** — full coverage of Azure BloodHound edge types: app secret injection, role assignment, group membership, app role grants, and more — authenticated via SP client-credentials (roadtx) or delegated user tokens
- **Live Post-Compromise Enumeration** — after each successful step, re-enumerates AD to surface writeables, ADCS ESC findings, and tombstoned privileged accounts that BH doesn't see
- **Automated Exploitation** — 101 BloodHound edge types handled across on-prem AD and Azure/Entra ID
- **Command Emission (`learn`)** — print the exact tool commands PathStrike would run for any edge or path — an offline template, or fully resolved with real values/secrets — for manual operation and training; executes nothing
- **Campaign Mode** — interactive step-through exploration across all reachable targets
- **Auto Mode** — greedy opportunistic escalation from source toward any reachable exploitable node
- **Cross-Domain Escalation** — detects and exploits domain trust relationships (child-to-parent, forest trusts)
- **Three Execution Modes** — `interactive` (step-by-step), `auto` (fully automated), `dry_run` (read-only simulation)
- **Tool Fallbacks** — handlers fall back to **netexec** when their primary tool (Impacket/bloodyAD/Certipy) is missing or fails — covering delegation (S4U), DCSync, gMSA/LAPS, MSSQL/DCOM execution, RBCD computer-staging, and Kerberoasting. The primary path is unchanged; the fallback only runs on failure
- **Credential Chaining** — captured creds (NT hashes, Kerberos tickets, Azure SP secrets) feed into subsequent attack steps automatically
- **Rollback Support** — logs every AD/Azure modification and can reverse changes post-engagement
- **Checkpoint & Resume** — serialize attack state to disk and resume after interruption
- **Kerberos Time Sync** — auto-detects clock skew against the DC; syncs system clock via `ntpdate/chronyd/net time/rdate`, and falls back to wrapping subprocesses with **libfaketime** when system sync fails (e.g. no sudo)
- **Clean Console + Session Logs** — default output is terse; every run writes a full DEBUG log to `~/.pathstrike/logs/session_<timestamp>.log`
- **Reporting** — JSON and HTML attack reports with full step-by-step details

---

## Supported Edge Types

### Active Directory (on-premises)

| Category | Edges |
|---|---|
| **ACL Abuse** | `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights` |
| **Credential Access** | `ReadLAPSPassword`, `ReadGMSAPassword`, `DumpSMSAPassword`, `SyncLAPSPassword`, `ForceChangePassword` |
| **Kerberos Delegation** | `AllowedToDelegate`, `AllowedToAct`, `AddAllowedToAct`, `WriteAccountRestrictions` |
| **Kerberos Tickets** | `DiamondTicket`, `SapphireTicket` |
| **AD CS (Certificates)** | `ADCSESC1`–`ADCSESC13`, `GoldenCert`, `ManageCA`, `ManageCertificates` |
| **Replication** | `GetChanges`, `GetChangesAll`, `GetChangesInFilteredSet`, `DCSync` |
| **Coercion & Relay** | `CoerceAndRelayTo`, `CoerceAndRelayNTLMToSMB/LDAP/LDAPS/ADCS`, `CoerceToTGT` |
| **Remote Execution** | `AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, `SQLAdmin` |
| **Group Membership** | `MemberOf`, `AddMembers`, `AddSelf` |
| **Shadow Credentials** | `AddKeyCredentialLink` |
| **SID History** | `HasSIDHistory`, `SpoofSIDHistory` |
| **Group Policy** | `GPLink`, `WriteGPLink` |
| **Domain Trusts** | `TrustedBy`, `SameForestTrust`, `ExternalTrust`, `CrossForestTrust`, `TrustedForestTrust`, `AbuseTGTDelegation`, `HasTrustKeys` |
| **Extended Access** | `WriteSPN`, `HasSession` |
| **Containment** | `Contains`, `ClaimSpecialIdentity` |
| **Live-Enum Synthetic** | `RestorableFrom` (discovered by PathStrike's live LDAP scan of `CN=Deleted Objects` — reanimates tombstoned privileged accounts) |

### Azure / Entra ID

| Category | Edges |
|---|---|
| **App Secret & Credential** | `AZAddSecret`, `AZMGAddSecret`, `AZResetPassword` |
| **Role Assignment** | `AZMGGrantRole`, `AZPrivilegedRoleAdmin`, `AZPrivilegedAuthAdmin` |
| **Group & Object Ownership** | `AZAddMembers`, `AZAddMember`, `AZMGAddMember`, `AZAddOwner`, `AZOwns`, `AZMGAddOwner` |
| **App Role Grants** | `AZMGGrantAppRoles` |
| **MG Permission Edges** | `AZMGRoleManagement_ReadWrite_Directory`, `AZMGApplication_ReadWrite_All`, `AZMGAppRoleAssignment_ReadWrite_All`, `AZMGDirectory_ReadWrite_All`, `AZMGGroupMember_ReadWrite_All` |
| **Traversal** | `AZContains`, `AZMemberOf`, `AZRunsAs`, `AZGlobalAdmin`, `AZHasRole`, `AZAuthenticatesTo` |

---

## Validation Status

All listed handlers are implemented. The table below summarises what has been verified end-to-end in a live lab. The authoritative per-edge matrix lives in [docs/EDGE_STATUS.md](docs/EDGE_STATUS.md).

### Active Directory — ✅ Validated live

- **ACL:** `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` (+`WriteOwnerRaw`), `Owns` (+`OwnsRaw`), `AllExtendedRights`
- **Replication:** `DCSync`, `GetChanges`, `GetChangesAll`, `GetChangesInFilteredSet`
- **Credential access:** `ReadLAPSPassword`, `ReadGMSAPassword`, `SyncLAPSPassword`, `ForceChangePassword`
- **Group:** `AddMembers`/`AddMember`, `AddSelf`, `MemberOf`
- **Delegation / RBCD:** `AllowedToDelegate` (both with protocol transition and without — via the staged-computer RBCD bridge), `AddAllowedToAct`, `WriteAccountRestrictions`
- **Shadow credentials:** `AddKeyCredentialLink`
- **SID history:** `HasSIDHistory`, `SpoofSIDHistory`
- **Group Policy:** `GPLink`, `WriteGPLink`
- **Domain trusts:** `SameForestTrust`, `CrossForestTrust`
- **AD CS:** `ADCSESC1`, `ADCSESC3`, `ADCSESC4` (modify → exploit → restore), `ADCSESC6`/`ESC6a`, `ADCSESC9`/`ESC9a`, `GoldenCert`, `ManageCA` (covers ESC7), `ManageCertificates`
- **Traversal:** `Contains`, `ClaimSpecialIdentity`

### Azure / Entra ID — ✅ Validated live

Validated against a test tenant (AzureHound CE ingest + live Graph API calls):

- **`AZAddSecret`** — inject a secret into an app registration via delegated Application Administrator rights; rollback via `removePassword` ✅
- **`AZMGGrantRole`** — assign an Entra ID directory role to a principal using a SP with `RoleManagement.ReadWrite.Directory`; rollback via `roleAssignments` DELETE ✅
- **`AZMGAddSecret`** — add a secret to a target app/SP using a SP with `Application.ReadWrite.All`; handles SP objectId→appId resolution automatically ✅
- **`AZMGAddMember`** — add a principal to an Entra group using a SP with `Directory.ReadWrite.All`; rollback requires `Group.ReadWrite.All` or `GroupMember.ReadWrite.All` ✅
- **`AZMGGrantAppRoles`** — grant MS Graph application permissions to a SP via `AppRoleAssignment.ReadWrite.All`; technique confirmed working (Global Admin delegation path); handler falls back to user-token for MS Graph SP objectId resolution when SP token lacks read scope ✅

**⬜ Implemented, dry-run validated:** `AZResetPassword`, `AZAddMembers`, `AZAddMember`, `AZAddOwner`, `AZOwns`, `AZMGAddOwner`, `AZPrivilegedRoleAdmin`, `AZPrivilegedAuthAdmin`; traversal stubs for `AZContains`, `AZMemberOf`, `AZRunsAs`, `AZGlobalAdmin`, `AZHasRole`, `AZAuthenticatesTo`; MG permission edges

### 🚫 Environment-gated

- **`CoerceToTGT`** — coercion fires (the DC calls back), but SMB→LDAP relay never completes against a hardened DC (MIC enforced / CVE-2019-1040 mitigated). Not a code bug.
- **`ADCSESC8`** — NTLM relay to AD CS HTTP web enrollment; requires the web-enrollment endpoint to be up and reachable.

### ⬜ Implemented, not yet validated live

`AllowedToAct`, `DumpSMSAPassword`, `AdminTo`, `HasSession`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, `SQLAdmin`, `WriteSPN`, `RestorableFrom`, `DiamondTicket`, `SapphireTicket`, the `CoerceAndRelayNTLMTo*` family, `TrustedBy`/`ExternalTrust`/`AbuseTGTDelegation`/`HasTrustKeys`, and `ADCSESC2`/`ESC5`/`ESC10`/`ESC11`/`ESC13`

---

## Live Enumeration (supplements BH CE data)

BloodHound CE is a **static snapshot** taken at SharpHound ingest time. PathStrike runs three post-compromise enumerators each time a new identity is owned, contributing synthetic edges to an in-memory capability graph consulted alongside BH during the next discovery round:

| Source | Covers | When it runs |
|---|---|---|
| **`bloodyAD get writable`** | Standard ACE writes (`GenericWrite`, `Owns`, `WriteOwner`, `WriteDacl`) | After every successful compromise, per newly-owned user/computer |
| **`certipy find -vulnerable`** | AD CS templates with ESC1/3/4/6/9/10/11/13 findings | After every successful compromise, per newly-owned user/computer |
| **`ldap3` Recycle Bin scan** | Tombstoned privileged accounts in `CN=Deleted Objects` (surfaced as synthetic `RestorableFrom` edges) | After every successful compromise, per newly-owned identity |

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/0xSA-X1/Pathstrike.git
cd Pathstrike
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Install attack tools (venv)
pip install bloodyAD impacket
pip install git+https://github.com/Pennyw0rth/NetExec.git

# Tools for the GPO and coercion edges
pip install coercer
pip install git+https://github.com/Hackndo/pyGPOAbuse.git

# Install Certipy in an isolated env (avoids cryptography pin conflict with bloodyAD)
pipx install certipy-ad

# libfaketime — KDC clock-skew fallback (no-sudo mode)
sudo apt install faketime

# ROADtools / roadtx — required for Azure/Entra ID edges
pip install roadtx   # or: pip install roadlib roadtx in a separate venv

# Configure
cp pathstrike.yaml.example pathstrike.yaml
# Edit with your BloodHound CE API keys + domain/credentials

# Verify tools + BH CE connectivity + time offset
pathstrike verify

# Interactive step-through campaign
pathstrike campaign

# Greedy opportunistic escalation
pathstrike auto
```

---

## CLI Commands

| Command | Description |
|---|---|
| `pathstrike auto` | **Greedy reachable-targets exploitation** — escalate as far as possible from the source, chasing the deepest reachable exploitable node. Re-queries BH + live-enum after each successful step. |
| `pathstrike campaign` | **Interactive step-through campaign** — enumerates every reachable exploitable node, prompts you to pick one per round, exploits it, re-queries. Use `--high-value-only` to restrict to Domain Admins / Tier Zero. |
| `pathstrike learn` | **Print the commands PathStrike would run** to exploit an edge or path, instead of executing. Offline template by default; fully resolved with `--config`/`--creds-file`. `--redact` hides secrets. |
| `pathstrike edges` | List all supported BloodHound edge types and their registered handlers |
| `pathstrike verify` | Validate config, check that all tools are on PATH, test BH CE connectivity |
| `pathstrike domains` | List all AD domains discovered by BloodHound CE |
| `pathstrike trusts` | Enumerate domain trust relationships from BloodHound CE |
| `pathstrike adcs` | Discover AD CS Certificate Authorities and vulnerable templates via Certipy |
| `pathstrike kerberoast` | Targeted Kerberoasting attack |
| `pathstrike asreproast` | AS-REP roasting attack |
| `pathstrike credentials` | Interactively update the credentials in the config file |
| `pathstrike timesync` | Check or sync Kerberos clock offset against the DC |
| `pathstrike rollback` | Reverse AD/Azure changes from a previous attack (reads rollback log JSON) |
| `pathstrike checkpoints` | List saved attack-path checkpoints |

### Edge validation & testing

| Command | Description |
|---|---|
| `pathstrike test-edge` | Exercise a **single** edge handler against the live environment — safe dry-run by default, `--live` to exploit. |
| `pathstrike test-edges` | Run a **batch** of edge tests from a plan file, log structured results, and update the coverage matrix. |
| `pathstrike gen-test-plan` | Scaffold a `test-edges` plan seeded from the edge registry (optionally filtered by `--category`). |
| `pathstrike discover-edges` | Build a test plan by enumerating the edges actually **exploitable** from the credentials you hold. |
| `pathstrike validate-paths` | Validate escalation **chains** end-to-end. |

---

## Configuration

PathStrike uses a YAML config file. It searches these locations in order:

1. `./pathstrike.yaml`
2. `./pathstrike.yml`
3. `./.pathstrike.yaml`
4. `~/.config/pathstrike/config.yaml`
5. `~/.pathstrike.yaml`

### On-premises AD

```yaml
bloodhound:
  base_url: "http://localhost:8080"
  token_id: "your-api-token-id"
  token_key: "your-api-token-key"

domain:
  name: "corp.local"
  dc_host: "10.10.10.10"
  dc_fqdn: "dc01.corp.local"

credentials:
  username: "johnsmith"
  password: "Winter2020!"
  # Or: nt_hash / ccache_path

target:
  group: "DOMAIN ADMINS"

execution:
  mode: "interactive"       # interactive | auto | dry_run
  timeout: 30
  max_paths: 5
  auto_time_sync: true
```

### Azure / Entra ID (additional section)

```yaml
azure:
  tenant_id: "60961cc5-..."
  tenant_domain: "corp.onmicrosoft.com"
  username: "attacker@corp.onmicrosoft.com"
  password: "..."
  auth_mode: "ropc"         # ropc (username/password) | refresh (cached token — MFA-compatible)
  roadtx_path: "/path/to/.venv/bin/roadtx"
```

`auth_mode: refresh` is required when the tenant enforces MFA or Conditional Access. Seed the token cache once with `roadtx gettokens --device-code`, then PathStrike redeems the refresh token on each run without prompting.

---

## Requirements

- **Python 3.11+**
- **BloodHound Community Edition v9.0.1 or newer** — earlier builds (e.g. `bloodhound 8.7.0~rc3` shipped by the Kali apt package) are missing or differently gate the `/api/v2/graphs/cypher` endpoint PathStrike depends on. Install the latest via Docker Compose from https://ghst.ly/getbhce.
- **Linux attacker box** (Kali, Parrot, Ubuntu, Debian)
- **External tools for AD edges**: bloodyAD, Impacket, Certipy (v5+, install via pipx), NetExec, Coercer, pyGPOAbuse, ntpdate, libfaketime. Coercer/pyGPOAbuse are only needed for the coercion and GPO edges respectively; the rest are core.
- **External tools for Azure edges**: roadtx / ROADtools (`pip install roadtx`). Requires Python 3.10+. A separate venv is recommended to avoid dependency conflicts.
- **AD CS edges require SharpHound collected with `-c All`** — the CertServices/CARegistry data that the ESC and CA-management handlers depend on is *not* gathered by `netexec --bloodhound` or `bloodhound-python`. Collect with SharpHound (`-c All`) for ADCS attack paths.
- **Azure edges require AzureHound** — run AzureHound and ingest the output into BloodHound CE to populate `AZ*` edges.

---

## Troubleshooting

- **`404 resource not found` from BH CE Cypher endpoint** — upgrade BH CE to v9.0.1+
- **`KDC_ERR_CLIENT_NOT_TRUSTED` during shadow-creds** — usually clock skew; PathStrike attempts `ntpdate` / `chronyd` / `net time` / `rdate`, then falls back to wrapping the subprocess with `faketime +Xs` if libfaketime is installed
- **Certipy `pkg_resources` ModuleNotFoundError on Python 3.13** — install Certipy via pipx: `pipx install certipy-ad`
- **No ADCS / ESCx edges in BloodHound** — re-collect with SharpHound `-c All`; `netexec --bloodhound` and `bloodhound-python` don't collect ADCS data
- **`CoerceToTGT` / SMB→LDAP relay never completes** — this is modern DC hardening (MIC enforced / CVE-2019-1040 mitigated), not a tool bug
- **Azure SP token auth fails immediately after `AZAddSecret`** — Azure AD has a ~35–40 second propagation delay before a newly created app secret can authenticate via client-credentials. PathStrike waits automatically; if you're driving manually, wait before calling `get_sp_token`
- **`AZMGGrantAppRoles` returns 403 with SP token** — some tenants enforce admin consent policies that prevent even `AppRoleAssignment.ReadWrite.All` SPs from granting permissions; a Global Administrator delegated token is required in those environments
- **Handler crashes buried in a Rich Live panel** — look at `~/.pathstrike/logs/session_<timestamp>.log` for full tracebacks

---

## Roadmap

### Engine Improvements

- [ ] **Extended-rights LDAP scanner** — enumerate `AddSelf` / `ForceChangePassword` / `ReadGMSAPassword` / `ReadLAPSPassword` / `DCSync` rights live, beyond what `bloodyAD get writable` surfaces
- [ ] **Parallel path execution** — run independent path branches concurrently
- [ ] **OPSEC profiles** — configurable noise levels (stealth vs speed) with tool selection preferences
- [ ] **Plugin system** — drop-in handler modules for custom/proprietary edge types
- [ ] **Real-time BloodHound sync** — push newly compromised nodes back into BloodHound CE for live graph updates
- [ ] **SOCKS proxy support** — route tool traffic through proxychains/SOCKS for pivoting
- [ ] **Multi-forest campaigns** — orchestrate attacks across multiple forests from a single config
- [ ] **Mythic Plugin** — access to the tool via Mythic

### Planned Integrations

- [ ] **GitHound** — Git credential discovery. Scan repositories and CI/CD pipelines for leaked secrets that can feed PathStrike's credential store.
- [ ] **VsphereHound** — VMware vSphere enumeration for BloodHound. Discover attack paths through virtualization infrastructure into AD.
- [ ] **KrbRelayUp** — Local privilege escalation via Kerberos relay. Chain with existing RBCD and shadow credential handlers for local-to-domain escalation paths.
- [ ] **Whisker** — Alternative shadow credential manipulation for `AddKeyCredentialLink` edges.
- [ ] **PKINITtools** — PKINIT-based authentication utilities to complement Certipy for certificate-to-TGT flows and UnPAC-the-hash.

---

## Disclaimer

PathStrike is intended for **authorized security testing and research only**. Only use this tool against systems you have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## Acknowledgments

PathStrike is built on top of incredible work by the offensive security community:

| Tool | Description | Link |
|---|---|---|
| **BloodHound CE** | Active Directory attack path mapping and analysis | [github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) |
| **Impacket** | Python classes for working with network protocols (DCSync, S4U, PSExec, and more) | [github.com/fortra/impacket](https://github.com/fortra/impacket) |
| **bloodyAD** | Active Directory privilege escalation framework | [github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) |
| **Certipy** | AD Certificate Services enumeration and exploitation | [github.com/ly4k/Certipy](https://github.com/ly4k/Certipy) |
| **NetExec** | Network execution and credential validation toolkit (successor to CrackMapExec) | [github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) |
| **ROADtools / roadtx** | Azure AD / Entra ID token acquisition, enumeration, and Graph API interaction | [github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) |
| **libfaketime** | LD_PRELOAD clock-offset wrapping used as Kerberos skew fallback | [github.com/wolfcw/libfaketime](https://github.com/wolfcw/libfaketime) |
| **ldap3** | Pure-Python LDAP library — powers PathStrike's live Recycle Bin + ACL enumeration | [github.com/cannatag/ldap3](https://github.com/cannatag/ldap3) |
| **dnspython** | DNS toolkit — resolves CA / member-server hosts via the DC's DNS for ADCS edges | [github.com/rthalley/dnspython](https://github.com/rthalley/dnspython) |
| **pyGPOAbuse** | Group Policy Object abuse for privilege escalation | [github.com/Hackndo/pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) |
| **Coercer** | Multi-method MS-RPC authentication coercion | [github.com/p0dalirius/Coercer](https://github.com/p0dalirius/Coercer) |
| **ntlmrelayx** | NTLM relay framework (part of Impacket) | [github.com/fortra/impacket](https://github.com/fortra/impacket) |

## License

MIT

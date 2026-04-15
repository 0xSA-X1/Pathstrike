# PathStrike

**Automated Active Directory attack path exploitation via BloodHound CE.**

PathStrike discovers and executes AD privilege escalation paths identified by BloodHound Community Edition using Bloodhound API. Point it at a compromised user, and it will find the shortest path to Domain Admin or highest privilege (if a path exists), then exploit each edge automatically using a variety of tools.

---

## Features

- **Path Discovery** -- queries BloodHound's API for attack paths via Cypher
- **Automated Exploitation** -- 50+ BloodHound edge types handled by dedicated attack modules
- **Campaign Mode** -- autonomous multi-target loop: discover, rank, exploit, re-discover
- **Cross-Domain Escalation** -- detects and exploits domain trust relationships (child-to-parent, forest trusts)
- **Three Execution Modes** -- `interactive` (step-by-step), `auto` (fully automated), `dry_run` (read-only simulation)
- **Credential Chaining** -- captured creds feed into subsequent attack steps automatically
- **Rollback Support** -- logs every AD modification and can reverse changes post-engagement
- **Checkpoint & Resume** -- serialize attack state to disk and resume after interruption
- **Kerberos Time Sync** -- auto-detects and fixes clock skew against the DC
- **Reporting** -- JSON and HTML attack reports with full step-by-step details

## Supported Edge Types

| Category | Edges |
|---|---|
| **ACL Abuse** | `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights` |
| **Credential Access** | `ReadLAPSPassword`, `ReadGMSAPassword`, `DumpSMSAPassword`, `ForceChangePassword` |
| **Kerberos Delegation** | `AllowedToDelegate`, `AllowedToAct`, `WriteAccountRestrictions` |
| **Kerberos Tickets** | `DiamondTicket`, `SapphireTicket` |
| **AD CS (Certificates)** | `ADCSESC1`-`ADCSESC13`, `GoldenCert`, `ManageCA`, `ManageCertificates` |
| **Replication** | `GetChanges`, `GetChangesAll`, `GetChangesInFilteredSet`, `DCSync` |
| **Coercion & Relay** | `CoerceAndRelayTo`, `CoerceAndRelayNTLMToSMB/LDAP/LDAPS/ADCS`, `CoerceToTGT` |
| **Remote Execution** | `AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, `SQLAdmin` |
| **Group Membership** | `MemberOf`, `AddMembers`, `AddSelf` |
| **Shadow Credentials** | `AddKeyCredentialLink` |
| **SID History** | `HasSIDHistory`, `SpoofSIDHistory` |
| **Group Policy** | `GPLink`, `WriteGPLink` |
| **Domain Trusts** | `TrustedBy`, `SameForestTrust`, `ExternalTrust`, `CrossForestTrust`, `AbuseTGTDelegation` |
| **Extended Access** | `AddAllowedToAct`, `WriteSPN`, `SyncLAPSPassword`, `HasSession` |
| **Containment** | `Contains`, `ClaimSpecialIdentity` |

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/0x-SA-X1/Pathstrike.git
cd Pathstrike
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Install attack tools
pip install bloodyAD impacket certipy-ad
pip install git+https://github.com/Pennyw0rth/NetExec.git

# Configure
cp pathstrike.yaml.example pathstrike.yaml
# Edit pathstrike.yaml with your BloodHound CE API keys [Optional: domain info, and credentials]

# Verify everything is ready
pathstrike verify

# Discover paths
pathstrike paths -s jsmith

# Exploit a path (interactive mode)
pathstrike attack -s jsmith

# Full auto
pathstrike attack -s jsmith -m auto

# Autonomous campaign
pathstrike campaign -s jsmith
```


---

## CLI Commands

| Command | Description |
|---|---|
| `pathstrike paths` | Discover shortest attack paths from source to target |
| `pathstrike attack` | Execute a discovered attack path |
| `pathstrike campaign` | Autonomous multi-target campaign (discover-rank-exploit loop) |
| `pathstrike auto` | Automatic discovery + execution in one step |
| `pathstrike edges` | List all supported BloodHound edge types |
| `pathstrike verify` | Validate config and check that all tools are on PATH |
| `pathstrike recon` | Detailed reconnaissance of a target node |
| `pathstrike domains` | Enumerate all AD domains from BloodHound |
| `pathstrike trusts` | Enumerate domain trust relationships |
| `pathstrike kerberoast` | Kerberoasting attack |
| `pathstrike asreproast` | AS-REP roasting attack |
| `pathstrike credentials` | Display captured credentials or Write new credentials to config file |
| `pathstrike timesync` | Check or sync Kerberos clock offset |
| `pathstrike rollback` | Reverse AD changes from a previous attack |
| `pathstrike checkpoints` | List and manage saved attack checkpoints |

---

## Configuration

PathStrike uses a YAML config file. It searches these locations in order:

1. `./pathstrike.yaml`
2. `./pathstrike.yml`
3. `./.pathstrike.yaml`
4. `~/.config/pathstrike/config.yaml`
5. `~/.pathstrike.yaml`

```yaml
bloodhound:
  base_url: "http://localhost:8080"
  token_id: "your-api-token-id"
  token_key: "your-api-token-key-base64"

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
  max_retries: 3
  auto_time_sync: true
```

---

## Requirements

- Python 3.11+
- BloodHound Community Edition (running with API keys)
- Linux attacker box (Kali, Parrot, Ubuntu)
- External tools: bloodyAD, Impacket, Certipy, NetExec, ntpdate

---

## Roadmap

### Planned Integrations

- [ ] **ROADtools** -- Azure AD / Entra ID enumeration and exploitation. Integrate `roadrecon` for Azure AD data collection and `roadlib` for token manipulation to extend attack paths into hybrid and cloud-only environments.
- [ ] **GitHound** -- Git credential discovery. Scan repositories, commit history, and CI/CD pipelines for leaked secrets (API keys, tokens, passwords) that can feed new credentials into PathStrike's credential store.
- [ ] **VsphereHound** -- VMware vSphere enumeration for BloodHound. Ingest vSphere relationships (VM-to-host, permissions, roles) to discover attack paths through virtualization infrastructure into AD.
- [ ] **Coercer** -- Expanded authentication coercion beyond PetitPotam/PrinterBug/DFSCoerce. Integrate Coercer's comprehensive MS-RPC method database for more reliable coercion across edge types.
- [ ] **KrbRelayUp** -- Local privilege escalation via Kerberos relay. Chain with existing RBCD and shadow credential handlers for local-to-domain escalation paths.
- [ ] **Whisker** -- Alternative shadow credential manipulation tooling for `AddKeyCredentialLink` edges.
- [ ] **PKINITtools** -- PKINIT-based authentication utilities to complement Certipy for certificate-to-TGT flows and UnPAC-the-hash.

### Engine Improvements

- [ ] **Parallel path execution** -- run independent path branches concurrently
- [ ] **OPSEC profiles** -- configurable noise levels (stealth vs speed) with tool selection preferences
- [ ] **Plugin system** -- drop-in handler modules for custom/proprietary edge types
- [ ] **Real-time BloodHound sync** -- push newly compromised nodes back into BloodHound CE for live graph updates
- [ ] **SOCKS proxy support** -- route tool traffic through proxychains/SOCKS for pivoting
- [ ] **Multi-forest campaigns** -- orchestrate attacks across multiple forests from a single config
- [ ] **Mythic Plugin** -- access to the tool via Mythic
---

## Disclaimer

PathStrike is intended for **authorized security testing and research only**. Only use this tool against systems you have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## Acknowledgments

PathStrike is built on top of incredible work by the offensive security community. Thank you to the authors and contributors of every tool that makes this project possible:

| Tool | Description | Link |
|---|---|---|
| **BloodHound CE** | Active Directory attack path mapping and analysis | [github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) |
| **Impacket** | Python classes for working with network protocols (DCSync, S4U, PSExec, and more) | [github.com/fortra/impacket](https://github.com/fortra/impacket) |
| **bloodyAD** | Active Directory privilege escalation framework | [github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) |
| **Certipy** | AD Certificate Services enumeration and exploitation | [github.com/ly4k/Certipy](https://github.com/ly4k/Certipy) |
| **NetExec** | Network execution and credential validation toolkit (successor to CrackMapExec) | [github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) |
| **pyGPOAbuse** | Group Policy Object abuse for privilege escalation | [github.com/Hackndo/pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) |
| **PetitPotam** | MS-EFSRPC authentication coercion | [github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam) |
| **PrinterBug** | MS-RPRN Print Spooler authentication coercion | [github.com/dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx) |
| **DFSCoerce** | MS-DFSNM Distributed File System coercion | [github.com/Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) |
| **ntlmrelayx** | NTLM relay framework (part of Impacket) | [github.com/fortra/impacket](https://github.com/fortra/impacket) |


## License

MIT

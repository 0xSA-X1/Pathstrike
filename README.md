<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-dark.svg" alt="Pathstrike" width="96">
  </picture>
</p>

# PathStrike

**Automated Active Directory attack path exploitation via BloodHound CE.**

PathStrike discovers and executes AD privilege escalation paths identified by BloodHound Community Edition using the BloodHound API, plus a live post-compromise enumeration layer that surfaces paths BH's frozen snapshot doesn't see. Point it at a compromised user, and it will find reachable exploitable targets (or the shortest path to Domain Admin), then exploit each edge automatically using a variety of tools — re-querying after each step so newly created edges are picked up on the fly.

---

## Features

- **Path Discovery** — queries BloodHound CE's Cypher API for attack paths + merges with live-discovered edges
- **Live Post-Compromise Enumeration** — after each successful step, re-enumerates AD to surface writeables, ADCS ESC findings, and tombstoned privileged accounts that BH doesn't see
- **Automated Exploitation** — 77 BloodHound edge types handled by 49 dedicated attack modules
- **Command Emission (`learn`)** — print the exact tool commands PathStrike would run for any edge or path — an offline template, or fully resolved with real values/secrets — for manual operation and teaching; executes nothing
- **Campaign Mode** — interactive step-through exploration across all reachable targets
- **Auto Mode** — greedy opportunistic escalation from source toward any reachable exploitable node
- **Cross-Domain Escalation** — detects and exploits domain trust relationships (child-to-parent, forest trusts)
- **Three Execution Modes** — `interactive` (step-by-step), `auto` (fully automated), `dry_run` (read-only simulation)
- **Tool Fallbacks** — handlers fall back to **netexec** when their primary tool (Impacket/bloodyAD/Certipy) is missing or fails — covering delegation (S4U), DCSync, gMSA/LAPS, MSSQL/DCOM execution, RBCD computer-staging, and Kerberoasting. The primary path is unchanged; the fallback only runs on failure
- **Credential Chaining** — captured creds feed into subsequent attack steps automatically
- **Rollback Support** — logs every AD modification and can reverse changes post-engagement
- **Checkpoint & Resume** — serialize attack state to disk and resume after interruption
- **Kerberos Time Sync** — auto-detects clock skew against the DC; syncs system clock via `ntpdate/chronyd/net time/rdate`, and falls back to wrapping subprocesses with **libfaketime** when system sync fails (e.g. no sudo)
- **Clean Console + Session Logs** — default output is terse; every run writes a full DEBUG log to `~/.pathstrike/logs/session_<timestamp>.log` and prints a one-line hint pointing at it if any warnings/errors occurred
- **Reporting** — JSON and HTML attack reports with full step-by-step details

## Supported Edge Types

| Category | Edges |
|---|---|
| **ACL Abuse** | `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights` |
| **Credential Access** | `ReadLAPSPassword`, `ReadGMSAPassword`, `DumpSMSAPassword`, `ForceChangePassword` |
| **Kerberos Delegation** | `AllowedToDelegate`, `AllowedToAct`, `WriteAccountRestrictions` |
| **Kerberos Tickets** | `DiamondTicket`, `SapphireTicket` |
| **AD CS (Certificates)** | `ADCSESC1`–`ADCSESC13`, `GoldenCert`, `ManageCA`, `ManageCertificates` |
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
| **Live-Enum Synthetic** | `RestorableFrom` (discovered by Pathstrike's live LDAP scan of `CN=Deleted Objects` — reanimates tombstoned privileged accounts) |

### Validation status

All listed handlers are implemented. The breakdown below records what has been **validated end-to-end** — the attack module driven against live Active Directory across varied test environments — versus what is implemented but not yet exercised live. The authoritative per-edge matrix (with notes) lives in [docs/EDGE_STATUS.md](docs/EDGE_STATUS.md).

**✅ Validated live end-to-end:**

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
- **Traversal (informational no-ops):** `Contains`, `ClaimSpecialIdentity`

**🚫 Environment-gated — technique mitigated or endpoint absent in the tested environment, not a code bug:**

- **`CoerceToTGT`** — coercion fires (the DC calls back), but the SMB→LDAP relay never completes against a hardened DC (MIC enforced / CVE-2019-1040 mitigated). PathStrike will not weaken DC security to force it.
- **`ADCSESC8`** — NTLM relay to AD CS HTTP web enrollment; requires the web-enrollment endpoint to be up and reachable.

**⬜ Implemented but not yet validated live** — no instance of the edge (or a usable source/target) was present in the tested environments, so the technique was exercised only by dry-run / unit test: `AllowedToAct`, `DumpSMSAPassword`, `AdminTo`, `HasSession`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, `SQLAdmin`, `WriteSPN`, `RestorableFrom`, `DiamondTicket`, `SapphireTicket`, the `CoerceAndRelayNTLMTo*` family, `TrustedBy`/`ExternalTrust`/`AbuseTGTDelegation`/`HasTrustKeys`, and `ADCSESC2`/`ESC5`/`ESC10`/`ESC11`/`ESC13`.

---

## Live Enumeration (supplements BH CE data)

BloodHound CE is a **static snapshot** of the graph taken at SharpHound ingest time. Once a campaign starts modifying AD, BH's view drifts — new group memberships, fresh ACEs, and transitive rights created by earlier steps are invisible until re-collection. Pathstrike runs three post-compromise enumerators as each new identity is owned, recording the discovered edges in an in-memory **capability graph** consulted alongside BH during the next discovery round:

| Source | Covers | When it runs |
|---|---|---|
| **`bloodyAD get writable`** | Standard ACE writes (`GenericWrite`, `Owns`, `WriteOwner`, `WriteDacl`) | After every successful compromise, per newly-owned user/computer |
| **`certipy find -vulnerable`** | AD CS templates with ESC1/ESC3/ESC4/ESC6/ESC9/ESC10/ESC11/ESC13 findings | After every successful compromise, per newly-owned user/computer |
| **`ldap3` Recycle Bin scan** | Tombstoned privileged accounts in `CN=Deleted Objects` (surfaced as synthetic `RestorableFrom` edges) | After every successful compromise, per newly-owned identity |

Each enumerator contributes synthetic edges that appear in the next round's target table tagged with their discovery method. Pathstrike prefers BH-sourced multi-hop paths over synthetic single-hops when both point at the same target.

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
pip install coercer                                    # multi-method auth coercion (CoerceToTGT)
pip install git+https://github.com/Hackndo/pyGPOAbuse.git   # GPLink / WriteGPLink

# Install Certipy in an isolated env (avoids cryptography pin conflict with bloodyAD)
pipx install certipy-ad

# Install libfaketime for KDC clock-skew fallback (no-sudo mode)
sudo apt install faketime      # or build from source: https://github.com/wolfcw/libfaketime

# Configure
cp pathstrike.yaml.example pathstrike.yaml
# Edit pathstrike.yaml with your BloodHound CE API keys + domain/credentials

# Verify tools + BH CE connectivity + time offset
pathstrike verify

# Interactive step-through campaign (default — pick a target each round)
pathstrike campaign

# Greedy opportunistic escalation (no prompts, chases deepest reachable target)
pathstrike auto
```

---

## CLI Commands

| Command | Description |
|---|---|
| `pathstrike auto` | **Greedy reachable-targets exploitation** — escalate as far as possible from the source, chasing the deepest reachable exploitable node. Re-queries BH + live-enum after each successful step. |
| `pathstrike campaign` | **Interactive step-through campaign** — enumerates every reachable exploitable node, prompts you to pick one per round, exploits it, re-queries. Use `--high-value-only` to restrict to Domain Admins / Tier Zero. |
| `pathstrike learn` | **Print the commands PathStrike would run** to exploit an edge or a comma-separated path, instead of executing — an offline template by default, or fully resolved with real values/secrets when `--config`/`--creds-file` is given (`--redact` to hide secrets, `--steps` for annotated output). Branchy handlers emit every alternative. `campaign --learn` does the same per selected path. |
| `pathstrike edges` | List all supported BloodHound edge types and their registered handlers |
| `pathstrike verify` | Validate config, check that all tools are on PATH, test BH CE connectivity |
| `pathstrike domains` | List all AD domains discovered by BloodHound CE |
| `pathstrike trusts` | Enumerate domain trust relationships from BloodHound CE |
| `pathstrike adcs` | Discover AD CS Certificate Authorities and vulnerable templates via Certipy |
| `pathstrike kerberoast` | Targeted Kerberoasting attack |
| `pathstrike asreproast` | AS-REP roasting attack |
| `pathstrike credentials` | Interactively update the credentials in the config file (prompts for username, password, domain, DC host) |
| `pathstrike timesync` | Check or sync Kerberos clock offset against the DC |
| `pathstrike rollback` | Reverse AD changes from a previous attack (reads rollback log JSON) |
| `pathstrike checkpoints` | List saved attack-path checkpoints |

### Edge validation & testing

| Command | Description |
|---|---|
| `pathstrike test-edge` | Exercise a **single** edge handler against the live environment — safe dry-run preview by default, `--live` to exploit. |
| `pathstrike test-edges` | Run a **batch** of edge tests from a plan file, log structured results, and update the coverage matrix. |
| `pathstrike gen-test-plan` | Scaffold a `test-edges` plan seeded from the edge registry (optionally filtered by `--category`). |
| `pathstrike discover-edges` | Build a test plan by enumerating the edges actually **exploitable** from the credentials you hold. |
| `pathstrike validate-paths` | Validate escalation **chains** end-to-end — does a multi-hop path actually reach a higher-privileged principal? |

### When to use `auto` vs `campaign`

- **`pathstrike auto`** when you want to let the tool run free — it picks the highest-value reachable target each round and exploits it without prompting. Best for rapid escalation during authorised engagements.
- **`pathstrike campaign`** when you want to drive decisions yourself — each round presents a ranked table of reachable targets and you pick. Best for thorough documentation during pentest reporting and when you need to control side effects.

Both share the same discovery engine, live-enum pipeline, and edge handlers.

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
  max_retries: 3
  auto_time_sync: true
```

---

## Requirements

- **Python 3.11+**
- **BloodHound Community Edition v9.0.1 or newer** — earlier builds (e.g. `bloodhound 8.7.0~rc3` shipped by the Kali apt package) are missing or differently gate the `/api/v2/graphs/cypher` endpoint Pathstrike depends on. Install the latest via Docker Compose from https://ghst.ly/getbhce — see [INSTALL.md](INSTALL.md).
- **Linux attacker box** (Kali, Parrot, Ubuntu, Debian)
- **External tools**: bloodyAD, Impacket, Certipy (v5+, install via pipx), NetExec, Coercer, pyGPOAbuse, ntpdate, libfaketime. Coercer/pyGPOAbuse are only needed for the coercion and GPO edges respectively; the rest are core.
- **AD CS edges require SharpHound collected with `-c All`** — the CertServices/CARegistry data that the ESC and CA-management handlers depend on is *not* gathered by `netexec --bloodhound` or `bloodhound-python`, so collect with SharpHound (`-c All`) if you want PathStrike to see ADCS attack paths.

---

## Troubleshooting at a glance

- **`404 resource not found` from BH CE Cypher endpoint** — upgrade BH CE to v9.0.1+ (see above)
- **`KDC_ERR_CLIENT_NOT_TRUSTED` during shadow-creds** — usually clock skew; Pathstrike attempts `ntpdate` / `chronyd` / `net time` / `rdate`, then falls back to wrapping the subprocess with `faketime +Xs` if libfaketime is installed
- **Certipy `pkg_resources` ModuleNotFoundError on Python 3.13** — install certipy via pipx instead of pip so it gets its own environment: `pipx install certipy-ad`
- **No ADCS / ESCx edges show up in BloodHound** — your collection didn't gather AD CS data. Re-collect with SharpHound `-c All` (CertServices + CARegistry); `netexec --bloodhound` and `bloodhound-python` don't collect ADCS at all
- **`CoerceToTGT` / SMB→LDAP relay never completes** — this is modern DC hardening (MIC enforced / CVE-2019-1040 mitigated), not a tool bug. The coercion itself fires; PathStrike won't weaken DC signing to force the relay through
- **Handler crashes buried in a Rich Live panel** — look at `~/.pathstrike/logs/session_<timestamp>.log` for full tracebacks; the console keeps only one-line summaries

---

## Roadmap

### Planned Integrations

- [ ] **ROADtools** — Azure AD / Entra ID enumeration and exploitation. Integrate `roadrecon` for Azure AD data collection and `roadlib` for token manipulation to extend attack paths into hybrid and cloud-only environments.
- [ ] **GitHound** — Git credential discovery. Scan repositories, commit history, and CI/CD pipelines for leaked secrets (API keys, tokens, passwords) that can feed new credentials into PathStrike's credential store.
- [ ] **VsphereHound** — VMware vSphere enumeration for BloodHound. Ingest vSphere relationships (VM-to-host, permissions, roles) to discover attack paths through virtualization infrastructure into AD.
- [ ] **KrbRelayUp** — Local privilege escalation via Kerberos relay. Chain with existing RBCD and shadow credential handlers for local-to-domain escalation paths.
- [ ] **Whisker** — Alternative shadow credential manipulation tooling for `AddKeyCredentialLink` edges.
- [ ] **PKINITtools** — PKINIT-based authentication utilities to complement Certipy for certificate-to-TGT flows and UnPAC-the-hash.

### Engine Improvements

- [ ] **Extended-rights LDAP scanner** — Phase 3D: enumerate `AddSelf` / `ForceChangePassword` / `ReadGMSAPassword` / `ReadLAPSPassword` / `DCSync` rights live, not just what bloodyAD's `get writable` surfaces
- [ ] **Parallel path execution** — run independent path branches concurrently
- [ ] **OPSEC profiles** — configurable noise levels (stealth vs speed) with tool selection preferences
- [ ] **Plugin system** — drop-in handler modules for custom/proprietary edge types
- [ ] **Real-time BloodHound sync** — push newly compromised nodes back into BloodHound CE for live graph updates
- [ ] **SOCKS proxy support** — route tool traffic through proxychains/SOCKS for pivoting
- [ ] **Multi-forest campaigns** — orchestrate attacks across multiple forests from a single config
- [ ] **Mythic Plugin** — access to the tool via Mythic

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
| **libfaketime** | LD_PRELOAD clock-offset wrapping used as Kerberos skew fallback | [github.com/wolfcw/libfaketime](https://github.com/wolfcw/libfaketime) |
| **ldap3** | Pure-Python LDAP library — powers Pathstrike's live Recycle Bin + ACL enumeration | [github.com/cannatag/ldap3](https://github.com/cannatag/ldap3) |
| **dnspython** | DNS toolkit — resolves CA / member-server hosts via the DC's DNS for ADCS edges | [github.com/rthalley/dnspython](https://github.com/rthalley/dnspython) |
| **pyGPOAbuse** | Group Policy Object abuse for privilege escalation | [github.com/Hackndo/pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) |
| **Coercer** | Multi-method MS-RPC authentication coercion (primary coercion driver) | [github.com/p0dalirius/Coercer](https://github.com/p0dalirius/Coercer) |
| **PetitPotam** | MS-EFSRPC authentication coercion | [github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam) |
| **PrinterBug** | MS-RPRN Print Spooler authentication coercion | [github.com/dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx) |
| **DFSCoerce** | MS-DFSNM Distributed File System coercion | [github.com/Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) |
| **ntlmrelayx** | NTLM relay framework (part of Impacket) | [github.com/fortra/impacket](https://github.com/fortra/impacket) |


## License

MIT

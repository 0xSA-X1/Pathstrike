# PathStrike — Install Guide

## Requirements

- **Python 3.11+** (3.12 / 3.13 tested)
- **BloodHound Community Edition v9.0.1 or newer** — earlier builds are missing or differently gate the `/api/v2/graphs/cypher` endpoint Pathstrike depends on. See [Section 4](#4-bloodhound-ce-setup-v901-required).
- **Linux attacker box** (Kali, Parrot, Debian, Ubuntu)
- **Root access helpful** — time sync, Docker, some package installs need sudo

---

## 1. Install PathStrike

```bash
git clone https://github.com/0xSA-X1/Pathstrike.git
cd Pathstrike

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install PathStrike + Python dependencies
pip install -e .
```

> **Python 3.13+ note:** If you get build errors, make sure pip and setuptools
> are up to date: `pip install --upgrade pip setuptools wheel`

This installs the `pathstrike` CLI command and pulls in:

- `httpx` — async HTTP client for BloodHound CE API
- `pydantic` — config validation
- `typer` + `rich` — CLI framework + live progress display
- `pyyaml` — config file parsing
- `ldap3` (transitively via bloodyAD) — powers Pathstrike's live Recycle Bin and LDAP enumeration

---

## 2. Install External Attack Tools

PathStrike wraps these tools as async subprocesses. Install whichever you need:

### bloodyAD (AD object manipulation — ACLs, passwords, RBCD, shadow creds, writable enum)

```bash
pip install bloodyAD
```

### Impacket (DCSync, S4U delegation, PSExec, DCOM)

```bash
pip install impacket
```

### Certipy — install via pipx to avoid dependency conflicts

**Important:** Certipy (`certipy-ad`) pins `cryptography~=42.0.8`, which conflicts with bloodyAD's `cryptography==44.0.2`. Installing Certipy into the same venv as bloodyAD will downgrade cryptography and break bloodyAD. Use pipx to keep Certipy in its own isolated environment:

```bash
# Install pipx first if you don't have it
sudo apt install pipx
pipx ensurepath

# Install Certipy in an isolated env (on PATH via pipx)
pipx install certipy-ad

# Verify
which certipy        # ~/.local/bin/certipy (pipx)
certipy --version
```

Pathstrike subprocesses Certipy via PATH — it doesn't care whether Certipy lives in pipx or the venv, only that `certipy` is callable.

### NetExec (credential validation, LAPS, command execution)

NetExec isn't on PyPI. Install via pipx or from GitHub:

```bash
# Option A: pipx (recommended — isolated install, stays on PATH)
pipx install git+https://github.com/Pennyw0rth/NetExec.git

# Option B: pip from GitHub (installs into current venv — may conflict with cryptography)
pip install git+https://github.com/Pennyw0rth/NetExec.git

# Option C: Kali — already packaged
sudo apt install netexec
```

### ntpdate (Kerberos system-clock sync)

```bash
# Kali (usually pre-installed)
which ntpdate

# Debian/Ubuntu — ntpdate has been replaced by ntpsec-ntpdate
sudo apt install ntpsec-ntpdate

# Arch
sudo pacman -S ntp
```

### libfaketime (Kerberos skew fallback — no sudo / no NTP required)

When system clock sync fails (no sudo, NTP blocked, DC unreachable for NTP but reachable for LDAP), PathStrike falls back to wrapping each tool subprocess with `faketime +Xs` where `X` is the DC offset measured via `ntpdate -q`. This doesn't change the real system clock but gives each Kerberos-using subprocess a correct clock.

```bash
# Option A: Kali / Debian package (easiest)
sudo apt install faketime

# Option B: Build from source (pins to latest)
git clone https://github.com/wolfcw/libfaketime.git
cd libfaketime
sudo make install        # installs /usr/local/bin/faketime + /usr/local/lib/faketime/
cd .. && rm -rf libfaketime

# Verify
which faketime           # /usr/bin/faketime or /usr/local/bin/faketime
```

PathStrike detects `faketime` on PATH and uses it automatically when system sync fails.

### Install everything at once

```bash
# Python tools (inside your venv)
pip install bloodyAD impacket

# Certipy in its own pipx env (avoids cryptography conflict)
pipx install certipy-ad

# NetExec (pipx preferred, or venv if you accept the cryptography churn)
pipx install git+https://github.com/Pennyw0rth/NetExec.git

# System tools
sudo apt install ntpsec-ntpdate faketime
```

### Verify all tools are available

```bash
pathstrike verify
```

This checks every binary on PATH (bloodyAD, impacket CLIs, certipy, netexec, pyGPOAbuse, ntlmrelayx, ntpdate, **faketime**), measures the time offset against the DC, and tests BloodHound CE connectivity.

---

## 3. Configure

```bash
# Copy the example config
cp pathstrike.yaml.example pathstrike.yaml

# Edit with your values
vim pathstrike.yaml
```

### Required fields

```yaml
bloodhound:
  base_url: "http://localhost:8080"        # BH CE URL (v9.0.1+ required)
  token_id: "your-api-token-id"            # My Profile -> API Key Management in BH CE
  token_key: "your-api-token-key"

domain:
  name: "corp.local"                       # Target AD domain
  dc_host: "10.10.10.10"                   # DC IP address
  dc_fqdn: "dc01.corp.local"               # DC FQDN (for Kerberos/NTP)

credentials:
  username: "jsmith"
  # Provide ONE of these:
  password: "Summer2024!"
  # nt_hash: "aad3b435b51404eeaad3b435b51404ee"
  # ccache_path: "/tmp/krb5cc_jsmith"
```

### Optional fields (with defaults)

```yaml
target:
  group: "DOMAIN ADMINS"                   # Target group
  # custom_target: "DC01.CORP.LOCAL"       # Or a specific node

execution:
  mode: "interactive"                      # interactive | auto | dry_run
  timeout: 30                              # Per-tool timeout (seconds)
  max_paths: 5                             # Max paths to discover
  max_retries: 3                           # Retries on transient failures
  auto_time_sync: true                     # Auto ntpdate + faketime fallback on skew
```

### Config auto-discovery

You don't need `-c config.yaml` every time. PathStrike searches these locations in order:

1. `./pathstrike.yaml`
2. `./pathstrike.yml`
3. `./.pathstrike.yaml`
4. `~/.config/pathstrike/config.yaml`
5. `~/.pathstrike.yaml`

---

## 4. BloodHound CE Setup (v9.0.1+ required)

**PathStrike requires BloodHound Community Edition v9.0.1 or newer.** Older builds (including the `bloodhound 8.7.0~rc3-0kali1` package shipped by Kali's apt repo) either don't implement the `/api/v2/graphs/cypher` endpoint or have different permission-gate semantics that cause silent 404 responses. If you see `BH API error 404: resource not found` during `pathstrike paths` / `campaign` / `auto`, check your BH CE version first.

### Recommended: Docker Compose install

This is the upstream-recommended way to run BH CE and always gets you the latest stable version:

```bash
# Stop any pre-existing native BH stack that would conflict on port 8080 / 7687
sudo systemctl stop bloodhound 2>/dev/null
sudo pkill -9 -f 'org.neo4j.server.CommunityEntryPoint'
sudo pkill -9 -f bhapi

# Install Docker + Compose plugin if not already present
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"          # log out/in to take effect

# Pull and launch BH CE
mkdir -p ~/bloodhound-ce && cd ~/bloodhound-ce
curl -L https://ghst.ly/getbhce -o docker-compose.yml
sudo docker compose pull
sudo docker compose up -d

# Grab the initial admin password
sleep 30
sudo docker compose logs bloodhound 2>&1 | grep -i "Initial Password" | tail -1
```

### Create an API token

1. Open `http://localhost:8080`, log in as `admin` with the initial password, change it on first login
2. Top-right avatar → **My Profile** → **API Key Management** → **Create Token**
3. Give it any name, copy the **Token ID** and **Token Key** into `pathstrike.yaml`
4. Tokens inherit the creating user's permissions — create as admin for broadest access

### Import your collection data

5. Collect AD data with a CE-compatible collector (not BloodHound-Legacy):
   - **bloodhound-ce-python** (Kali: `pip install bloodhound-ce`, NOT `bloodhound-python` which is legacy 4.x)
   - **SharpHound** (Windows / Mono)
6. Upload the resulting zip via the BH CE UI → **File Ingest** or **Quick Upload**
7. Wait for analysis to complete (sidebar shows pending/running counts)

---

## 5. Usage

### Discover attack paths (read-only)

```bash
# Shortest path from compromised user to Domain Admins
pathstrike paths -s jsmith

# All shortest paths
pathstrike paths -s jsmith --all

# Verbose (debug logging to console; always also to the session log file)
pathstrike paths -s jsmith -v
```

### Interactive step-through campaign (recommended for engagements)

```bash
# Each round presents a ranked table of reachable targets; you pick one
pathstrike campaign

# Restrict to Domain Admins / Enterprise Admins / Tier Zero targets only
pathstrike campaign --high-value-only

# Override max targets per round (default 10)
pathstrike campaign --max-targets 15
```

### Greedy auto escalation (no prompts)

```bash
# Chases the deepest reachable exploitable target; doesn't prompt
pathstrike auto

# Limit how deep it searches
pathstrike auto --max-depth 8
```

### Execute a single attack path

```bash
# Interactive mode (prompts before each step)
pathstrike attack -s jsmith

# Full auto mode
pathstrike attack -s jsmith -m auto

# Dry run (no changes, just shows what would happen)
pathstrike attack -s jsmith -m dry_run

# Override retry count
pathstrike attack -s jsmith --max-retries 5

# Disable auto time sync (will not attempt ntpdate or faketime fallback)
pathstrike attack -s jsmith --no-time-sync
```

### Time synchronisation

```bash
# Check clock offset with DC (non-invasive)
pathstrike timesync --check

# Sync clock with DC (tries ntpdate, chronyd, net time, rdate — requires sudo)
pathstrike timesync
```

If all system-clock sync methods fail but `faketime` is installed, PathStrike will automatically wrap subsequent attack subprocesses with `faketime +Xs` where `X` is the measured offset. This works without root.

### Session log + warning summary

Every run writes a full DEBUG-level log to:

```
~/.pathstrike/logs/session_<YYYYMMDD_HHMMSS>.log
```

The console stays quiet by default — only step outcomes, captured credentials, and actionable errors are shown. If any warnings or errors were logged during the run, the tool prints a one-line hint at exit:

```
⚠  3 warning(s) logged during this run.
   cat /home/sax1/.pathstrike/logs/session_20260417_134120.log
```

Use `-v` / `--verbose` to mirror DEBUG to the console too.

### List supported edge types

```bash
pathstrike edges
```

### Rollback changes

Rollback logs are saved automatically after every attack, auto, and campaign run to `rollback_logs/`.

```bash
# Roll back a specific log file
pathstrike rollback rollback_logs/rollback_campaign_20260414_153022.json

# Preview what would be rolled back without executing
pathstrike rollback --dry-run rollback_logs/...

# Continue rolling back even if some actions fail
pathstrike rollback --force rollback_logs/...
```

---

## 6. Troubleshooting

### BH CE: `BH API error 404: resource not found` on `/api/v2/graphs/cypher`

Your BH CE is too old. Upgrade to v9.0.1+ (see [Section 4](#4-bloodhound-ce-setup-v901-required)). Common signs:

- You're running the Kali apt `bloodhound` package (`bloodhound 8.7.0~rc3-0kali1` or older)
- `GET /api/v2/available-domains` works but `POST /api/v2/graphs/cypher` returns 404

### Certipy: `ModuleNotFoundError: No module named 'pkg_resources'`

Python 3.13 doesn't include `pkg_resources` by default. Either update setuptools, or (preferred) install certipy via pipx so it manages its own deps:

```bash
pip uninstall -y certipy-ad
pipx install certipy-ad
certipy --version
```

### Certipy and bloodyAD cryptography version conflict

`certipy-ad 5.x` pins `cryptography~=42.0.8`; `bloodyad 2.5+` pins `cryptography==44.0.2`. They cannot live in the same venv. Install Certipy via pipx:

```bash
pipx install certipy-ad
pip install --force-reinstall 'cryptography==44.0.2'   # restore for bloodyAD
```

### `netexec` — `No matching distribution found`

NetExec isn't on PyPI. Install from GitHub via pipx:

```bash
pipx install git+https://github.com/Pennyw0rth/NetExec.git
# or on Kali:
sudo apt install netexec
```

### `ntpdate` — `Package has no installation candidate`

On newer Debian/Ubuntu, ntpdate was replaced:

```bash
sudo apt install ntpsec-ntpdate
```

### `KRB_AP_ERR_SKEW` / `Clock skew too great`

PathStrike auto-handles this in two stages:

1. Tries `sudo ntpdate <dc>`, `sudo chronyd`, `sudo net time`, `sudo rdate` in order
2. If all system sync methods fail and `faketime` is installed, enables a per-subprocess clock offset via `faketime +Xs`

Manual fixes if the auto path doesn't work:

```bash
sudo ntpdate dc01.corp.local
# or without sudo, once libfaketime is installed, Pathstrike will wrap
# tool calls with faketime automatically — no manual action needed
```

### `KDC_ERR_CLIENT_NOT_TRUSTED` during shadow-credentials

Usually a clock skew problem at the KDC side. See the `KRB_AP_ERR_SKEW` fix above — install libfaketime so PathStrike can compensate without root. If that doesn't resolve it:

- Confirm DC actually has a valid KDC certificate (check `certipy find`)
- Confirm your Certipy build does PKINIT properly (v5+ is most reliable)

### Tool not found errors

```bash
# Check what's missing
pathstrike verify

# Install missing Python tools
pip install bloodyAD impacket
pipx install certipy-ad
pipx install git+https://github.com/Pennyw0rth/NetExec.git
sudo apt install ntpsec-ntpdate faketime
```

### BloodHound CE connection failed

- Confirm BH CE is running: `curl http://localhost:8080/ui` (expect HTTP 200)
- Check `base_url` in config matches the actual BH CE address
- Verify API key is valid and not expired (regenerate if in doubt)
- Confirm the data you collected is for the domain in your config (`pathstrike domains`)

### Permission errors on time sync

`ntpdate` / `chronyd` / `net time` / `rdate` all need root to change the system clock. If you can't use sudo:

1. Install libfaketime (`sudo apt install faketime`) and PathStrike will wrap tools with the right clock offset — no root required for subsequent runs
2. Or disable auto sync and manage time manually:

```yaml
execution:
  auto_time_sync: false
```

Or use `--no-time-sync` on the CLI.

### Rich Live panel appears stacked / fragmented

Fixed in recent releases — `_QuietLive` now muzzles log handlers while the progress panel is active. If you still see it, pull latest:

```bash
cd ~/Tools/Pathstrike
git pull origin main
pip install -e .
```

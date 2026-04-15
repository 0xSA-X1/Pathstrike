# PathStrike -- Install Guide

## Requirements

- **Python 3.11+**
- **BloodHound Community Edition** running with API keys configured
- **Linux attacker box** (Kali, Parrot, etc.) -- time sync tools need sudo

---

## 1. Install PathStrike

```bash
git clone https://github.com/0x-SA-X1/Pathstrike.git
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
- `httpx` -- async HTTP client for BloodHound CE API
- `pydantic` -- config validation
- `typer` + `rich` -- CLI framework + live progress display
- `pyyaml` -- config file parsing

---

## 2. Install External Attack Tools

PathStrike wraps these tools as async subprocesses. Install whichever you need:

### bloodyAD (AD object manipulation -- ACLs, passwords, RBCD, shadow creds)

```bash
pip install bloodyAD
```

### Impacket (DCSync, S4U delegation, PSExec, DCOM)

```bash
pip install impacket
```

### Certipy (AD CS / certificate attacks -- ESC1-ESC13)

```bash
pip install certipy-ad
```

### NetExec (credential validation, LAPS, command execution)

NetExec is not on PyPI. Install via pipx or from GitHub:

```bash
# Option A: pipx (recommended -- isolated install, stays on PATH)
sudo apt install pipx
pipx install git+https://github.com/Pennyw0rth/NetExec.git

# Option B: pip from GitHub (installs into current venv)
pip install git+https://github.com/Pennyw0rth/NetExec.git

# Option C: Kali -- already packaged
sudo apt install netexec
```

### ntpdate (Kerberos time sync -- auto-fix for clock skew)

```bash
# Kali (usually pre-installed)
which ntpdate

# Debian/Ubuntu -- ntpdate has been replaced by ntpsec-ntpdate
sudo apt install ntpsec-ntpdate

# Arch
sudo pacman -S ntp
```

> If ntpdate is unavailable, PathStrike will fall back to
> `chronyd -q` -> `net time` -> `rdate` automatically.

### Install everything at once

```bash
# Python tools (inside your venv)
pip install bloodyAD impacket certipy-ad

# NetExec (from GitHub)
pip install git+https://github.com/Pennyw0rth/NetExec.git

# System tools
sudo apt install ntpsec-ntpdate    # or ntpdate on Kali
```

### Verify all tools are available

```bash
pathstrike verify
```

This checks every binary on PATH and tests BloodHound CE connectivity.

---

## 3. Configure

```bash
# Copy the example config
cp pathstrike.yaml.example pathstrike.yaml

# Edit with your values
nano pathstrike.yaml
```

### Required fields

```yaml
bloodhound:
  base_url: "http://localhost:8080"        # BH CE URL
  token_id: "your-api-token-id"            # Settings -> API Keys in BH CE
  token_key: "your-api-token-key-base64"

domain:
  name: "corp.local"                       # Target AD domain
  dc_host: "10.10.10.10"                   # DC IP address
  dc_fqdn: "dc01.corp.local"              # DC FQDN (for Kerberos/NTP)

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
  auto_time_sync: true                     # Auto ntpdate on clock skew
```

### Config auto-discovery

You don't need `-c config.yaml` every time. PathStrike searches these locations in order:

1. `./pathstrike.yaml`
2. `./pathstrike.yml`
3. `./.pathstrike.yaml`
4. `~/.config/pathstrike/config.yaml`
5. `~/.pathstrike.yaml`

---

## 4. BloodHound CE Setup

1. Start BH CE (Docker or bare metal)
2. Go to **Settings -> API Keys**
3. Create a new API key pair
4. Copy the **Token ID** and **Token Key** into your config
5. **Import SharpHound/BloodHound data** so the graph has nodes and edges

---

## 5. Usage

### Discover attack paths

```bash
# Shortest path from compromised user to Domain Admins
pathstrike paths -s jsmith

# All shortest paths
pathstrike paths -s jsmith --all

# Verbose (debug logging)
pathstrike paths -s jsmith -v
```

### Execute an attack path

```bash
# Interactive mode (prompts before each step)
pathstrike attack -s jsmith

# Full auto mode
pathstrike attack -s jsmith -m auto

# Dry run (no changes, just shows what would happen)
pathstrike attack -s jsmith -m dry_run

# Override retry count
pathstrike attack -s jsmith --max-retries 5

# Disable auto time sync
pathstrike attack -s jsmith --no-time-sync
```

### Run an autonomous campaign

```bash
# Interactive campaign (prompts before each path)
pathstrike campaign -s jsmith

# Fully autonomous campaign
pathstrike campaign -s jsmith -m auto

# Limit to 5 targets per round
pathstrike campaign -s jsmith -m auto --max-targets 5
```

### Time synchronisation

```bash
# Check clock offset with DC
pathstrike timesync --check

# Sync clock with DC (requires sudo)
pathstrike timesync
```

### List supported edge types

```bash
pathstrike edges
```

### Rollback changes

Rollback logs are saved automatically after every attack, auto, and campaign run
to the `rollback_logs/` directory.

```bash
# Roll back the most recent attack (auto-discovers latest log)
pathstrike rollback

# Roll back a specific log file
pathstrike rollback rollback_logs/rollback_campaign_20260414_153022.json

# Preview what would be rolled back without executing
pathstrike rollback --dry-run

# Continue rolling back even if some actions fail
pathstrike rollback --force
```

---

## 6. Troubleshooting

### `pip install -e .` fails with `Cannot import setuptools.backends._legacy`

Your setuptools is too old or too new. Update it:

```bash
pip install --upgrade pip setuptools wheel
pip install -e .
```

### `netexec` -- `No matching distribution found`

NetExec isn't on PyPI. Install from GitHub:

```bash
pip install git+https://github.com/Pennyw0rth/NetExec.git
# or on Kali:
sudo apt install netexec
```

### `ntpdate` -- `Package has no installation candidate`

On newer Debian/Ubuntu, ntpdate was replaced:

```bash
sudo apt install ntpsec-ntpdate
```

### `KRB_AP_ERR_SKEW` / Clock skew too great

PathStrike auto-fixes this during attacks. To fix manually:

```bash
sudo ntpdate dc01.corp.local
# or
sudo chronyd -q 'server dc01.corp.local iburst'
```

### Tool not found errors

```bash
# Check what's missing
pathstrike verify

# Install missing Python tools
pip install bloodyAD impacket certipy-ad
pip install git+https://github.com/Pennyw0rth/NetExec.git
```

### BloodHound CE connection failed

- Confirm BH CE is running: `curl http://localhost:8080/api/version`
- Check `base_url` in config matches the actual BH CE address
- Verify API key is valid and not expired

### Permission errors on time sync

ntpdate needs root to change the system clock:

```bash
sudo ntpdate 10.10.10.10
```

If you can't use sudo, disable auto sync and manage time manually:

```yaml
execution:
  auto_time_sync: false
```

Or use `--no-time-sync` on the CLI.

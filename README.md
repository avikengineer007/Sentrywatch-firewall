# Sentrywatch v2 — Intelligent Log-Based IDS/IPS

**Sentrywatch v2** is a log-based Intrusion Detection and Prevention System (IDS/IPS) that extends traditional rule-based security with multi-class incident detection, IP threat attribution, time-decaying reputation scoring, an advisory LLM (Claude API) risk analyzer, a pluggable multi-channel notification module, and a tamper-evident hash-chained audit log — while strictly maintaining **deterministic, fail-closed, and auditable blocking guarantees**.

---

## Architecture Overview

```
 ┌────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌───────────────┐
 │ Log Sources│──▶│  Ingest/Parse │──▶│ Detection Engine  │──▶│ Incident Store │
 └────────────┘   └───────────────┘   │ (deterministic     │   └───────┬───────┘
                                        │  rule set)         │           │
                                        └──────────────────┘           ▼
                                                              ┌──────────────────┐
                                                              │  Scoring Layer    │
                                                              │ (Claude API,      │
                                                              │  advisory only)   │
                                                              └───────┬──────────┘
                                                                      ▼
                                                              ┌──────────────────┐
                                                              │  Decision Engine  │
                                                              │ (deterministic,   │
                                                              │  allowlist+TTL)   │
                                                              └───────┬──────────┘
                                                                      ▼
                                                    ┌──────────────────────────────┐
                                                    │ Enforcement (dry-run default) │
                                                    │  iptables/nftables adapter     │
                                                    └───────────────┬──────────────┘
                                                                    │
                                         ┌──────────────────────────┴──────────────────────────┐
                                         ▼                                                     ▼
                             ┌───────────────────────┐                             ┌───────────────────────┐
                             │ Notification Module   │                             │   Audit Log (append-  │
                             │ (notify-send, webhook,│                             │   only, signed)       │
                             │  watch_terminal)      │                             └───────────────────────┘
                             └───────────────────────┘                                         │
                                                                                               ▼
                                                                                   ┌───────────────────────┐
                                                                                   │  Terminal UI (rich)   │
                                                                                   └───────────────────────┘
```

---

## Core Features & Engineering Philosophy

1. **LLM Advisory-Only Isolation**: The Claude API Scoring Layer is **strictly advisory**. Its output (`severity_score`, `rationale`, `recommended_action`) is stored for analyst visibility, but **never read by the Decision Engine**. Blocking decisions are triggered solely by deterministic rules evaluated against a mandatory allowlist.
2. **Multi-Channel Notification Engine**:
   - **`notify-send`**: Desktop notifications (Linux).
   - **`webhook`**: Generic HTTP POST JSON dispatcher compatible with **ntfy.sh**, **Discord**, **Telegram**, or custom endpoints.
   - **`watch_terminal`**: Live Rich terminal watcher.
   - **Deduplication Cooldown**: Suppresses alert storms per `(source_ip, incident_type)` tuple within a configurable window (default 300s).
   - **Non-Blocking Worker**: Async queue dispatch guarantees notifications never delay ingestion, scoring, or blocking.
3. **Dual Severity Signals (Defense-in-Depth)**:
   - *Deterministic IP Reputation Score*: Mathematical, time-decaying counter based on historical incident frequency and weights.
   - *LLM Advisory Severity Score*: Contextual natural-language risk assessment produced by Claude 3.5 Sonnet.
4. **Fail-Closed & Reversible Enforcement**: Dry-run mode is enabled by default. Every block is TTL-limited, checked against the allowlist, and recorded in a SHA-256 hash-chained audit log.

---

## Supported Incident Classes

| Incident Class | Source Log | Detection Logic |
|---|---|---|
| **Brute-force login** | `auth.log` / `journalctl` | $N$ failed authentication attempts from single IP within window $T$ |
| **Port scan** | `ufw.log` / `conntrack` | $\ge N$ distinct destination ports probed by single IP within window $T$ |
| **Privilege escalation** | `auditd` / `sudo` log | Failed `sudo`/`su` authentications or unauthorized command invocations |
| **Anomalous outbound** | `conntrack` / netstat | New outbound connection to suspicious high-risk external ports (e.g. 4444, 8443) |
| **Suspicious process spawn** | `auditd` (`execve`) | Unprivileged web process (`nginx`, `apache2`, `www-data`) spawning shell binaries (`sh`, `bash`, `nc`) |

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- (Optional) `iptables` or `nftables` for Linux firewall enforcement (defaults to `simulated` mode for dev/dry-run)

### Step 1: Clone Repository
```bash
git clone https://github.com/avikengineer007/Sentrywatch-firewall.git
cd Sentrywatch-firewall
```

### Step 2: Install Package
```bash
pip install -e .
```

### Step 3: Configure Environment Variables (`.env`)
Create a `.env` file in the project root directory:

```env
# Optional: Anthropic API Key for AI Advisory Scoring
ANTHROPIC_API_KEY="sk-ant-api03-..."

# Optional: Webhook URL for push notifications (e.g., ntfy.sh, Discord, Telegram)
SENTRYWATCH_WEBHOOK_URL="https://ntfy.sh/your_custom_topic_name"

# Optional: Firewall adapter (simulated, iptables, nftables)
SENTRYWATCH_FIREWALL="simulated"

# Optional: Dry-run mode (true / false)
SENTRYWATCH_DRY_RUN="true"
```

---

## Environment Variables Reference

| Variable | Description | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Claude API key for advisory scoring | `None` (Heuristic Fallback) |
| `SENTRYWATCH_WEBHOOK_URL` | Webhook URL for push notifications | `None` |
| `SENTRYWATCH_DB` | Path to SQLite database | `sentrywatch.db` |
| `SENTRYWATCH_DRY_RUN` | Enable dry-run mode (`true`/`false`) | `true` |
| `SENTRYWATCH_FIREWALL` | Firewall adapter (`simulated`, `iptables`, `nftables`) | `simulated` |

---

## Usage Guide

### 1. Run Attack Simulator & Detection Daemon
```bash
python -m sentrywatch daemon --simulate
```

### 2. Launch Interactive Terminal UI (Rich TUI)
```bash
python -m sentrywatch tui
```

### 3. Test Notification Triggers & Webhook Dispatch
```bash
# Trigger notification via severity score threshold
python -m sentrywatch simulate-incident --type brute_force --ip 10.0.0.5 --severity 90

# Trigger notification via consider_block recommendation
python -m sentrywatch simulate-incident --type priv_esc --recommended-action consider_block --severity 30

# Test enforced block trigger
python -m sentrywatch simulate-incident --type port_scan --ip 203.0.113.88 --severity 40 --enforce
```

### 4. Verify Audit Log Integrity
```bash
python -m sentrywatch audit verify
```

### 5. Display Active Configuration & Rules
```bash
python -m sentrywatch config
```

---

## Automated Test Suite

Run full test suite (15 unit tests):

```bash
python -m pytest tests/ -v
```

---

## License
MIT License.

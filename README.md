# Feedly Cyber Attacks Agent → OpenCTI Integration

Fetches cyber attack intelligence from your **Feedly Cyber Attacks Agent** and imports it into **OpenCTI** as a fully linked STIX2 graph — Incidents, Threat Actors, Malware, Attack Patterns, and Locations, with relationships between them.

---

## How It Works

1. Calls the Feedly Cyber Attacks Agent API (`POST /v3/ml/relationships/cyber-attacks/dashboard/table`) for a given time period and optional filters.
2. For each attack record, extracts:
   - Title, description, and date
   - Attack types (Ransomware, Data Breach, Phishing, etc.)
   - Threat actor names and metadata
   - Malware families used
   - Victim countries and industries
   - Source article URLs for external references
3. Creates linked STIX2 objects in OpenCTI:
   - **Incident** — one per attack record
   - **Threat Actor** — deduplicated across the sync run
   - **Malware** — deduplicated across the sync run
   - **Attack Pattern** — one per distinct attack type
   - **Location** — one per victim country
4. Creates **relationships** between the objects:
   - `Incident` → `attributed-to` → `Threat Actor`
   - `Incident` → `uses` → `Malware`
   - `Incident` → `uses` → `Attack Pattern`
   - `Incident` → `targets` → `Location`
   - `Threat Actor` → `uses` → `Malware`
5. Optionally creates a **Report** in OpenCTI bundling all objects from the sync run.
6. Persists a state file so repeated runs remember the last-used period.

---

## Requirements

- Python 3.8+
- Feedly Enterprise account with **Cyber Attacks Agent** access
- OpenCTI instance (v5.9+) with a user token that has connector permissions

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

### Option 1 — Config file (recommended)

Copy the template and fill in your values:

```bash
cp config.yaml.template config.yaml
```

Edit `config.yaml`:

```yaml
feedly:
  api_key: "YOUR_FEEDLY_API_KEY"
  period: "Last7Days"

opencti:
  url: "https://your-opencti-instance"
  token: "YOUR_OPENCTI_API_TOKEN"
  create_report: false

sync:
  daemon: false
  interval: 1440
```

### Option 2 — Environment variables

```bash
export FEEDLY_API_KEY="your_feedly_api_key"
export OPENCTI_URL="https://your-opencti-instance"
export OPENCTI_TOKEN="your_opencti_token"
```

Or place them in a `.env` file in the same directory:

```
FEEDLY_API_KEY=your_feedly_api_key
OPENCTI_URL=https://your-opencti-instance
OPENCTI_TOKEN=your_opencti_token
```

### Option 3 — CLI flags

All configuration values can be passed directly on the command line (see [CLI Reference](#cli-reference)).

---

## Usage

### Dry run (preview — no changes written to OpenCTI)

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py --dry-run -v
```

### One-shot sync (last 7 days)

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py --period Last7Days
```

### Filter by attack type

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py \
  --period Last30Days \
  --attack-type Ransomware
```

### Filter by victim country

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py \
  --period Last7Days \
  --victim-country US
```

### Filter by threat actor

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py \
  --threat-actor "LockBit" \
  --period Last3Months
```

### Filter by victim continent

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py \
  --period Last7Days \
  --victim-continent "nlp/f/entity/gz:loc:46"
```

### Sync and create a summary Report

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py \
  --period Last30Days \
  --create-report
```

### Daemon mode (run every 24 hours)

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py \
  --daemon \
  --interval 1440
```

### Using a config file

```bash
python Feedly_CyberAttacks_Agent_OpenCTI.py --config config.yaml
```

---

## CLI Reference

```
usage: Feedly_CyberAttacks_Agent_OpenCTI.py [options]

Feedly:
  --feedly-api-key KEY          Feedly API key
  --period PERIOD               Time period: Last24Hours, Last7Days, Last30Days,
                                Last3Months, Last6Months, LastYear (default: Last7Days)
  --attack-type TYPE            Filter by attack type (see Attack Types below)
  --threat-actor ACTOR          Filter by threat actor name or Feedly entity ID
  --malware-family MALWARE      Filter by malware family name or Feedly entity ID
  --victim-country CODE         Filter by victim country (ISO 3166-1 alpha-2, e.g. US, GB)
  --victim-industry INDUSTRY    Filter by victim industry (Feedly entity ID or label)
  --victim-continent ENTITY_ID  Filter by victim continent (Feedly entity ID)
  --max-results N               Maximum attack records per sync cycle (default: 500)

OpenCTI:
  --opencti-url URL             OpenCTI platform URL
  --opencti-token TOKEN         OpenCTI API token
  --create-report               Create a summary threat-report linking all imported objects

Automation:
  --daemon                      Run continuously on a fixed interval
  --interval MINUTES            Interval between daemon cycles (default: 1440)

General:
  --dry-run                     Preview actions without writing to OpenCTI
  --state-file FILE             Path to sync state JSON file
                                (default: feedly_opencti_cyber_attacks_state.json)
  --config FILE                 YAML config file (default: config.yaml)
  -v, --verbose                 Enable debug output
```

---

## Attack Types

| CLI value | Description |
|-----------|-------------|
| `Ransomware` | Ransomware attacks |
| `DataBreachesAndExfiltration` | Data breaches and exfiltration |
| `DenialOfService` | Denial of Service / DDoS |
| `PhishingAndSocialEngineering` | Phishing and social engineering |
| `SupplyChainAttack` | Supply chain compromise |
| `ZeroDay` | Zero-day exploits |
| `APT` | Advanced Persistent Threat campaigns |
| `Cryptojacking` | Cryptojacking / illicit mining |
| `Espionage` | Cyber espionage |
| `Sabotage` | Destructive / sabotage attacks |
| `Wiper` | Wiper malware attacks |
| `BEC` | Business Email Compromise |

---

## What Gets Created in OpenCTI

| STIX2 Object | Fields populated |
|---|---|
| `Incident` | `name`, `description`, `incident_type`, `first_seen`, `last_seen`, `confidence`, external references |
| `Threat Actor` | `name`, `description`, `confidence` |
| `Malware` | `name`, `description`, `confidence` |
| `Attack Pattern` | `name`, `description`, `confidence` |
| `Location` | `name`, `description`, `country` (ISO code), `x_opencti_location_type` |
| `Report` *(optional)* | `name`, `description`, `published`, `report_types`, linked object refs |

### Relationships Created

| From | Relationship | To |
|---|---|---|
| `Incident` | `attributed-to` | `Threat Actor` |
| `Incident` | `uses` | `Malware` |
| `Incident` | `uses` | `Attack Pattern` |
| `Incident` | `targets` | `Location` |
| `Threat Actor` | `uses` | `Malware` |

---

## OpenCTI Setup

1. Go to **Settings → Security → Users** and create a dedicated connector user (e.g., `feedly-connector`).
2. Add the user to the **Connectors** group.
3. Copy the API token from the user's profile page.
4. Set `opencti.token` in `config.yaml` or the `OPENCTI_TOKEN` environment variable.

---

## State and Incremental Sync

The script writes a `feedly_opencti_cyber_attacks_state.json` file after each successful sync (path configurable via `--state-file`). It stores the last-used period so daemon runs stay consistent between restarts.

Delete or reset this file to start fresh.

---

## Scheduling with Cron

Instead of daemon mode, you can schedule the script via cron:

```cron
# Sync daily at 06:00
0 6 * * * /usr/bin/python3 /opt/feedly-opencti/Feedly_CyberAttacks_Agent_OpenCTI.py \
  --config /opt/feedly-opencti/config.yaml \
  >> /var/log/feedly_opencti_cyber_attacks.log 2>&1
```

---

## Troubleshooting

| Symptom | Resolution |
|---------|-----------|
| `403 Forbidden` from Feedly | Check your API key and confirm your account has Cyber Attacks Agent access |
| `401 Unauthorized` from OpenCTI | Verify the token and that the user belongs to the Connectors group |
| No records returned | Try a wider period (e.g. `Last30Days`) or remove filters to confirm data is available |
| Empty `items` in response | Your account may not have Cyber Attacks Agent access — contact Feedly support |
| `pycti` import error | Run `pip install "pycti>=5.9.6"` |
| Duplicate objects in OpenCTI | Expected — `create()` calls in pycti upsert by name, so re-runs are safe |

---

## License

© 2025 Feedly, Inc. All rights reserved. See the script header for the full disclaimer.

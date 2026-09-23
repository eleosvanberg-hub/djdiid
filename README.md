# SSN Dorker — ValueSERP Edition

> **Authorized security research and privacy audits only.**  
> Misuse for identity theft, unauthorised access, or any illegal purpose is strictly prohibited.

A powerful Google-dork OSINT tool that uses the [ValueSERP API](https://www.valueserp.com) to discover websites that expose, aggregate, or sell Social Security Number data — built for penetration testers, privacy auditors, and breach researchers.

---

## Features

| Feature | Details |
|---|---|
| **10 dork categories** | SSN lookup, data brokers, exposed DBs, breach dumps, API leaks, directory listings, error disclosures, identity-theft marketplaces, and more |
| **60+ built-in dork templates** | Covering file types (`sql`, `csv`, `xls`, `txt`, `json`), URL patterns, title patterns, and domain constraints |
| **Custom dork queries** | Supply your own dorks via `--custom-queries` |
| **Risk scoring engine** | Every result gets a 0–100 severity score (Critical / High / Medium / Low / Info) |
| **Benign-domain filter** | Auto-suppresses results from `ssa.gov`, `irs.gov`, Reddit, GitHub, etc. |
| **4 export formats** | JSON, CSV, HTML (dark-themed report), plain TXT |
| **Progress bar** | Live rich terminal progress with per-category updates |
| **Severity breakdown** | Bar-chart breakdown of result distribution |
| **Interactive mode** | Guided category + option selection with no CLI flags needed |
| **Proxy support** | Route all requests through an HTTP/HTTPS proxy |
| **Rate-limit safe** | Configurable per-request delay |
| **Verbose logging** | Per-session log files in `logs/` |
| **Persistent config** | API key stored in `~/.ssn_dorker.env` |

---

## Installation

```bash
git clone <repo>
cd djdiid
pip install -r requirements.txt
```

---

## Quick Start

### 1. Save your ValueSERP API key
```bash
python ssn_dorker.py --set-api-key YOUR_KEY_HERE
```
Or copy `.env.example` → `.env` and fill in `VALUESERP_API_KEY`.

### 2. Interactive guided mode (recommended first run)
```bash
python ssn_dorker.py --interactive
```

### 3. Run all categories, export everything
```bash
python ssn_dorker.py --all --export all --output ./results
```

---

## CLI Reference

```
python ssn_dorker.py [OPTIONS]

API / Config
  --api-key KEY         ValueSERP API key (overrides env/config)
  --set-api-key KEY     Save key to ~/.ssn_dorker.env and exit

Category Selection
  --all                 Run all 10 dork categories
  -c CAT[,CAT]          Run specific comma-separated categories
  --list-categories     Print category list and exit
  --custom-queries Q…   One or more raw Google dork strings

Search Tuning
  --pages N             Pages per query (default: 3)
  --delay S             Seconds between requests (default: 1.5)
  --country CC          Google country code (default: us)
  --language LC         Language code (default: en)
  --num N               Results per page up to 100

Filtering
  --min-score N         Minimum risk score 0-100 (default: 0)
  --strict-filter       Drop known-benign domains from output
  --only-severity LVL   critical | high | medium | low | info
  --domain-filter D…    Restrict results to listed domains

Output
  --export FMT          json | csv | html | txt | all | none
  --output DIR          Directory for exported files (default: ./results)
  --no-print            Suppress terminal result table
  --top N               Print only top N results

Modes
  --interactive         Guided interactive session
  --verbose             Debug logging to stdout + log file
  --version             Print version and exit
```

---

## Dork Categories

| Category | Dorks | What it finds |
|---|---|---|
| `ssn_lookup` | 6 | Live SSN lookup/search services |
| `data_brokers` | 6 | People-search & background-check sites |
| `exposed_databases` | 6 | Public SQL/CSV/XLS/JSON dumps with SSN fields |
| `identity_theft` | 4 | Sites selling/buying SSN "fullz" |
| `breach_data` | 5 | Paste sites & breach downloads |
| `api_endpoints` | 4 | REST/Swagger APIs exposing SSN endpoints |
| `directory_listings` | 3 | Open directory listings with SSN files |
| `error_disclosures` | 3 | SQL/stack-trace error pages leaking SSNs |
| `government_adjacent` | 3 | Non-gov lookalike SSN services |
| `dark_web_clearnet` | 3 | Clearnet references to dark-web SSN markets |

---

## Risk Scoring

Each result is scored 0–100 based on keyword matches in title, URL, and snippet:

| Severity | Score | Typical indicators |
|---|---|---|
| **CRITICAL** | 40–100 | "buy ssn", "sell ssn", "fullz", "ssn dump" |
| **HIGH** | 20–39 | "ssn lookup", "ssn search", "full info", "breach" |
| **MEDIUM** | 10–19 | "background check", "data broker", "people search" |
| **LOW** | 5–9 | "ssn verify", "ssn check", employment verification |
| **INFO** | 0–4 | Benign or unclear context |

---

## Output Files

All exports land in `./results/` (or `--output DIR`) with timestamp prefix:

```
results/
  ssn_dork_20260923_143022.json   ← full structured data + metadata
  ssn_dork_20260923_143022.csv    ← spreadsheet-ready flat file
  ssn_dork_20260923_143022.html   ← dark-themed clickable report
  ssn_dork_20260923_143022.txt    ← plain text for easy grep/sharing
logs/
  ssn_dorker_20260923_143022.log  ← per-session debug log
```

---

## Legal Notice

This tool is intended solely for:
- Authorized penetration tests and security assessments
- Privacy audits commissioned by the data owner
- Academic / breach research with appropriate ethics approval
- Personal exposure monitoring

Do **not** use this tool to locate SSN data for identity theft, fraud, stalking, or any other illegal purpose. The author assumes no liability for misuse.

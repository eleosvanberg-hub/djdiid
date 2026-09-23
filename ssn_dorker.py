#!/usr/bin/env python3
"""
SSN Dorker — ValueSERP-powered OSINT tool for security researchers
Authorized use only: penetration testing, privacy audits, breach research.
"""

import os
import sys
import json
import csv
import time
import logging
import hashlib
import re
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, quote_plus
from collections import defaultdict

import requests
import tldextract
from dotenv import load_dotenv, set_key

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.style import Style
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import pyfiglet
    FIGLET_AVAILABLE = True
except ImportError:
    FIGLET_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

VERSION = "2.1.0"
CONFIG_FILE = Path.home() / ".ssn_dorker.env"
LOG_DIR = Path("logs")
RESULTS_DIR = Path("results")
VALUESERP_BASE = "https://api.valueserp.com/search"

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          SSN DORKER  v{ver}  —  ValueSERP Edition          ║
║    OSINT · Security Research · Privacy Audit · Breach Hunt   ║
╚══════════════════════════════════════════════════════════════╝
  ⚠  For authorized security research and privacy audits only.
""".format(ver=VERSION)

TG_API_BASE = "https://api.telegram.org/bot{token}/{method}"
# Severity → emoji mapping used in Telegram messages
SEV_EMOJI = {
    "critical": "🚨",
    "high":     "⚠️",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "ℹ️",
}

# Dork categories ──────────────────────────────────────────────
DORK_TEMPLATES = {
    "ssn_lookup": [
        'intitle:"SSN lookup" OR intitle:"social security lookup"',
        'inurl:"ssn" site:.com "lookup" "social security number"',
        '"social security number" "lookup" "free" -site:ssa.gov',
        'intitle:"find SSN" OR intitle:"SSN search" "social security"',
        '"ssn lookup" OR "ssn search" filetype:html',
        'inurl:"ssn-lookup" OR inurl:"ssn_lookup" OR inurl:"ssn/lookup"',
    ],
    "data_brokers": [
        '"social security number" "background check" "full name" inurl:search',
        '"ssn" "date of birth" "address history" site:.com -site:ssa.gov',
        'intitle:"people search" "ssn" "social security"',
        '"find anyone" "ssn" "social security number" OR "SSN"',
        '"background check" "SSN" "full report" -site:gov',
        'inurl:"people-search" OR inurl:"people_search" "social security"',
    ],
    "exposed_databases": [
        'filetype:sql "social_security" OR "ssn" OR "social_security_number"',
        'filetype:csv "ssn" "first_name" "last_name" "date_of_birth"',
        'filetype:xls "social security number" "SSN" "dob"',
        'filetype:txt "###-##-####" "ssn" OR "social security"',
        'ext:log "social security" OR "ssn" "###-##-####"',
        'intext:"social_security_number" filetype:json OR filetype:xml',
    ],
    "identity_theft": [
        '"buy ssn" OR "sell ssn" OR "ssn for sale" -site:gov',
        '"full info" "ssn" "dob" "address" site:.com -site:ssa.gov',
        '"ssn" "fullz" OR "full info" "credit card"',
        'inurl:"ssn" "purchase" OR "buy" "social security number"',
    ],
    "breach_data": [
        '"social security" "leaked" OR "breached" OR "exposed" filetype:txt',
        '"ssn" site:pastebin.com OR site:ghostbin.com OR site:hastebin.com',
        '"social security number" "data breach" "download"',
        '"ssn dump" OR "ssn leak" -site:gov -site:edu',
        'site:ghostbin.co OR site:paste.ee "social security" OR "ssn"',
    ],
    "api_endpoints": [
        'inurl:"api" "ssn" "social_security" filetype:json',
        'inurl:"/api/v" "ssn" OR "social_security_number"',
        'intext:"ssn" inurl:"swagger" OR inurl:"api-docs"',
        '"ssn_verification" OR "ssn_lookup" inurl:api',
    ],
    "directory_listings": [
        'intitle:"index of" "ssn" OR "social_security" filetype:csv OR filetype:xls',
        'intitle:"index of /" "ssn" "database"',
        'intitle:"directory listing" "social security" OR "ssn"',
    ],
    "error_disclosures": [
        'intext:"ssn" "sql syntax" OR "mysql error" OR "database error"',
        '"social_security_number" "ORA-" OR "MySQL" site:.com',
        '"ssn" "exception" "stack trace" "social security"',
    ],
    "government_adjacent": [
        '"social security" "ssn" -site:ssa.gov -site:gov "lookup" "search"',
        'inurl:"ssn-check" OR inurl:"verify-ssn" OR inurl:"ssn-verify"',
        '"verify social security number" "online" "instant"',
    ],
    "dark_web_clearnet": [
        '"ssn" "onion" OR ".onion" "social security" site:.com',
        '"deep web" "ssn" "social security" "find"',
        '"ssn" "dark web" "purchase" OR "lookup" -site:gov',
    ],
}

RISK_KEYWORDS = {
    "critical": ["buy ssn", "sell ssn", "ssn for sale", "fullz", "ssn dump", "ssn leak", "dark web"],
    "high":     ["ssn lookup", "ssn search", "social security lookup", "full info", "breach", "leaked"],
    "medium":   ["background check", "people search", "find anyone", "data broker", "directory"],
    "low":      ["ssn verify", "ssn check", "validation", "tax", "employment"],
}

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "yellow",
    "low":      "green",
    "info":     "cyan",
}

BENIGN_DOMAINS = {
    "ssa.gov", "irs.gov", "usa.gov", "dhs.gov", "ftc.gov",
    "consumer.ftc.gov", "identitytheft.gov", "annualcreditreport.com",
    "reddit.com", "stackoverflow.com", "github.com", "wikipedia.org",
    "nolo.com", "bankrate.com", "nerdwallet.com",
}


# ─────────────────────────────────────────────────────────────
# Console / Logging helpers
# ─────────────────────────────────────────────────────────────

console = Console() if RICH_AVAILABLE else None


def cprint(msg, style=""):
    if RICH_AVAILABLE:
        console.print(msg, style=style)
    else:
        print(msg)


def setup_logging(verbose: bool = False) -> logging.Logger:
    LOG_DIR.mkdir(exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = LOG_DIR / f"ssn_dorker_{stamp}.log"

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout) if verbose else logging.NullHandler(),
        ],
    )
    return logging.getLogger("ssn_dorker")


# ─────────────────────────────────────────────────────────────
# Configuration management
# ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    load_dotenv(CONFIG_FILE)
    load_dotenv()  # also read .env in cwd
    return {
        "api_key":        os.getenv("VALUESERP_API_KEY", ""),
        "default_pages":  int(os.getenv("DORKER_PAGES", "3")),
        "delay":          float(os.getenv("DORKER_DELAY", "1.5")),
        "proxy":          os.getenv("DORKER_PROXY", ""),
        "country":        os.getenv("DORKER_COUNTRY", "us"),
        "language":       os.getenv("DORKER_LANGUAGE", "en"),
        "safe":           os.getenv("DORKER_SAFE", "off"),
        "timeout":        int(os.getenv("DORKER_TIMEOUT", "30")),
        # Telegram
        "tg_bot_token":   os.getenv("TG_BOT_TOKEN", ""),
        "tg_chat_id":     os.getenv("TG_CHAT_ID", ""),
        "tg_min_score":   int(os.getenv("TG_MIN_SCORE", "0")),
        "tg_send_files":  os.getenv("TG_SEND_FILES", "true").lower() == "true",
    }


def save_api_key(api_key: str):
    CONFIG_FILE.touch(mode=0o600)
    set_key(str(CONFIG_FILE), "VALUESERP_API_KEY", api_key)
    cprint(f"[green]API key saved to {CONFIG_FILE}[/green]")


def save_tg_token(token: str):
    CONFIG_FILE.touch(mode=0o600)
    set_key(str(CONFIG_FILE), "TG_BOT_TOKEN", token)
    cprint(f"[green]Telegram bot token saved to {CONFIG_FILE}[/green]")


def save_tg_chat_id(chat_id: str):
    CONFIG_FILE.touch(mode=0o600)
    set_key(str(CONFIG_FILE), "TG_CHAT_ID", chat_id)
    cprint(f"[green]Telegram chat ID saved to {CONFIG_FILE}[/green]")


def prompt_api_key() -> str:
    if RICH_AVAILABLE:
        key = Prompt.ask("[bold cyan]Enter your ValueSERP API key[/bold cyan]")
    else:
        key = input("Enter your ValueSERP API key: ").strip()
    if key:
        save_api_key(key)
    return key


# ─────────────────────────────────────────────────────────────
# Risk scoring
# ─────────────────────────────────────────────────────────────

def score_result(result: dict) -> tuple[str, int]:
    """Return (severity_label, numeric_score)."""
    combined = " ".join([
        result.get("title", ""),
        result.get("snippet", ""),
        result.get("url", ""),
    ]).lower()

    score = 0
    severity = "info"

    for level, keywords in RISK_KEYWORDS.items():
        for kw in keywords:
            if kw in combined:
                if level == "critical":
                    score += 40
                    severity = "critical"
                elif level == "high":
                    score += 20
                    if severity not in ("critical",):
                        severity = "high"
                elif level == "medium":
                    score += 10
                    if severity not in ("critical", "high"):
                        severity = "medium"
                elif level == "low":
                    score += 5
                    if severity == "info":
                        severity = "low"

    # Penalise benign domains
    ext = tldextract.extract(result.get("url", ""))
    domain = f"{ext.domain}.{ext.suffix}"
    if domain in BENIGN_DOMAINS:
        score = max(0, score - 50)
        severity = "info"

    return severity, min(score, 100)


# ─────────────────────────────────────────────────────────────
# ValueSERP API client
# ─────────────────────────────────────────────────────────────

class ValueSERPClient:
    def __init__(self, api_key: str, config: dict, logger: logging.Logger):
        self.api_key = api_key
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": f"SSN-Dorker/{VERSION}"})
        if config.get("proxy"):
            self.session.proxies = {
                "http":  config["proxy"],
                "https": config["proxy"],
            }
        self._call_count = 0

    def search(self, query: str, page: int = 1, num: int = 100) -> dict:
        params = {
            "api_key":  self.api_key,
            "q":        query,
            "num":      num,
            "page":     page,
            "gl":       self.config.get("country", "us"),
            "hl":       self.config.get("language", "en"),
            "safe":     self.config.get("safe", "off"),
            "output":   "json",
        }
        self._call_count += 1
        self.logger.debug("API call #%d: %s (page %d)", self._call_count, query[:80], page)
        try:
            resp = self.session.get(
                VALUESERP_BASE,
                params=params,
                timeout=self.config.get("timeout", 30),
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            self.logger.error("Request timed out for query: %s", query)
            return {}
        except requests.exceptions.HTTPError as e:
            self.logger.error("HTTP error %s for query: %s", e.response.status_code, query)
            return {}
        except Exception as e:
            self.logger.error("Unexpected error: %s", e)
            return {}

    @property
    def total_calls(self) -> int:
        return self._call_count


# ─────────────────────────────────────────────────────────────
# Result processing
# ─────────────────────────────────────────────────────────────

def extract_results(raw: dict) -> list[dict]:
    results = []
    for item in raw.get("organic_results", []):
        results.append({
            "title":     item.get("title", ""),
            "url":       item.get("link", ""),
            "snippet":   item.get("snippet", ""),
            "domain":    tldextract.extract(item.get("link", "")).registered_domain,
            "position":  item.get("position", 0),
        })
    return results


def deduplicate(results: list[dict]) -> list[dict]:
    seen: set[str] = set()
    unique = []
    for r in results:
        key = hashlib.md5(r["url"].encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def filter_benign(results: list[dict], strict: bool = False) -> list[dict]:
    if not strict:
        return results
    return [r for r in results if r["domain"] not in BENIGN_DOMAINS]


# ─────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────

def print_banner():
    if RICH_AVAILABLE:
        if FIGLET_AVAILABLE:
            fig = pyfiglet.figlet_format("SSN DORKER", font="slant")
            console.print(f"[bold red]{fig}[/bold red]")
        console.print(Panel(
            "[bold white]ValueSERP-Powered SSN Site Discoverer[/bold white]\n"
            "[dim]Version " + VERSION + "  |  OSINT & Security Research[/dim]\n"
            "[bold red]⚠  Authorized Use Only — Penetration Testing / Privacy Audits[/bold red]",
            border_style="red",
            expand=False,
        ))
    else:
        print(BANNER)


def print_result_table(results: list[dict], title: str = "Results"):
    if not RICH_AVAILABLE:
        for i, r in enumerate(results, 1):
            sev, score = score_result(r)
            print(f"[{i}] [{sev.upper()}:{score}] {r['title']}")
            print(f"     {r['url']}")
            print(f"     {r['snippet'][:100]}")
        return

    table = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
        highlight=True,
    )
    table.add_column("#",       style="dim",          width=4)
    table.add_column("Risk",    style="bold",         width=9)
    table.add_column("Score",   justify="center",     width=7)
    table.add_column("Title",   style="bold white",   ratio=2, no_wrap=False)
    table.add_column("URL",     style="cyan",         ratio=3, no_wrap=True)
    table.add_column("Domain",  style="yellow",       width=22)

    for i, r in enumerate(results, 1):
        sev, score = score_result(r)
        r["severity"] = sev
        r["risk_score"] = score
        color = SEVERITY_COLORS.get(sev, "white")
        bar = "█" * (score // 10) + "░" * (10 - score // 10)
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            f"[{color}]{score:3d}[/{color}]  {bar}",
            r["title"][:90],
            r["url"][:120],
            r["domain"],
        )

    console.print(table)


def print_stats(stats: dict):
    if not RICH_AVAILABLE:
        print("\n=== STATS ===")
        for k, v in stats.items():
            print(f"  {k}: {v}")
        return

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Metric", style="bold cyan", min_width=25)
    table.add_column("Value",  style="bold white")

    for k, v in stats.items():
        table.add_row(k, str(v))

    console.print(Panel(table, title="[bold]Session Statistics[/bold]", border_style="cyan"))


def print_severity_breakdown(results: list[dict]):
    if not RICH_AVAILABLE:
        return
    counts: defaultdict[str, int] = defaultdict(int)
    for r in results:
        counts[r.get("severity", "info")] += 1

    table = Table(box=box.SIMPLE, show_header=True)
    table.add_column("Severity",   style="bold", width=12)
    table.add_column("Count",      justify="right", width=8)
    table.add_column("Bar",        width=30)

    total = sum(counts.values()) or 1
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = counts[sev]
        bar_len = int((cnt / total) * 28)
        bar = "█" * bar_len
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            f"[{color}]{cnt}[/{color}]",
            f"[{color}]{bar}[/{color}]",
        )

    console.print(Panel(table, title="[bold]Severity Breakdown[/bold]", border_style="yellow"))


# ─────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────

def export_json(results: list[dict], path: Path, meta: dict):
    payload = {"meta": meta, "results": results}
    path.write_text(json.dumps(payload, indent=2))
    cprint(f"[green]JSON saved → {path}[/green]")


def export_csv(results: list[dict], path: Path):
    if not results:
        return
    fields = ["severity", "risk_score", "title", "url", "domain", "snippet", "position"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)
    cprint(f"[green]CSV saved  → {path}[/green]")


def export_html(results: list[dict], path: Path, meta: dict):
    rows = ""
    for r in results:
        sev = r.get("severity", "info")
        score = r.get("risk_score", 0)
        color_map = {
            "critical": "#ff4444",
            "high":     "#ffaa00",
            "medium":   "#ffee00",
            "low":      "#44ff44",
            "info":     "#aaaaaa",
        }
        col = color_map.get(sev, "#aaa")
        rows += f"""
        <tr>
          <td style="color:{col};font-weight:bold">{sev.upper()}</td>
          <td style="color:{col}">{score}</td>
          <td><a href="{r['url']}" target="_blank">{r['title'][:80]}</a></td>
          <td style="font-size:0.85em;color:#aaa">{r['domain']}</td>
          <td style="font-size:0.8em">{r['snippet'][:120]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SSN Dorker Results — {meta.get('timestamp','')}</title>
  <style>
    body {{background:#0d0d0d;color:#e0e0e0;font-family:monospace;padding:20px}}
    h1   {{color:#ff4444}}
    p    {{color:#888;font-size:0.9em}}
    table{{border-collapse:collapse;width:100%}}
    th   {{background:#1a1a1a;color:#ff4444;padding:8px;text-align:left;border-bottom:2px solid #333}}
    td   {{padding:6px 8px;border-bottom:1px solid #222;vertical-align:top}}
    tr:hover td{{background:#1a1a1a}}
    a    {{color:#4fc3f7;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    .meta{{background:#111;padding:12px;border-left:4px solid #ff4444;margin-bottom:20px}}
  </style>
</head>
<body>
  <h1>SSN Dorker — Results Report</h1>
  <div class="meta">
    <strong>Timestamp:</strong> {meta.get('timestamp','')} |
    <strong>Queries run:</strong> {meta.get('queries_run',0)} |
    <strong>Total results:</strong> {meta.get('total_results',0)} |
    <strong>Unique domains:</strong> {meta.get('unique_domains',0)}
  </div>
  <table>
    <tr><th>Risk</th><th>Score</th><th>Title</th><th>Domain</th><th>Snippet</th></tr>
    {rows}
  </table>
  <p style="margin-top:20px">Generated by SSN Dorker v{VERSION} — Authorized Security Research Only</p>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    cprint(f"[green]HTML saved → {path}[/green]")


def export_txt(results: list[dict], path: Path, meta: dict):
    lines = [
        f"SSN Dorker — Results Report  [{meta.get('timestamp','')}]",
        "=" * 70,
        f"Queries run   : {meta.get('queries_run',0)}",
        f"Total results : {meta.get('total_results',0)}",
        f"Unique domains: {meta.get('unique_domains',0)}",
        "=" * 70,
        "",
    ]
    for i, r in enumerate(results, 1):
        lines += [
            f"[{i:03d}] {r.get('severity','info').upper()} | Score: {r.get('risk_score',0)}",
            f"      Title  : {r['title']}",
            f"      URL    : {r['url']}",
            f"      Domain : {r['domain']}",
            f"      Snippet: {r['snippet'][:150]}",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")
    cprint(f"[green]TXT saved  → {path}[/green]")


# ─────────────────────────────────────────────────────────────
# Telegram notifier
# ─────────────────────────────────────────────────────────────

class TelegramNotifier:
    """Send real-time dork findings and session summaries to a Telegram chat."""

    def __init__(self, bot_token: str, chat_id: str, logger: logging.Logger,
                 proxy: str = "", min_score: int = 0):
        self.bot_token = bot_token.strip()
        self.chat_id   = str(chat_id).strip()
        self.logger    = logger
        self.min_score = min_score
        self._session  = requests.Session()
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}
        self._last_send = 0.0      # unix timestamp of last message sent
        self._send_interval = 1.1  # stay comfortably under Telegram's 1 msg/s limit
        self._ok = False           # set True after a successful test

    # ── Low-level helpers ─────────────────────────────────────

    def _url(self, method: str) -> str:
        return TG_API_BASE.format(token=self.bot_token, method=method)

    def _throttle(self):
        """Ensure we never send faster than _send_interval seconds."""
        elapsed = time.time() - self._last_send
        if elapsed < self._send_interval:
            time.sleep(self._send_interval - elapsed)
        self._last_send = time.time()

    def _post(self, method: str, **kwargs) -> dict:
        self._throttle()
        try:
            resp = self._session.post(self._url(method), timeout=15, **kwargs)
            data = resp.json()
            if not data.get("ok"):
                self.logger.warning("Telegram API error (%s): %s", method, data.get("description"))
            return data
        except Exception as e:
            self.logger.error("Telegram request failed (%s): %s", method, e)
            return {}

    @staticmethod
    def _escape(text: str) -> str:
        """Escape special chars for Telegram HTML parse mode."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))

    @staticmethod
    def _chunk(text: str, size: int = 4000) -> list[str]:
        """Split text into chunks that fit within Telegram's 4096-char limit."""
        return [text[i:i + size] for i in range(0, len(text), size)]

    # ── Public API ────────────────────────────────────────────

    def send_message(self, html: str, silent: bool = False) -> bool:
        """Send an HTML-formatted message, splitting if over 4000 chars."""
        chunks = self._chunk(html)
        success = True
        for i, chunk in enumerate(chunks):
            data = self._post(
                "sendMessage",
                data={
                    "chat_id":                  self.chat_id,
                    "text":                     chunk,
                    "parse_mode":               "HTML",
                    "disable_web_page_preview": True,
                    "disable_notification":     silent,
                },
            )
            if not data.get("ok"):
                success = False
        return success

    def send_document(self, path: Path, caption: str = "") -> bool:
        """Upload a file as a Telegram document."""
        if not path.exists():
            self.logger.warning("TG send_document: file not found: %s", path)
            return False
        self._throttle()
        try:
            with path.open("rb") as fh:
                data = self._post(
                    "sendDocument",
                    data={
                        "chat_id":    self.chat_id,
                        "caption":    caption[:1024],
                        "parse_mode": "HTML",
                    },
                    files={"document": (path.name, fh)},
                )
            return data.get("ok", False)
        except Exception as e:
            self.logger.error("Telegram send_document failed: %s", e)
            return False

    def test(self) -> bool:
        """Verify credentials by calling getMe and sending a test ping."""
        data = self._post("getMe")
        if not data.get("ok"):
            cprint("[red]Telegram: getMe failed — check bot token.[/red]")
            return False
        bot_name = data.get("result", {}).get("username", "?")
        ok = self.send_message(
            f"🤖 <b>SSN Dorker v{VERSION}</b> connected\n"
            f"Bot: @{self._escape(bot_name)}\n"
            f"Chat ID: <code>{self._escape(self.chat_id)}</code>\n"
            f"<i>Notifications are active.</i>"
        )
        if ok:
            self._ok = True
            cprint(f"[green]Telegram: connected as @{bot_name}[/green]")
        return ok

    # ── Structured event messages ─────────────────────────────

    def send_scan_start(self, categories: list[str], pages: int, total_queries: int):
        cat_str = ", ".join(f"<code>{self._escape(c)}</code>" for c in categories[:8])
        if len(categories) > 8:
            cat_str += f" +{len(categories) - 8} more"
        self.send_message(
            f"🔍 <b>SSN Dorker — Scan Started</b>\n\n"
            f"📂 <b>Categories:</b> {cat_str}\n"
            f"📄 <b>Pages/query:</b> {pages}\n"
            f"🔢 <b>Total queries:</b> {total_queries}\n"
            f"🕐 <b>Started:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            silent=True,
        )

    def send_result(self, result: dict):
        """Send a single finding if it meets the minimum score threshold."""
        score = result.get("risk_score", 0)
        if score < self.min_score:
            return
        sev   = result.get("severity", "info")
        emoji = SEV_EMOJI.get(sev, "ℹ️")
        title   = self._escape(result.get("title", "")[:120])
        url     = self._escape(result.get("url", "")[:200])
        domain  = self._escape(result.get("domain", ""))
        snippet = self._escape(result.get("snippet", "")[:200])
        dork    = self._escape(result.get("dork_query", "")[:100])

        self.send_message(
            f"{emoji} <b>{sev.upper()}</b>  |  Score: <b>{score}</b>\n\n"
            f"📌 <b>Title:</b> {title}\n"
            f"🔗 <b>URL:</b> <a href=\"{url}\">{url}</a>\n"
            f"🌐 <b>Domain:</b> <code>{domain}</code>\n"
            f"📄 <b>Snippet:</b> <i>{snippet}</i>\n"
            f"🔎 <b>Dork:</b> <code>{dork}</code>"
        )

    def send_summary(self, results: list[dict], meta: dict, exported_files: list[Path]):
        """Send a final summary message and optionally attach exported files."""
        counts: defaultdict[str, int] = defaultdict(int)
        for r in results:
            counts[r.get("severity", "info")] += 1

        sev_lines = "  ".join(
            f"{SEV_EMOJI[s]} {s.capitalize()}: <b>{counts[s]}</b>"
            for s in ("critical", "high", "medium", "low", "info")
            if counts[s]
        )

        self.send_message(
            f"✅ <b>SSN Dorker — Scan Complete</b>\n\n"
            f"📊 <b>Queries run:</b> {meta.get('queries_run', 0)}\n"
            f"🎯 <b>Unique results:</b> {meta.get('total_results', 0)}\n"
            f"🌐 <b>Unique domains:</b> {meta.get('unique_domains', 0)}\n"
            f"📡 <b>API calls:</b> {meta.get('api_calls', 0)}\n\n"
            f"<b>Severity breakdown:</b>\n{sev_lines}\n\n"
            f"🕐 <b>Finished:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )

        # Upload each exported file as a document
        for path in exported_files:
            if path.exists():
                self.send_document(
                    path,
                    caption=f"📎 <b>{path.suffix.lstrip('.').upper()} report</b> — SSN Dorker v{VERSION}"
                )

    def send_top_results(self, results: list[dict], top: int = 10):
        """Send the top-N results as a compact digest (critical/high first)."""
        high_prio = [r for r in results if r.get("severity") in ("critical", "high")][:top]
        if not high_prio:
            return
        lines = [f"🏆 <b>Top {len(high_prio)} High/Critical Findings</b>\n"]
        for i, r in enumerate(high_prio, 1):
            sev   = r.get("severity", "info")
            emoji = SEV_EMOJI.get(sev, "ℹ️")
            title = self._escape(r.get("title", "")[:60])
            url   = self._escape(r.get("url", "")[:100])
            score = r.get("risk_score", 0)
            lines.append(
                f"{i}. {emoji} <b>[{score}]</b> <a href=\"{url}\">{title}</a>"
            )
        self.send_message("\n".join(lines))


# ─────────────────────────────────────────────────────────────
# Core dorking engine
# ─────────────────────────────────────────────────────────────

class SSNDorker:
    def __init__(self, config: dict, logger: logging.Logger,
                 notifier: Optional["TelegramNotifier"] = None):
        self.config   = config
        self.logger   = logger
        self.notifier = notifier
        self.client   = ValueSERPClient(config["api_key"], config, logger)
        self.all_results: list[dict] = []
        self.seen_urls:   set[str]   = set()
        self.stats:       dict       = defaultdict(int)

    def run_query(self, query: str, pages: int, delay: float) -> list[dict]:
        found = []
        for page in range(1, pages + 1):
            self.logger.info("Querying (page %d): %s", page, query[:80])
            raw = self.client.search(query, page=page)
            results = extract_results(raw)
            if not results:
                break

            for r in results:
                if r["url"] and r["url"] not in self.seen_urls:
                    self.seen_urls.add(r["url"])
                    sev, score = score_result(r)
                    r["severity"] = sev
                    r["risk_score"] = score
                    r["dork_query"] = query
                    r["dork_page"] = page
                    r["discovered_at"] = datetime.utcnow().isoformat()
                    found.append(r)
                    # Real-time Telegram alert for high/critical hits
                    if self.notifier and sev in ("critical", "high", "medium"):
                        self.notifier.send_result(r)

            self.stats["total_raw_results"] += len(results)
            if page < pages:
                time.sleep(delay)

        return found

    def run_category(
        self,
        category: str,
        pages: int,
        delay: float,
        custom_queries: Optional[list[str]] = None,
        progress=None,
        task_id=None,
    ) -> list[dict]:
        queries = custom_queries if custom_queries else DORK_TEMPLATES.get(category, [])
        cat_results = []

        for q in queries:
            results = self.run_query(q, pages, delay)
            cat_results.extend(results)
            self.all_results.extend(results)
            self.stats["queries_run"] += 1
            if progress and task_id is not None:
                progress.advance(task_id)
            time.sleep(delay)

        return cat_results

    def run(
        self,
        categories: list[str],
        pages: int,
        delay: float,
        strict_filter: bool = False,
        min_score: int = 0,
        custom_queries: Optional[list[str]] = None,
    ) -> list[dict]:
        total_queries = sum(
            len(custom_queries or DORK_TEMPLATES.get(c, []))
            for c in categories
        )

        if self.notifier:
            self.notifier.send_scan_start(categories, pages, total_queries)

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task("[cyan]Dorking...", total=total_queries)
                for cat in categories:
                    progress.update(task, description=f"[cyan]Category: [bold]{cat}[/bold]")
                    self.run_category(cat, pages, delay, custom_queries if cat == categories[0] and custom_queries else None, progress, task)
        else:
            for cat in categories:
                print(f"\n[*] Category: {cat}")
                self.run_category(cat, pages, delay, custom_queries if cat == categories[0] and custom_queries else None)

        # Post-processing
        unique = deduplicate(self.all_results)
        if strict_filter:
            unique = filter_benign(unique, strict=True)
        if min_score > 0:
            unique = [r for r in unique if r.get("risk_score", 0) >= min_score]

        # Sort by risk score descending
        unique.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        self.stats["total_unique"] = len(unique)
        self.stats["unique_domains"] = len({r["domain"] for r in unique})
        self.stats["api_calls"] = self.client.total_calls

        return unique


# ─────────────────────────────────────────────────────────────
# Interactive mode
# ─────────────────────────────────────────────────────────────

def interactive_mode(config: dict, logger: logging.Logger):
    print_banner()

    if not config["api_key"]:
        cprint("[bold red]No API key configured.[/bold red]")
        config["api_key"] = prompt_api_key()
        if not config["api_key"]:
            cprint("[red]Aborting — no API key provided.[/red]")
            sys.exit(1)

    if RICH_AVAILABLE:
        # Show available categories
        table = Table(title="Available Dork Categories", box=box.ROUNDED)
        table.add_column("#",          width=4, style="dim")
        table.add_column("Category",   style="bold cyan")
        table.add_column("Queries",    justify="right")
        table.add_column("Description")

        descs = {
            "ssn_lookup":        "Sites offering SSN lookup/search services",
            "data_brokers":      "Data broker & people-search sites exposing SSNs",
            "exposed_databases": "Exposed DB/file dumps with SSN fields",
            "identity_theft":    "Sites selling/buying SSN data",
            "breach_data":       "Breach/leak sites with SSN data",
            "api_endpoints":     "APIs exposing SSN endpoints",
            "directory_listings":"Open directory listings with SSN files",
            "error_disclosures": "Sites leaking SSNs via error messages",
            "government_adjacent":"Non-gov sites mimicking SSN services",
            "dark_web_clearnet": "Clearnet dark-web adjacent SSN sites",
        }

        for i, (cat, queries) in enumerate(DORK_TEMPLATES.items(), 1):
            table.add_row(str(i), cat, str(len(queries)), descs.get(cat, ""))

        console.print(table)

        choices = Prompt.ask(
            "\n[bold]Select categories[/bold] (comma-separated #s, or 'all')",
            default="all",
        )
        if choices.strip().lower() == "all":
            selected = list(DORK_TEMPLATES.keys())
        else:
            idxs = [int(x.strip()) - 1 for x in choices.split(",") if x.strip().isdigit()]
            cats = list(DORK_TEMPLATES.keys())
            selected = [cats[i] for i in idxs if 0 <= i < len(cats)]

        pages = int(Prompt.ask("[bold]Pages per query[/bold]", default="3"))
        delay = float(Prompt.ask("[bold]Delay between requests (s)[/bold]", default="1.5"))
        min_score = int(Prompt.ask("[bold]Minimum risk score (0-100)[/bold]", default="0"))
        strict = Confirm.ask("[bold]Filter out known benign domains?[/bold]", default=True)
        export_fmt = Prompt.ask(
            "[bold]Export format[/bold]",
            choices=["json", "csv", "html", "txt", "all", "none"],
            default="all",
        )
        use_tg = Confirm.ask(
            "[bold]Send results to Telegram?[/bold]",
            default=bool(config.get("tg_bot_token") and config.get("tg_chat_id")),
        )
        if use_tg:
            if not config.get("tg_bot_token"):
                config["tg_bot_token"] = Prompt.ask("[bold cyan]Telegram bot token[/bold cyan]")
                if Confirm.ask("Save bot token?", default=True):
                    save_tg_token(config["tg_bot_token"])
            if not config.get("tg_chat_id"):
                config["tg_chat_id"] = Prompt.ask("[bold cyan]Your Telegram chat/user ID[/bold cyan]")
                if Confirm.ask("Save chat ID?", default=True):
                    save_tg_chat_id(config["tg_chat_id"])
            tg_min = int(Prompt.ask("[bold]Only send results with score ≥[/bold]", default="20"))
            config["tg_min_score"] = tg_min
    else:
        selected = list(DORK_TEMPLATES.keys())
        pages = 3
        delay = 1.5
        min_score = 0
        strict = True
        export_fmt = "all"
        use_tg = bool(config.get("tg_bot_token") and config.get("tg_chat_id"))

    notifier = _build_notifier(config, logger) if use_tg else None
    dorker = SSNDorker(config, logger, notifier=notifier)
    results = dorker.run(selected, pages, delay, strict, min_score)

    cprint(f"\n[bold green]Done! {len(results)} unique results.[/bold green]")

    if results:
        print_result_table(results, title=f"SSN Dork Results ({len(results)})")
        print_severity_breakdown(results)

    # Stats
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    meta = {
        "timestamp":     stamp,
        "version":       VERSION,
        "categories":    selected,
        "pages":         pages,
        "queries_run":   int(dorker.stats["queries_run"]),
        "total_results": int(dorker.stats["total_unique"]),
        "unique_domains": int(dorker.stats["unique_domains"]),
        "api_calls":     int(dorker.stats["api_calls"]),
    }
    print_stats({
        "Queries run":      meta["queries_run"],
        "Total unique":     meta["total_results"],
        "Unique domains":   meta["unique_domains"],
        "API calls made":   meta["api_calls"],
        "Session start":    stamp,
    })

    exported_files: list[Path] = []
    if export_fmt != "none" and results:
        RESULTS_DIR.mkdir(exist_ok=True)
        base = RESULTS_DIR / f"ssn_dork_{stamp}"
        fmts = ["json", "csv", "html", "txt"] if export_fmt == "all" else [export_fmt]
        for fmt in fmts:
            if fmt == "json":
                p = base.with_suffix(".json"); export_json(results, p, meta); exported_files.append(p)
            elif fmt == "csv":
                p = base.with_suffix(".csv"); export_csv(results, p); exported_files.append(p)
            elif fmt == "html":
                p = base.with_suffix(".html"); export_html(results, p, meta); exported_files.append(p)
            elif fmt == "txt":
                p = base.with_suffix(".txt"); export_txt(results, p, meta); exported_files.append(p)

    if notifier and results:
        cprint("[cyan]Sending summary to Telegram...[/cyan]")
        notifier.send_top_results(results, top=10)
        notifier.send_summary(
            results, meta,
            exported_files if config.get("tg_send_files") else [],
        )
        cprint("[green]Telegram notifications sent.[/green]")


# ─────────────────────────────────────────────────────────────
# CLI — argument parsing
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ssn_dorker",
        description="SSN Dorker — ValueSERP-Powered OSINT Tool for Security Researchers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
  # Interactive guided mode:
  python ssn_dorker.py --interactive

  # Run all categories, export HTML:
  python ssn_dorker.py --all --export html --output ./out

  # Only run specific categories:
  python ssn_dorker.py -c ssn_lookup,data_brokers --pages 5

  # Run with custom dork queries:
  python ssn_dorker.py --custom-queries "intitle:ssn filetype:csv" "ssn dump site:paste.ee"

  # High-risk results only (score >= 50), strict filter:
  python ssn_dorker.py --all --min-score 50 --strict-filter --export all

  # Set API key:
  python ssn_dorker.py --set-api-key YOUR_KEY_HERE

  # List available categories:
  python ssn_dorker.py --list-categories
""",
    )

    # API / config
    p.add_argument("--api-key",       help="ValueSERP API key (overrides env/config)")
    p.add_argument("--set-api-key",   metavar="KEY", help="Save API key to config and exit")

    # Category selection
    p.add_argument("--all",           action="store_true", help="Run all dork categories")
    p.add_argument("-c", "--categories", metavar="CAT[,CAT]",
                   help="Comma-separated categories to run")
    p.add_argument("--list-categories", action="store_true", help="List categories and exit")
    p.add_argument("--custom-queries",  nargs="+", metavar="DORK",
                   help="Custom Google dork query strings")

    # Search tuning
    p.add_argument("--pages",       type=int,   default=None, help="Pages per query (default: 3)")
    p.add_argument("--delay",       type=float, default=None, help="Delay between requests in seconds")
    p.add_argument("--country",     default=None, help="Country code (e.g. us, gb, de)")
    p.add_argument("--language",    default=None, help="Language code (e.g. en, de, fr)")
    p.add_argument("--num",         type=int, default=100, help="Results per page (max 100)")

    # Filtering
    p.add_argument("--min-score",     type=int, default=0, help="Minimum risk score 0-100")
    p.add_argument("--strict-filter", action="store_true",
                   help="Exclude known-benign domains from results")
    p.add_argument("--only-severity", choices=["critical","high","medium","low","info"],
                   help="Only show results of this severity")
    p.add_argument("--domain-filter", metavar="DOMAIN", nargs="+",
                   help="Only include results from these domains")

    # Output
    p.add_argument("--export", choices=["json","csv","html","txt","all","none"],
                   default="all", help="Export format (default: all)")
    p.add_argument("--output",  default="./results", metavar="DIR",
                   help="Output directory (default: ./results)")
    p.add_argument("--no-print", action="store_true", help="Suppress result table output")
    p.add_argument("--top",      type=int, default=0,
                   help="Show only top N results in table")

    # Telegram
    tg = p.add_argument_group("Telegram notifications")
    tg.add_argument("--telegram",       action="store_true",
                    help="Enable Telegram notifications for this run")
    tg.add_argument("--tg-bot-token",   metavar="TOKEN",
                    help="Telegram bot token (overrides env/config)")
    tg.add_argument("--tg-chat-id",     metavar="ID",
                    help="Telegram chat/user ID to send results to")
    tg.add_argument("--tg-min-score",   type=int, default=None, metavar="N",
                    help="Only send results with risk score ≥ N via Telegram (default: 0)")
    tg.add_argument("--tg-no-files",    action="store_true",
                    help="Don't attach exported files to the Telegram summary")
    tg.add_argument("--tg-test",        action="store_true",
                    help="Test Telegram credentials and exit")
    tg.add_argument("--set-tg-token",   metavar="TOKEN",
                    help="Save Telegram bot token to config and exit")
    tg.add_argument("--set-tg-chat-id", metavar="ID",
                    help="Save Telegram chat ID to config and exit")

    # Modes
    p.add_argument("--interactive", action="store_true", help="Launch interactive guided mode")
    p.add_argument("--verbose",     action="store_true", help="Enable verbose/debug logging")
    p.add_argument("--version",     action="version", version=f"SSN Dorker {VERSION}")

    return p


def list_categories():
    if RICH_AVAILABLE:
        table = Table(title="SSN Dork Categories", box=box.ROUNDED)
        table.add_column("Category",   style="bold cyan")
        table.add_column("Queries",    justify="right")
        for cat, queries in DORK_TEMPLATES.items():
            table.add_row(cat, str(len(queries)))
        console.print(table)
    else:
        print("\nAvailable categories:")
        for cat, queries in DORK_TEMPLATES.items():
            print(f"  {cat:30s}  ({len(queries)} queries)")


# ─────────────────────────────────────────────────────────────
# Notifier factory
# ─────────────────────────────────────────────────────────────

def _build_notifier(config: dict, logger: logging.Logger) -> Optional[TelegramNotifier]:
    token   = config.get("tg_bot_token", "").strip()
    chat_id = config.get("tg_chat_id", "").strip()
    if not token or not chat_id:
        return None
    return TelegramNotifier(
        bot_token=token,
        chat_id=chat_id,
        logger=logger,
        proxy=config.get("proxy", ""),
        min_score=config.get("tg_min_score", 0),
    )


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    config = load_config()
    logger = setup_logging(args.verbose)

    # ── Quick exits ───────────────────────────────────────────
    if args.set_api_key:
        save_api_key(args.set_api_key)
        sys.exit(0)

    if args.set_tg_token:
        save_tg_token(args.set_tg_token)
        sys.exit(0)

    if args.set_tg_chat_id:
        save_tg_chat_id(args.set_tg_chat_id)
        sys.exit(0)

    if args.list_categories:
        list_categories()
        sys.exit(0)

    # ── Telegram credential overrides ─────────────────────────
    if args.tg_bot_token:
        config["tg_bot_token"] = args.tg_bot_token
    if args.tg_chat_id:
        config["tg_chat_id"] = args.tg_chat_id
    if args.tg_min_score is not None:
        config["tg_min_score"] = args.tg_min_score
    if args.tg_no_files:
        config["tg_send_files"] = False

    # ── Telegram test ─────────────────────────────────────────
    if args.tg_test:
        notifier = _build_notifier(config, logger)
        if not notifier:
            cprint("[red]No Telegram credentials configured. Use --tg-bot-token and --tg-chat-id.[/red]")
            sys.exit(1)
        ok = notifier.test()
        sys.exit(0 if ok else 1)

    # ── Interactive mode ──────────────────────────────────────
    if args.interactive or (not args.all and not args.categories and not args.custom_queries):
        interactive_mode(config, logger)
        return

    # ── Override config with CLI args ─────────────────────────
    if args.api_key:
        config["api_key"] = args.api_key
    if args.pages:
        config["default_pages"] = args.pages
    if args.delay:
        config["delay"] = args.delay
    if args.country:
        config["country"] = args.country
    if args.language:
        config["language"] = args.language

    if not config["api_key"]:
        cprint("[bold red]Error: No API key.[/bold red] Use --api-key or --set-api-key, or set VALUESERP_API_KEY.")
        sys.exit(1)

    print_banner()

    # ── Determine categories ──────────────────────────────────
    if args.all:
        categories = list(DORK_TEMPLATES.keys())
    elif args.categories:
        categories = [c.strip() for c in args.categories.split(",")]
        bad = [c for c in categories if c not in DORK_TEMPLATES and not args.custom_queries]
        if bad:
            cprint(f"[red]Unknown categories: {bad}. Use --list-categories.[/red]")
            sys.exit(1)
    elif args.custom_queries:
        categories = ["__custom__"]
    else:
        categories = list(DORK_TEMPLATES.keys())

    pages = args.pages or config["default_pages"]
    delay = args.delay or config["delay"]

    notifier = _build_notifier(config, logger) if args.telegram else None
    if notifier:
        if not notifier.test():
            cprint("[yellow]Warning: Telegram test failed — notifications disabled.[/yellow]")
            notifier = None

    dorker = SSNDorker(config, logger, notifier=notifier)
    results = dorker.run(
        categories=categories,
        pages=pages,
        delay=delay,
        strict_filter=args.strict_filter,
        min_score=args.min_score,
        custom_queries=args.custom_queries,
    )

    # Extra filters
    if args.only_severity:
        results = [r for r in results if r.get("severity") == args.only_severity]
    if args.domain_filter:
        results = [r for r in results if r.get("domain") in args.domain_filter]

    if not args.no_print:
        top = args.top or len(results)
        print_result_table(results[:top], title=f"SSN Dork Results ({len(results)} total)")
        print_severity_breakdown(results)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    meta = {
        "timestamp":      stamp,
        "version":        VERSION,
        "categories":     categories,
        "pages":          pages,
        "queries_run":    int(dorker.stats["queries_run"]),
        "total_results":  int(dorker.stats["total_unique"]),
        "unique_domains": int(dorker.stats["unique_domains"]),
        "api_calls":      int(dorker.stats["api_calls"]),
    }

    print_stats({
        "Queries run":    meta["queries_run"],
        "Total unique":   meta["total_results"],
        "Unique domains": meta["unique_domains"],
        "API calls made": meta["api_calls"],
    })

    exported_files: list[Path] = []
    if args.export != "none" and results:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        base = out_dir / f"ssn_dork_{stamp}"
        fmts = ["json","csv","html","txt"] if args.export == "all" else [args.export]
        for fmt in fmts:
            if fmt == "json":
                p = base.with_suffix(".json"); export_json(results, p, meta); exported_files.append(p)
            elif fmt == "csv":
                p = base.with_suffix(".csv"); export_csv(results, p); exported_files.append(p)
            elif fmt == "html":
                p = base.with_suffix(".html"); export_html(results, p, meta); exported_files.append(p)
            elif fmt == "txt":
                p = base.with_suffix(".txt"); export_txt(results, p, meta); exported_files.append(p)

    if notifier and results:
        cprint("[cyan]Sending Telegram summary...[/cyan]")
        notifier.send_top_results(results, top=10)
        notifier.send_summary(
            results, meta,
            exported_files if config.get("tg_send_files") else [],
        )
        cprint("[green]Telegram notifications sent.[/green]")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SentraX-CLI (single-file edition) - Terminal Website Security Scanner
Author: Arqam (CoreSec Solutions) — https://sentrax.lovable.app

Checks: WHOIS, DNS, SSL/TLS, HTTP security headers, passive subdomain
discovery (crt.sh), common-port scan, tech fingerprinting, robots.txt/sitemap.

Usage:
    python3 sentrax.py -d example.com
    python3 sentrax.py -d example.com --modules ssl,headers,dns
    python3 sentrax.py -d example.com --format json,html --output ./out
    python3 sentrax.py -d example.com --config myconfig.yaml
    python3 sentrax.py -d example.com --no-banner --verbose

Only scan domains you own or are explicitly authorized to test.
"""

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import yaml
import dns.resolver
from colorama import init as colorama_init, Fore, Style

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG = {
    "general": {
        "timeout": 6,
        "threads": 20,
        "user_agent": "SentraX-CLI/1.0 (+https://sentrax.lovable.app)",
        "verbose": False,
    },
    "modules": {
        "whois": True, "dns": True, "ssl": True, "headers": True,
        "subdomains": True, "ports": True, "tech_detect": True, "robots_sitemap": True,
    },
    "ports": {
        "common_ports": [21, 22, 25, 53, 80, 110, 143, 443, 465, 587,
                          993, 995, 3306, 3389, 5432, 8080, 8443],
    },
    "subdomains": {"source": "crtsh", "max_results": 50},
    "report": {"formats": ["terminal", "json"], "output_dir": "reports", "include_raw_data": True},
}


def load_config(path):
    if not path or not os.path.exists(path):
        if path:
            print(f"[!] Config file not found at {path}, using built-in defaults.")
        return json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    with open(path, "r") as f:
        loaded = yaml.safe_load(f) or {}
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    for section, values in loaded.items():
        if isinstance(values, dict) and section in merged:
            merged[section].update(values)
        else:
            merged[section] = values
    return merged


def normalize_domain(raw):
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.netloc or parsed.path
    return raw.split("/")[0]


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #

VERSION = "1.0.0"
BANNER = r"""
   _____ ______ _   _ _______ _____            __   __
  / ____|  ____| \ | |__   __|  __ \    /\     \ \ / /
 | (___ | |__  |  \| |  | |  | |__) |  /  \     \ V /
  \___ \|  __| | . ` |  | |  |  _  /  / /\ \     > <
  ____) | |____| |\  |  | |  | | \ \ / ____ \   / . \
 |_____/|______|_| \_|  |_|  |_|  \_/_/    \_\ /_/ \_\
"""


def print_banner():
    print(Fore.GREEN + Style.BRIGHT + BANNER)
    print(Fore.CYAN + f"        SentraX-CLI v{VERSION}  |  Terminal Website Security Scanner")
    print(Fore.CYAN + "        by Arqam / CoreSec Solutions  —  github project")
    print(Fore.YELLOW + "        Use only against targets you own or are authorized to test.\n")
    print(Style.RESET_ALL, end="")


# --------------------------------------------------------------------------- #
# Modules — each returns {"module": str, "status": "ok"|"warning"|"error",
#                          "data": dict, "error": str|None}
# --------------------------------------------------------------------------- #

def check_whois(domain, cfg):
    result = {"module": "whois", "status": "ok", "data": {}, "error": None}
    try:
        import whois
        socket.setdefaulttimeout(cfg["general"]["timeout"])
        w = whois.whois(domain)

        def clean(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return None if val is None else str(val)

        result["data"] = {
            "registrar": clean(w.registrar),
            "creation_date": clean(w.creation_date),
            "expiration_date": clean(w.expiration_date),
            "updated_date": clean(w.updated_date),
            "name_servers": clean(w.name_servers),
            "org": clean(getattr(w, "org", None)),
            "country": clean(getattr(w, "country", None)),
            "emails": clean(getattr(w, "emails", None)),
            "status": clean(w.status),
        }
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result


def check_dns(domain, cfg):
    result = {"module": "dns", "status": "ok", "data": {}, "error": None}
    resolver = dns.resolver.Resolver()
    resolver.timeout = cfg["general"]["timeout"]
    resolver.lifetime = cfg["general"]["timeout"]

    records = {}
    any_success = False
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = sorted([a.to_text() for a in answers])
            any_success = True
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            result["status"] = "error"
            result["error"] = "Domain does not exist (NXDOMAIN)"
            return result
        except Exception:
            records[rtype] = []

    result["data"] = records
    if not any_success:
        result["status"] = "warning"
        result["error"] = "No DNS records resolved for any queried type"
    return result


def check_ssl(domain, cfg):
    result = {"module": "ssl", "status": "ok", "data": {}, "error": None}
    timeout = cfg["general"]["timeout"]

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        days_left = None
        if not_after:
            expires_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expires_dt = expires_dt.replace(tzinfo=datetime.timezone.utc)
            days_left = (expires_dt - datetime.datetime.now(datetime.timezone.utc)).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        san = [entry[1] for entry in cert.get("subjectAltName", [])]

        findings = []
        if days_left is not None and days_left < 15:
            findings.append(f"Certificate expires soon ({days_left} days left)")
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(f"Outdated/insecure protocol negotiated: {protocol}")
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
        if cipher and any(w in cipher[0] for w in weak_ciphers):
            findings.append(f"Weak cipher suite negotiated: {cipher[0]}")

        result["data"] = {
            "issuer": issuer, "subject": subject,
            "valid_from": not_before, "valid_until": not_after,
            "days_until_expiry": days_left, "protocol": protocol,
            "cipher_suite": cipher[0] if cipher else None,
            "subject_alt_names": san, "findings": findings,
        }
        if findings:
            result["status"] = "warning"

    except ssl.SSLCertVerificationError as e:
        result["status"] = "warning"
        result["data"] = {"findings": ["Certificate verification failed: possible self-signed or expired cert"]}
        result["error"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS). Missing allows downgrade attacks.",
    "Content-Security-Policy": "Restricts sources of scripts/styles, mitigating XSS.",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks (should be 'nosniff').",
    "Referrer-Policy": "Controls how much referrer info is leaked cross-origin.",
    "Permissions-Policy": "Restricts access to browser features (camera, mic, geolocation).",
    "Cross-Origin-Opener-Policy": "Isolates browsing context to prevent cross-window attacks.",
    "Cross-Origin-Resource-Policy": "Restricts which origins can load this resource.",
}
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def check_headers(domain, cfg):
    result = {"module": "headers", "status": "ok", "data": {}, "error": None}
    timeout = cfg["general"]["timeout"]
    ua = cfg["general"]["user_agent"]

    try:
        resp = requests.get(f"https://{domain}", timeout=timeout, headers={"User-Agent": ua}, allow_redirects=True)
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(f"http://{domain}", timeout=timeout, headers={"User-Agent": ua}, allow_redirects=True)
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"Could not connect over HTTPS or HTTP: {e}"
            return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        return result

    headers = resp.headers
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    leaks = {h: headers[h] for h in INFO_LEAK_HEADERS if h in headers}

    findings = [f"Missing header: {h} — {SECURITY_HEADERS[h]}" for h in missing]
    if leaks:
        findings.append(f"Information disclosure via headers: {', '.join(f'{k}={v}' for k, v in leaks.items())}")

    result["data"] = {
        "final_url": resp.url, "status_code": resp.status_code,
        "present_security_headers": present, "missing_security_headers": missing,
        "info_leak_headers": leaks, "findings": findings,
    }
    if findings:
        result["status"] = "warning"
    return result


def check_subdomains(domain, cfg):
    result = {"module": "subdomains", "status": "ok", "data": {}, "error": None}
    timeout = cfg["general"]["timeout"]
    max_results = cfg.get("subdomains", {}).get("max_results", 50)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            result["status"] = "warning"
            result["error"] = f"crt.sh returned status {resp.status_code}"
            result["data"] = {"subdomains": []}
            return result

        entries = resp.json()
        subs = set()
        for entry in entries:
            for line in entry.get("name_value", "").split("\n"):
                line = line.strip().lower()
                if line.endswith(domain) and "*" not in line:
                    subs.add(line)

        result["data"] = {"count_found": len(subs), "subdomains": sorted(subs)[:max_results]}
    except ValueError:
        result["status"] = "warning"
        result["error"] = "crt.sh returned non-JSON response (rate-limited or empty)"
        result["data"] = {"subdomains": []}
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result


COMMON_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def _check_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False


def check_ports(domain, cfg):
    result = {"module": "ports", "status": "ok", "data": {}, "error": None}
    timeout = min(cfg["general"]["timeout"], 3)
    threads = cfg["general"].get("threads", 20)
    ports = cfg.get("ports", {}).get("common_ports", list(COMMON_SERVICE_NAMES.keys()))

    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Could not resolve host: {e}"
        return result

    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(_check_port, ip, p, timeout) for p in ports]
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        return result

    open_ports.sort()
    risky_open = [p for p in open_ports if p in (21, 23, 3306, 3389, 5432)]
    findings = []
    if risky_open:
        findings.append(
            "Potentially sensitive services exposed publicly: "
            + ", ".join(f"{p}/{COMMON_SERVICE_NAMES.get(p, 'unknown')}" for p in risky_open)
        )

    result["data"] = {
        "resolved_ip": ip,
        "open_ports": [{"port": p, "service": COMMON_SERVICE_NAMES.get(p, "unknown")} for p in open_ports],
        "scanned_count": len(ports),
        "findings": findings,
    }
    if findings:
        result["status"] = "warning"
    return result


TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "Shopify": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    "React": [r"__NEXT_DATA__|react\.production|data-reactroot"],
    "Next.js": [r"__NEXT_DATA__", r"/_next/static"],
    "Vue.js": [r"__vue__|/js/vue\."],
    "Laravel": [r"laravel_session"],
    "Django": [r"csrftoken"],
    "Cloudflare": [r"cloudflare"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
    "jQuery": [r"jquery(\.min)?\.js"],
    "Bootstrap": [r"bootstrap(\.min)?\.css"],
    "Google Analytics": [r"google-analytics\.com|gtag\("],
    "Supabase": [r"supabase\.co"],
    "Lovable": [r"lovable\.app|lovable\.dev"],
}


def check_tech(domain, cfg):
    result = {"module": "tech_detect", "status": "ok", "data": {}, "error": None}
    timeout = cfg["general"]["timeout"]
    ua = cfg["general"]["user_agent"]

    try:
        resp = requests.get(f"https://{domain}", timeout=timeout, headers={"User-Agent": ua})
    except Exception:
        try:
            resp = requests.get(f"http://{domain}", timeout=timeout, headers={"User-Agent": ua})
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            return result

    haystack = resp.text + " " + " ".join(f"{k}:{v}" for k, v in resp.headers.items())
    detected = []
    for tech, patterns in TECH_SIGNATURES.items():
        if any(re.search(pat, haystack, re.IGNORECASE) for pat in patterns):
            detected.append(tech)

    result["data"] = {
        "detected_technologies": sorted(set(detected)),
        "server_header": resp.headers.get("Server"),
        "powered_by_header": resp.headers.get("X-Powered-By"),
    }
    return result


SENSITIVE_KEYWORDS = ["admin", "login", "config", "backup", "private", "internal", "staging", "wp-admin", ".env"]


def check_robots_sitemap(domain, cfg):
    result = {"module": "robots_sitemap", "status": "ok", "data": {}, "error": None}
    timeout = cfg["general"]["timeout"]
    ua = cfg["general"]["user_agent"]
    base = f"https://{domain}"
    data = {"robots_txt_found": False, "sitemap_found": False, "disallowed_paths": [], "interesting_paths": []}

    try:
        r = requests.get(f"{base}/robots.txt", timeout=timeout, headers={"User-Agent": ua})
        if r.status_code == 200 and r.text.strip():
            data["robots_txt_found"] = True
            disallowed = []
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
            data["disallowed_paths"] = disallowed
            data["interesting_paths"] = [p for p in disallowed if any(k in p.lower() for k in SENSITIVE_KEYWORDS)]
    except Exception as e:
        result["error"] = f"robots.txt fetch failed: {e}"

    try:
        r = requests.get(f"{base}/sitemap.xml", timeout=timeout, headers={"User-Agent": ua})
        if r.status_code == 200 and ("<urlset" in r.text.lower() or "<sitemapindex" in r.text.lower()):
            data["sitemap_found"] = True
    except Exception:
        pass

    result["data"] = data
    if data["interesting_paths"]:
        result["status"] = "warning"
    return result


MODULE_MAP = {
    "whois": check_whois,
    "dns": check_dns,
    "ssl": check_ssl,
    "headers": check_headers,
    "subdomains": check_subdomains,
    "ports": check_ports,
    "tech_detect": check_tech,
    "robots_sitemap": check_robots_sitemap,
}

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

STATUS_COLORS = {"ok": Fore.GREEN, "warning": Fore.YELLOW, "error": Fore.RED}
STATUS_LABELS = {"ok": "OK", "warning": "WARNING", "error": "ERROR"}


def _print_module_summary(name, res):
    data = res.get("data", {})
    if not isinstance(data, dict):
        return
    if name == "dns":
        for rtype, vals in data.items():
            if vals:
                print(Fore.CYAN + f"   {rtype}: " + Style.RESET_ALL + ", ".join(vals[:5]))
    elif name == "ssl":
        if data.get("issuer"):
            print(f"   Issuer: {data['issuer'].get('organizationName', data['issuer'].get('commonName', 'n/a'))}")
        if data.get("days_until_expiry") is not None:
            print(f"   Expires in: {data['days_until_expiry']} days")
        if data.get("protocol"):
            print(f"   Protocol: {data['protocol']}")
    elif name == "headers":
        if data.get("present_security_headers"):
            print(f"   Present headers: {len(data['present_security_headers'])} / configured checks")
    elif name == "subdomains":
        subs = data.get("subdomains", [])
        if subs:
            print(f"   Found {data.get('count_found', len(subs))} unique subdomains (showing up to {len(subs)}):")
            for s in subs[:10]:
                print(Fore.CYAN + f"     - {s}" + Style.RESET_ALL)
    elif name == "ports":
        open_ports = data.get("open_ports", [])
        if open_ports:
            print("   Open ports: " + ", ".join(f"{p['port']}/{p['service']}" for p in open_ports))
        else:
            print("   No open ports found among scanned list.")
    elif name == "tech_detect":
        tech = data.get("detected_technologies", [])
        if tech:
            print(f"   Detected: {', '.join(tech)}")
    elif name == "whois":
        if data.get("registrar"):
            print(f"   Registrar: {data['registrar']}")
        if data.get("expiration_date"):
            print(f"   Domain expires: {data['expiration_date']}")
    elif name == "robots_sitemap":
        if data.get("robots_txt_found"):
            print(f"   robots.txt found — {len(data.get('disallowed_paths', []))} disallowed paths")
        if data.get("sitemap_found"):
            print("   sitemap.xml found")


def print_terminal_report(domain, results):
    print(Style.BRIGHT + f"\n{'=' * 60}")
    print(f" SCAN REPORT — {domain}")
    print(f" Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print(f"{'=' * 60}\n" + Style.RESET_ALL)

    total_findings = 0
    for module_name, res in results.items():
        color = STATUS_COLORS.get(res["status"], Fore.WHITE)
        label = STATUS_LABELS.get(res["status"], res["status"].upper())
        print(color + Style.BRIGHT + f"[{label}] {module_name.upper()}" + Style.RESET_ALL)

        if res.get("error") and res["status"] == "error":
            print(Fore.RED + f"   ! {res['error']}" + Style.RESET_ALL)

        findings = res.get("data", {}).get("findings") if isinstance(res.get("data"), dict) else None
        if findings:
            total_findings += len(findings)
            for f in findings:
                print(Fore.YELLOW + f"   - {f}" + Style.RESET_ALL)

        _print_module_summary(module_name, res)
        print()

    print(Style.BRIGHT + f"{'=' * 60}")
    print(f" TOTAL FINDINGS: {total_findings}")
    print(f"{'=' * 60}\n" + Style.RESET_ALL)


def save_json_report(domain, results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"sentrax_{domain}_{timestamp}.json")
    payload = {
        "target": domain,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "results": results,
    }
    with open(filename, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    return filename


def save_html_report(domain, results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"sentrax_{domain}_{timestamp}.html")

    status_color = {"ok": "#39ff14", "warning": "#ffcc00", "error": "#ff4444"}
    sections = ""
    total_findings = 0

    for module_name, res in results.items():
        color = status_color.get(res["status"], "#ffffff")
        findings = res.get("data", {}).get("findings") if isinstance(res.get("data"), dict) else None
        findings_html = ""
        if findings:
            total_findings += len(findings)
            findings_html = "<ul>" + "".join(f"<li>{f}</li>" for f in findings) + "</ul>"
        error_html = f"<p class='error'>{res['error']}</p>" if res.get("error") and res["status"] == "error" else ""
        raw_json = json.dumps(res.get("data", {}), indent=2, default=str)
        sections += f"""
        <div class="module-card">
          <h3 style="color:{color}">{module_name.upper()} — {res['status'].upper()}</h3>
          {error_html}
          {findings_html}
          <details><summary>Raw data</summary><pre>{raw_json}</pre></details>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentraX Report — {domain}</title>
<style>
  body {{ background:#0a0e14; color:#e0e0e0; font-family: 'Courier New', monospace; padding:2rem; }}
  h1 {{ color:#39ff14; }}
  .meta {{ color:#888; margin-bottom:2rem; }}
  .module-card {{ background:#111722; border:1px solid #1f2937; border-radius:8px; padding:1rem 1.5rem; margin-bottom:1rem; }}
  .error {{ color:#ff4444; }}
  ul {{ color:#ffcc00; }}
  pre {{ background:#0d1117; padding:1rem; overflow-x:auto; font-size:0.85rem; border-radius:6px; }}
  summary {{ cursor:pointer; color:#39ff14; margin-top:0.5rem; }}
  .totals {{ font-size:1.2rem; margin-top:2rem; color:#39ff14; }}
</style>
</head>
<body>
  <h1>SentraX-CLI Security Report</h1>
  <div class="meta">Target: {domain} &nbsp;|&nbsp; Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}</div>
  {sections}
  <div class="totals">Total findings: {total_findings}</div>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    return filename


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="sentrax",
        description="SentraX-CLI — Terminal Website Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain or URL, e.g. example.com")
    p.add_argument("-c", "--config", default=None, help="Path to a config.yaml (optional; sane defaults are built in)")
    p.add_argument(
        "-m", "--modules",
        help=f"Comma-separated modules to run, overrides config. Available: {', '.join(MODULE_MAP.keys())}",
    )
    p.add_argument("-f", "--format", help="Comma-separated output formats: terminal,json,html")
    p.add_argument("-o", "--output", help="Output directory for reports")
    p.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return p


def main():
    colorama_init(autoreset=False)
    args = build_arg_parser().parse_args()
    cfg = load_config(args.config)

    if args.verbose:
        cfg["general"]["verbose"] = True

    domain = normalize_domain(args.domain)

    if not args.no_banner:
        print_banner()

    if args.modules:
        requested = [m.strip() for m in args.modules.split(",")]
        active_modules = [m for m in requested if m in MODULE_MAP]
        unknown = [m for m in requested if m not in MODULE_MAP]
        if unknown:
            print(f"[!] Ignoring unknown module(s): {', '.join(unknown)}")
    else:
        active_modules = [m for m, enabled in cfg.get("modules", {}).items() if enabled and m in MODULE_MAP]

    if not active_modules:
        print("[!] No modules selected to run. Exiting.")
        sys.exit(1)

    print(f"[*] Target: {domain}")
    print(f"[*] Modules: {', '.join(active_modules)}\n")

    results = {}
    for mod_name in active_modules:
        print(f"[>] Running {mod_name} ...", end=" ", flush=True)
        start = time.time()
        try:
            mod_result = MODULE_MAP[mod_name](domain, cfg)
        except Exception as e:
            mod_result = {"module": mod_name, "status": "error", "data": {}, "error": f"Unhandled exception: {e}"}
        elapsed = time.time() - start
        print(f"done ({elapsed:.1f}s)")
        results[mod_name] = mod_result

    formats = [f.strip().lower() for f in args.format.split(",")] if args.format else cfg.get("report", {}).get("formats", ["terminal"])
    output_dir = args.output or cfg.get("report", {}).get("output_dir", "reports")

    if "terminal" in formats:
        print_terminal_report(domain, results)
    if "json" in formats:
        path = save_json_report(domain, results, output_dir)
        print(f"[+] JSON report saved: {path}")
    if "html" in formats:
        path = save_html_report(domain, results, output_dir)
        print(f"[+] HTML report saved: {path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)

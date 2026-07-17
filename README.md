# SentraX-CLI (single-file edition)

One Python file. No config.yaml required — sane defaults are built in, and you can still override them on the command line or with an optional config file.

The terminal companion to [SentraX](https://sentrax.lovable.app).

## What it checks

- **WHOIS** — registrar, creation/expiry dates, name servers
- **DNS** — A, AAAA, MX, NS, TXT, CNAME, SOA records
- **SSL/TLS** — cert expiry, issuer, protocol version, weak cipher detection
- **HTTP headers** — missing/present security headers, info-disclosure headers
- **Subdomains** — passive discovery via crt.sh certificate transparency (no brute forcing)
- **Ports** — fast TCP-connect scan across common ports
- **Tech fingerprinting** — CMS, frameworks, CDNs, analytics
- **robots.txt / sitemap.xml** — flags disallowed paths that look sensitive

## Install

```bash
git clone https://github.com/yourusername/sentrax-cli.git
cd sentrax-cli
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

```bash
# Full scan, all modules, terminal + JSON output
python3 sentrax.py -d example.com

# Only run specific modules
python3 sentrax.py -d example.com --modules ssl,headers,dns

# Export HTML + JSON report to a custom folder
python3 sentrax.py -d example.com --format json,html --output ./my_reports

# Optional: use a config.yaml to change defaults (timeouts, ports, thread count)
python3 sentrax.py -d example.com --config myconfig.yaml

# Verbose mode, no banner (good for scripting/CI)
python3 sentrax.py -d example.com --no-banner --verbose
```

### Flags

| Flag | Description |
|---|---|
| `-d, --domain` | Target domain or URL (required) |
| `-c, --config` | Optional path to a config.yaml to override built-in defaults |
| `-m, --modules` | Comma-separated modules to run, overrides config |
| `-f, --format` | Comma-separated output formats: `terminal`, `json`, `html` |
| `-o, --output` | Output directory for saved reports |
| `--no-banner` | Suppress the startup banner |
| `-v, --verbose` | Verbose output |

## Customization without editing code

Everything Sentrax reads from a config lives in a `DEFAULT_CONFIG` dict at the top of `sentrax.py`. To override it without touching the script, pass `--config` pointing at a YAML file like:

```yaml
general:
  timeout: 10
  threads: 30

modules:
  whois: false   # turn a module off entirely

ports:
  common_ports: [80, 443, 8080]

report:
  formats: ["terminal", "html"]
  output_dir: "my_reports"
```

Any key you don't set falls back to the built-in default.

## Adding a module

Since it's one file, add a new function following the same shape as the existing checks:

```python
def check_my_thing(domain, cfg):
    return {"module": "my_thing", "status": "ok", "data": {...}, "error": None}
```

Then register it in `MODULE_MAP` near the top of the file:

```python
MODULE_MAP = {
    ...,
    "my_thing": check_my_thing,
}
```

## Legal / Ethical Use

Scan only domains you own or have explicit written authorization to test. Port scanning, subdomain enumeration, and vulnerability probing against systems without permission can violate laws like the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and Tanzania's Cybercrimes Act, among others. Always get permission first.

## License

MIT.

---
Built by Arqam — [CoreSec Solutions](https://sentrax.lovable.app)

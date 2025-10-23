# URL Phishing Detector

Tiny Rust CLI to detect suspicious URLs using heuristic-based analysis.

Built with Rust, Clap, Reqwest, Regex, and Serde.

---

## Features

- Detects common phishing patterns:
  - Raw IP addresses in URLs
  - `@` in URL (credential trick)
  - Punycode homograph attacks (`xn--`)
  - Excessive subdomains
  - Long URLs (>75 chars)
  - Executable-like filenames (`.exe`, `.zip`, `.msi`, etc.)
  - Non-standard ports
  - Redirects to different hosts
- Outputs score and verdict:
  - `clean` → low risk
  - `suspicious` → medium risk
  - `phishy` → high risk
- Optional JSON output for automation.
- Optional redirect following (HTTP requests).

---

## Requirements

- Rust 1.70+ (tested on Windows 10/11)
- Internet connection if `--follow` is used
- Cargo (comes with Rust)

---

## Build

Clone the repo (or use your own local copy):

```bash
git clone https://github.com/your-username/url-phish-detector.git
cd url-phish-detector

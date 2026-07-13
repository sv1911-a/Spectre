# Changelog

All notable changes to SPECTRE will be documented here.

## 0.1.0 - Unreleased

Initial framework release.

### Changed after Kali validation

- Reworded project identity to simply "Spectre" instead of using a tagline.
- Improved terminal reports with summaries first and raw evidence hidden by default.
- Added `--verbose` for plugin names and raw evidence details.
- Hid internal scoring from normal terminal reports.
- Added multi-candidate target detection with alternative interpretations.
- Improved encoded-text detection for Base32-like input.
- Hardened technology fingerprinting so unusual `Server` header values are not treated as technologies.
- Improved rule-based next-step recommendations for files, web targets, crypto input, and infrastructure.
- Updated documentation to use simpler, more practical language.

### Improved

- Crypto analysis now includes built-in Base32, Base58, Base85, ASCII85, JWT, PEM, compressed blob, and Caesar-style transform attempts.
- Crypto graph search now avoids lower-quality branches more aggressively.
- File analysis now extracts URLs, domains, emails, IPs, hashes, JWTs, API keys, tokens, embedded file signatures, possible secrets, language hints, and suspicious strings.
- File analysis now includes basic PE and ELF triage hints where possible.
- Web analysis now checks robots.txt, sitemap.xml, security.txt, security headers, cookies, CSP, HTML comments, JavaScript endpoints, parameters, and authentication clues.
- GitHub repository analysis now includes releases, activity summary, health indicators, dependency/project files, and improved project hints.

### Added

- `spectre analyze <target>` workflow
- target auto-detection
- plugin system
- reporting system: terminal, JSON, CSV, Markdown, HTML
- SQLite investigation storage
- rule-based next-step recommendations
- finding extraction
- relationship graph metadata
- native file triage:
  - magic bytes
  - hashes
  - entropy
  - strings
  - extension/signature mismatch check
- crypto engine:
  - Base64
  - hex
  - URL decoding
  - ROT13
  - XOR candidates
  - hash identification
- technical/public-source analysis:
  - DNS
  - WHOIS
  - RDAP
  - IP lookup
  - reverse DNS
  - ASN lookup
  - SSL/TLS certificate lookup
  - CRT.SH lookup
  - web technology fingerprinting
- GitHub analysis:
  - users
  - organizations
  - repositories
  - search
  - contributors
  - redacted secret indicators
- Wayback Machine lookup

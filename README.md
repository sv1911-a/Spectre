# Spectre

Spectre is a command-line tool that analyzes cybersecurity targets and performs the first steps of an investigation automatically.

Give it a file, website, IP address, domain, binary, image, hash, GitHub repository, or encoded text. Spectre checks what it is, pulls out the useful details, summarizes what matters, and suggests what to investigate next.

```bash
spectre analyze <target>
```

## Why use it?

Spectre saves you from opening five different tools just to understand one target.

It is useful for:

- CTFs
- penetration testing
- digital forensics
- malware triage
- OSINT
- security research

Spectre does not try to replace the analyst. It handles the repetitive first pass so you can get to the interesting part faster.

## Quick examples

```bash
spectre analyze challenge.zip
spectre analyze suspicious.exe
spectre analyze image.jpg
spectre analyze example.com
spectre analyze https://example.com
spectre analyze 8.8.8.8
spectre analyze person@example.com
spectre analyze 5d41402abc4b2a76b9719d911017c592
spectre analyze SGVsbG8=
```

Example output style:

```text
Spectre Report :: suspicious.exe
================================
Detected: file (99%)

Summary
-------
File: suspicious.exe
Type: DOS/PE executable
SHA256: ...
Strings: 42

Interesting findings:
  - Executable/binary file detected
  - URL found in strings

Findings
--------
- Native file triage
  File type, hashes, entropy, and strings were collected.

What to investigate next
------------------------
1. Review extracted strings
2. Analyze discovered URLs or domains
3. Perform binary triage next
```

## Install

From the project folder:

```bash
python -m pip install -e ".[dns]"
```

Then run:

```bash
spectre --help
spectre analyze --help
spectre analyze example.com
```

## Main command

Use this first:

```bash
spectre analyze <target>
```

Spectre tries to detect what you gave it and chooses useful checks.

Examples:

```bash
spectre analyze example.com
```

Checks domain and network information.

```bash
spectre analyze https://portswigger.net
```

Checks DNS, RDAP, TLS, headers, and website technology clues.

```bash
spectre analyze suspicious.exe
```

Checks file type, hashes, entropy, and strings.

```bash
spectre analyze SGVsbG8=
```

Attempts decoding and shows the best result.

## Direct commands

Most users should start with `spectre analyze`, but direct commands are available when you already know what you want.

### Files

```bash
spectre file sample.bin
spectre binary sample.exe
spectre image photo.jpg
spectre document report.pdf
spectre archive sample.zip
spectre metadata report.pdf
```

### Domains, IPs, and websites

```bash
spectre domain example.com
spectre dns example.com
spectre ip 8.8.8.8
spectre web https://example.com
```

### Identity clues

```bash
spectre email person@example.com
spectre username analyst
```

### Crypto and hashes

```bash
spectre hash 5d41402abc4b2a76b9719d911017c592
spectre crypto SGVsbG8=
```

## Reports

Default terminal reports are designed to be readable.

They show:

- detected target type
- summary
- interesting findings
- next steps

Use `--verbose` when you want raw details:

```bash
spectre analyze example.com --verbose
```

Other formats:

```bash
spectre analyze example.com --format json
spectre analyze sample.pdf --format html --output report.html
```

Supported formats:

- terminal
- JSON
- CSV
- Markdown
- HTML

## Save investigations

```bash
spectre analyze example.com --save
spectre storage list
spectre storage show 1
```

Saved investigations use SQLite.

## What works today

Spectre currently supports:

- target auto-detection
- readable reports
- next-step suggestions
- file type checks
- file hashes
- entropy
- string extraction
- URL, domain, email, IP, hash, JWT, API key, and token extraction
- embedded file signature checks
- possible secret checks
- basic binary triage hints
- hash identification
- Base64, Base32, Base58, Base85, hex, URL, ROT13, Caesar-style, JWT, compressed blob, and XOR-style decoding
- DNS lookup
- WHOIS lookup
- RDAP lookup
- IP lookup
- reverse DNS lookup
- ASN lookup
- TLS certificate lookup
- Certificate Transparency lookup
- web checks for headers, cookies, security headers, robots.txt, sitemap.xml, security.txt, comments, endpoints, and parameters
- GitHub user, organization, repository, and search checks
- Wayback Machine lookup

## What Spectre is not

Spectre is not:

- an AI assistant
- an auto-solver
- a wrapper around a pile of other tools
- a replacement for Ghidra, Burp, Wireshark, or Nmap

Spectre is meant to be the first tool you run, not the only tool you ever need.

## Project structure

Most users do not need this section.

```text
spectre/
  cli.py          command-line interface
  core/           report, storage, detection, and shared code
  analysis/       local analysis code
  sources/        public lookups such as DNS, RDAP, GitHub, and CT logs
  plugins/        individual checks
  tests/          unit tests
```

## Development

Run tests:

```bash
python -m unittest discover -s tests -v
```

Useful docs:

- `docs/VISION.md` — what Spectre is trying to become
- `docs/NEXT_STEPS.md` — what to build next
- `docs/MODULES.md` — planned analysis areas
- `docs/SOURCES.md` — when internet lookups are acceptable
- `CONTRIBUTING.md` — contribution guide

## Guiding rule

Every feature should answer:

```text
Did this save the user time or reduce manual work?
```

If not, it probably does not belong yet.

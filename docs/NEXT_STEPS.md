# Spectre Roadmap

The main goal is still:

```bash
spectre analyze <target>
```

Spectre should detect the target, run useful first-pass checks, summarize the results, and suggest what to investigate next.

## How to choose what to build

Every new feature should answer yes to at least one question:

- Does it save time?
- Does it reduce manual work?
- Does it make the report clearer?
- Does it highlight something important?
- Does it help the user know what to do next?

If not, reconsider it.

## Priority 1: Improve `spectre analyze`

Current detection supports:

- files
- domains
- IP addresses
- URLs
- emails
- usernames
- hashes
- GitHub repositories
- encoded text

Next:

- improve target scoring
- show better alternative interpretations
- choose better default checks
- add `--fast`
- add `--deep`
- avoid slow checks unless useful

## Priority 2: Improve reports

Current reports show:

- detected target type
- summary
- findings
- next steps

Next:

- better summaries for websites
- better summaries for files
- better summaries for GitHub repositories
- cleaner HTML reports
- timeline sections when useful
- PDF export later

## Priority 3: Improve file analysis

Current:

- magic bytes
- hashes
- entropy
- strings
- extension mismatch check

Next:

- more file signatures
- embedded file detection
- better string extraction
- URL/email/domain extraction from strings
- suspicious pattern detection

## Priority 4: Metadata checks

Planned:

- EXIF parser
- GPS extraction
- PDF metadata parser
- Office document metadata parser
- timestamps
- author fields

## Priority 5: Archive checks

Planned:

- ZIP listing
- TAR listing
- GZIP handling
- hashes for files inside archives
- nested file analysis
- suspicious file detection

## Priority 6: Binary checks

Planned:

- PE parser
- ELF parser
- Mach-O parser
- imports
- exports
- sections
- section entropy
- compiler clues
- packer clues
- interesting strings

## Priority 7: Web checks

Planned:

- robots.txt
- sitemap.xml
- cookies
- JavaScript endpoint extraction
- security header checks
- interesting parameters
- authentication clues

## Priority 8: Domain and IP checks

Current:

- DNS
- WHOIS
- RDAP
- reverse DNS
- ASN
- TLS certificates
- Certificate Transparency

Next:

- better DNS summaries
- better RDAP ownership summaries
- better CT log cleanup
- verify subdomain leads
- better infrastructure summaries

## Priority 9: GitHub checks

Current:

- users
- organizations
- repositories
- search
- contributors
- commits
- redacted secret indicators

Next:

- repository timeline
- dependency file parsing
- GitHub Actions checks
- Docker/Terraform/Kubernetes clues
- better secret rule configuration

## Lower priority

These can wait:

- GUI
- Shodan
- Censys
- SecurityTrails
- external tool integrations
- AI summaries
- LLM agents

First, make the default command genuinely useful.

# Security Policy

## Scope

This repository is a research simulation platform (CIDSeeks / VIBE-CIDS Evaluation-2).
It is not intended to be deployed as a production security product.

We still treat security issues in the codebase and artifact tooling seriously,
especially issues that could affect:

- artifact integrity and reproducibility
- unsafe file extraction / path traversal
- unsafe shell execution patterns
- accidental disclosure of internal or sensitive files

## Supported Versions

Security fixes are best-effort for the latest `main` branch (or the branch used
for active paper/artifact preparation).

Older snapshots, archived branches, and experimental forks may not receive
patches.

## Reporting a Vulnerability

Please report vulnerabilities privately to the maintainers before opening a
public issue.

Include:

- affected file(s) / command(s)
- proof of concept or reproduction steps
- expected impact
- proposed mitigation (optional)

If you are unsure whether something is a security issue, report it anyway.

## Response Expectations

Best effort targets (not SLA):

- initial acknowledgement: within 7 days
- triage / severity assessment: within 14 days
- fix or mitigation plan: as soon as practical, depending on paper/release freeze

## Public Disclosure

Please avoid public disclosure until maintainers confirm a fix is available or a
temporary mitigation has been documented.

# Security Policy

## Supported versions

NetSentry is currently pre-1.0. Security fixes are applied to the latest revision on the
default branch; older revisions are not maintained separately.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository, when
available. Do not include secrets, credentials, packet captures, personal data, or details
of infrastructure you do not own. If private reporting is unavailable, open a minimal issue
asking the maintainer for a private contact channel without disclosing exploit details.

Include the affected version/commit, impact, safe reproduction steps, and a suggested fix if
known. Allow maintainers reasonable time to investigate before public disclosure.

## Scope and operational safety

Reports about payload retention, unsafe file handling, unbounded state, privilege handling,
parser crashes, or misleading security decisions are in scope. NetSentry is a passive signal
source, not a prevention control; missed detections and threshold tuning questions may be
limitations rather than vulnerabilities.

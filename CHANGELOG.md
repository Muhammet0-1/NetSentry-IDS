# Changelog

All notable changes to this project will be documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Installable `netsentry-ids` package and `netsentry` CLI.
- Separate capture, parsing, bounded state, rules, engine, reporting, and configuration layers.
- Explainable TCP SYN port-diversity and SYN-rate alerts with windows and cooldowns.
- IPv4/IPv6 and CLI input validation, capability/interface errors, and clean signal handling.
- Network-free unit tests and Python 3.10–3.13 CI quality matrix.
- Privacy, security, contribution, limitation, and legal-use documentation.

### Changed

- Replaced the unbounded global SYN counter with expiring, size-limited source state.
- Replaced the plain text log with minimal-metadata JSON Lines output.
- Disabled the default BPF prefilter so VLAN and supported IPv6 extension layouts reach
  the parser; explicit user filters are still forwarded unchanged after validation.
- Detection windows, state expiry, and cooldowns now use a monotonic clock independently
  from human-readable alert timestamps.
- State TTL must cover every rule window and the complete alert cooldown.
- SYN-rate events and distinct-port recency now use independent bounded structures, so
  repeated traffic to one port cannot evict other in-window port evidence.
- CLI and privacy documentation now distinguish transient Scapy packet materialization from
  disabled payload persistence, analysis, logging, and reporting.
- Unresolvable `~user` output paths now fail as configuration errors before reporting or
  capture initialization.
- Capture callback failures are preserved across Scapy's callback handling and now reach the
  CLI's reporting-error path instead of allowing a successful exit.

### Security

- Packet payloads are excluded from internal models and reports.
- New output files use owner-only permissions by default.
- Alert output is pinned to verified directory/file descriptors; symlinks, special files,
  insecure ownership or permissions, and unsupported safe-open platforms fail closed.
- Every alert-output ancestor is traversed with pinned directory descriptors and `O_NOFOLLOW`.
- Embedded TCP layers are ignored unless they belong to the outer IPv4/IPv6 protocol chain.
- Scoped IPv6 target selectors are rejected instead of silently failing to match packets.

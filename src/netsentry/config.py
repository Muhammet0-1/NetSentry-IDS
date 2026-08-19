"""Validated configuration objects and CLI value parsers."""

from __future__ import annotations

import ipaddress
import math
import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigurationError(ValueError):
    """Raised when a NetSentry setting is unsafe or inconsistent."""


def validate_ip(value: str) -> str:
    """Return a canonical IPv4/IPv6 address or raise a useful error."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigurationError(f"invalid IP address: {value!r}") from exc
    if isinstance(address, ipaddress.IPv6Address) and getattr(address, "scope_id", None):
        raise ConfigurationError(
            "scoped IPv6 addresses are not supported for --target-ip; "
            "select the interface separately with --interface"
        )
    return str(address)


def validate_port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
    return value


def validate_interface_name(value: str) -> str:
    value = value.strip()
    if not value:
        raise ConfigurationError("interface name cannot be empty")
    if len(value) > 128 or any(character.isspace() or ord(character) < 32 for character in value):
        raise ConfigurationError("interface name contains unsupported characters")
    return value


def validate_bpf_filter(value: str) -> str:
    value = value.strip()
    if not value:
        raise ConfigurationError("BPF filter cannot be empty")
    if len(value) > 4096 or any(ord(character) < 32 for character in value):
        raise ConfigurationError("BPF filter contains unsupported control characters")
    return value


def _positive_number(name: str, value: float) -> None:
    if not math.isfinite(value) or value <= 0:
        raise ConfigurationError(f"{name} must be a finite number greater than zero")


def _expand_user_path(path: Path) -> Path:
    try:
        return path.expanduser()
    except RuntimeError as exc:
        raise ConfigurationError(
            "output path could not be expanded; use an existing user or an explicit "
            f"absolute/relative path: {str(path)!r}"
        ) from exc


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Thresholds and hard state limits for SYN-based rules."""

    port_scan_threshold: int = 16
    port_scan_window: float = 60.0
    syn_rate_threshold: int = 100
    syn_rate_window: float = 10.0
    alert_cooldown: float = 120.0
    state_ttl: float = 300.0
    max_sources: int = 4_096
    max_events_per_source: int = 256
    max_ports_per_source: int = 256

    def __post_init__(self) -> None:
        for name in ("port_scan_threshold", "syn_rate_threshold"):
            if getattr(self, name) < 2:
                raise ConfigurationError(f"{name} must be at least 2")
        for name in ("port_scan_window", "syn_rate_window", "state_ttl"):
            _positive_number(name, getattr(self, name))
        if not math.isfinite(self.alert_cooldown) or self.alert_cooldown < 0:
            raise ConfigurationError("alert_cooldown must be finite and non-negative")
        if self.max_sources < 1:
            raise ConfigurationError("max_sources must be at least 1")
        if self.max_events_per_source < self.syn_rate_threshold:
            raise ConfigurationError(
                "max_events_per_source must be at least syn_rate_threshold"
            )
        if self.max_ports_per_source < self.port_scan_threshold:
            raise ConfigurationError(
                "max_ports_per_source must be at least port_scan_threshold"
            )
        if self.state_ttl < max(self.port_scan_window, self.syn_rate_window):
            raise ConfigurationError("state_ttl must be at least as long as every rule window")
        if self.state_ttl < self.alert_cooldown:
            raise ConfigurationError("state_ttl must be at least as long as alert_cooldown")


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Capture and reporting settings."""

    interface: str | None = None
    bpf_filter: str | None = None
    output_path: Path | None = Path("netsentry_alerts.jsonl")
    target_ips: frozenset[str] = field(default_factory=frozenset)
    target_ports: frozenset[int] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.interface is not None:
            object.__setattr__(self, "interface", validate_interface_name(self.interface))
        if self.bpf_filter is not None:
            object.__setattr__(self, "bpf_filter", validate_bpf_filter(self.bpf_filter))
        object.__setattr__(self, "target_ips", frozenset(validate_ip(ip) for ip in self.target_ips))
        object.__setattr__(
            self, "target_ports", frozenset(validate_port(p) for p in self.target_ports)
        )
        if self.output_path is not None:
            path = _expand_user_path(self.output_path)
            if path.is_symlink():
                raise ConfigurationError(f"output path cannot be a symbolic link: {path}")
            if path.exists() and not path.is_file():
                raise ConfigurationError(f"output path is not a regular file: {path}")
            if not path.parent.exists() or not path.parent.is_dir():
                raise ConfigurationError(f"output directory does not exist: {path.parent}")
            writable_target = path if path.exists() else path.parent
            if not os.access(writable_target, os.W_OK):
                raise ConfigurationError(f"output path is not writable: {path}")
            object.__setattr__(self, "output_path", path)

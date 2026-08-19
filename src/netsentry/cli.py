"""Command-line interface for live metadata monitoring."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from collections.abc import Sequence
from pathlib import Path

from netsentry.capture import CaptureError, ScapyLiveCapture
from netsentry.config import (
    ConfigurationError,
    DetectionConfig,
    RuntimeConfig,
    validate_ip,
    validate_port,
)
from netsentry.detector import SynDetector
from netsentry.engine import MonitoringEngine
from netsentry.parser import ScapyPacketParser
from netsentry.reporting import (
    CompositeReporter,
    ConsoleReporter,
    JsonlReporter,
    ManagedReporter,
    ReportingError,
)

PAYLOAD_PRIVACY_NOTICE = (
    "Scapy may transiently materialize full packets, including payload bytes, in process "
    "memory. NetSentry does not analyze, retain in its own state, log, or report payloads; "
    "Scapy packet-list retention is disabled with store=False."
)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _ip(value: str) -> str:
    try:
        return validate_ip(value)
    except ConfigurationError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _port(value: str) -> int:
    try:
        return validate_port(int(value))
    except (ConfigurationError, ValueError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentry",
        description="Observe TCP SYN metadata and report threshold crossings.",
        epilog=f"Privacy: {PAYLOAD_PRIVACY_NOTICE}",
    )
    parser.add_argument("--interface", help="capture interface (default: Scapy default)")
    parser.add_argument(
        "--bpf-filter",
        default=None,
        help="optional libpcap BPF filter (default: disabled)",
    )
    parser.add_argument("--output", type=Path, default=Path("netsentry_alerts.jsonl"))
    parser.add_argument("--no-file-output", action="store_true", help="do not persist alerts")
    parser.add_argument("--quiet", action="store_true", help="do not print alerts to stdout")
    parser.add_argument("--target-ip", action="append", type=_ip, default=[])
    parser.add_argument("--target-port", action="append", type=_port, default=[])
    parser.add_argument("--scan-threshold", type=_positive_int, default=16)
    parser.add_argument("--scan-window", type=_positive_float, default=60.0)
    parser.add_argument("--syn-threshold", type=_positive_int, default=100)
    parser.add_argument("--syn-window", type=_positive_float, default=10.0)
    parser.add_argument("--alert-cooldown", type=float, default=120.0)
    parser.add_argument("--state-ttl", type=_positive_float, default=300.0)
    parser.add_argument("--max-sources", type=_positive_int, default=4_096)
    parser.add_argument("--max-events-per-source", type=_positive_int, default=256)
    parser.add_argument("--max-ports-per-source", type=_positive_int, default=256)
    return parser


def _make_configs(args: argparse.Namespace) -> tuple[DetectionConfig, RuntimeConfig]:
    detection = DetectionConfig(
        port_scan_threshold=args.scan_threshold,
        port_scan_window=args.scan_window,
        syn_rate_threshold=args.syn_threshold,
        syn_rate_window=args.syn_window,
        alert_cooldown=args.alert_cooldown,
        state_ttl=args.state_ttl,
        max_sources=args.max_sources,
        max_events_per_source=args.max_events_per_source,
        max_ports_per_source=args.max_ports_per_source,
    )
    runtime = RuntimeConfig(
        interface=args.interface,
        bpf_filter=args.bpf_filter,
        output_path=None if args.no_file_output else args.output,
        target_ips=frozenset(args.target_ip),
        target_ports=frozenset(args.target_port),
    )
    return detection, runtime


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        detection_config, runtime_config = _make_configs(args)
    except ConfigurationError as exc:
        print(f"netsentry: invalid configuration: {exc}", file=sys.stderr)
        return 2

    reporters: list[ManagedReporter] = []
    try:
        if not args.quiet:
            reporters.append(ConsoleReporter())
        if runtime_config.output_path is not None:
            reporters.append(JsonlReporter(runtime_config.output_path))
    except ReportingError as exc:
        print(f"netsentry: {exc}", file=sys.stderr)
        return 1
    if not reporters:
        print("netsentry: at least one alert output must be enabled", file=sys.stderr)
        return 2

    composite_reporter = CompositeReporter(tuple(reporters))
    engine = MonitoringEngine(
        parser=ScapyPacketParser(),
        detector=SynDetector(detection_config),
        reporter=composite_reporter,
        target_ips=runtime_config.target_ips,
        target_ports=runtime_config.target_ports,
    )
    capture = ScapyLiveCapture(runtime_config.interface, runtime_config.bpf_filter)
    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()
        raise KeyboardInterrupt

    previous_term_handler = signal.signal(signal.SIGTERM, request_stop)
    exit_code = 0
    try:
        selected = capture.resolve_interface()
        print(
            f"NetSentry monitoring interface {selected!r}; "
            "payload persistence and reporting are disabled; "
            "Scapy may transiently materialize full packet payloads in process memory. "
            "Active response is disabled.",
            file=sys.stderr,
        )
        capture.run(engine.handle_packet, stop_event)
    except KeyboardInterrupt:
        print("NetSentry stopped cleanly.", file=sys.stderr)
    except CaptureError as exc:
        print(f"netsentry: {exc}", file=sys.stderr)
        exit_code = 1
    except ReportingError as exc:
        print(f"netsentry: {exc}", file=sys.stderr)
        exit_code = 1
    except Exception as exc:
        print(f"netsentry: unexpected monitoring failure: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        stop_event.set()
        signal.signal(signal.SIGTERM, previous_term_handler)
        try:
            composite_reporter.close()
        except ReportingError as exc:
            print(f"netsentry: {exc}", file=sys.stderr)
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    raise SystemExit(main())

from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

from netsentry.capture import CaptureError, ScapyLiveCapture
from netsentry.cli import build_parser
from netsentry.config import RuntimeConfig
from netsentry.reporting import ReportingError


class SniffRecorder:
    def __init__(self) -> None:
        self.arguments: dict[str, object] | None = None

    def __call__(self, **arguments: object) -> object:
        self.arguments = arguments
        return object()


class CaptureFilterTests(unittest.TestCase):
    def test_runtime_and_cli_defaults_disable_bpf(self) -> None:
        self.assertIsNone(RuntimeConfig(output_path=None).bpf_filter)
        arguments = build_parser().parse_args([])
        self.assertIsNone(arguments.bpf_filter)
        self.assertIn("default: disabled", build_parser().format_help())

    def test_default_capture_omits_filter_keyword(self) -> None:
        recorder = SniffRecorder()
        capture = ScapyLiveCapture(None, None, sniff_function=recorder)
        with (
            patch.object(capture, "resolve_interface", return_value="test0"),
            patch("netsentry.capture.platform.system", return_value="TestOS"),
        ):
            capture.run(lambda _packet: None, threading.Event())
        self.assertIsNotNone(recorder.arguments)
        assert recorder.arguments is not None
        self.assertNotIn("filter", recorder.arguments)
        self.assertEqual(recorder.arguments["iface"], "test0")
        self.assertFalse(recorder.arguments["store"])

    def test_explicit_filter_is_forwarded_unchanged(self) -> None:
        configured = RuntimeConfig(output_path=None, bpf_filter="tcp or udp")
        recorder = SniffRecorder()
        capture = ScapyLiveCapture(None, configured.bpf_filter, sniff_function=recorder)
        with (
            patch.object(capture, "resolve_interface", return_value="test0"),
            patch("netsentry.capture.platform.system", return_value="TestOS"),
        ):
            capture.run(lambda _packet: None, threading.Event())
        self.assertIsNotNone(recorder.arguments)
        assert recorder.arguments is not None
        self.assertEqual(recorder.arguments["filter"], "tcp or udp")

    def test_cli_preserves_explicit_filter_text(self) -> None:
        arguments = build_parser().parse_args(["--bpf-filter", "tcp port 443"])
        self.assertEqual(arguments.bpf_filter, "tcp port 443")

    def test_swallowed_callback_reporting_error_is_reraised(self) -> None:
        failure = ReportingError("synthetic write failure")

        def swallowing_sniff(**arguments: object) -> object:
            guarded_callback = arguments["prn"]
            assert callable(guarded_callback)
            try:
                guarded_callback(object())
            except Exception as exc:
                self.assertIs(exc, failure)
            return object()

        def failing_callback(_packet: object) -> None:
            raise failure

        stop_event = threading.Event()
        capture = ScapyLiveCapture(None, None, sniff_function=swallowing_sniff)
        with (
            patch.object(capture, "resolve_interface", return_value="test0"),
            patch("netsentry.capture.platform.system", return_value="TestOS"),
            self.assertRaises(ReportingError) as raised,
        ):
            capture.run(failing_callback, stop_event)
        self.assertIs(raised.exception, failure)
        self.assertTrue(stop_event.is_set())

    def test_successful_callback_allows_capture_to_return_normally(self) -> None:
        received: list[object] = []
        synthetic_packet = object()

        def successful_sniff(**arguments: object) -> object:
            guarded_callback = arguments["prn"]
            assert callable(guarded_callback)
            guarded_callback(synthetic_packet)
            return object()

        capture = ScapyLiveCapture(None, None, sniff_function=successful_sniff)
        with (
            patch.object(capture, "resolve_interface", return_value="test0"),
            patch("netsentry.capture.platform.system", return_value="TestOS"),
        ):
            capture.run(received.append, threading.Event())
        self.assertEqual(received, [synthetic_packet])

    def test_capture_backend_os_error_remains_a_capture_error(self) -> None:
        def failing_sniff(**_arguments: object) -> object:
            raise OSError("synthetic backend failure")

        capture = ScapyLiveCapture(None, None, sniff_function=failing_sniff)
        with (
            patch.object(capture, "resolve_interface", return_value="test0"),
            patch("netsentry.capture.platform.system", return_value="TestOS"),
            self.assertRaisesRegex(CaptureError, "capture failed: synthetic backend failure"),
        ):
            capture.run(lambda _packet: None, threading.Event())

    def test_callback_os_error_is_not_misclassified_as_capture_failure(self) -> None:
        failure = BrokenPipeError("synthetic reporter failure")

        def invoking_sniff(**arguments: object) -> object:
            guarded_callback = arguments["prn"]
            assert callable(guarded_callback)
            guarded_callback(object())
            return object()

        def failing_callback(_packet: object) -> None:
            raise failure

        capture = ScapyLiveCapture(None, None, sniff_function=invoking_sniff)
        with (
            patch.object(capture, "resolve_interface", return_value="test0"),
            patch("netsentry.capture.platform.system", return_value="TestOS"),
            self.assertRaises(BrokenPipeError) as raised,
        ):
            capture.run(failing_callback, threading.Event())
        self.assertIs(raised.exception, failure)

    def test_callback_base_exception_is_not_stored_or_hidden(self) -> None:
        def invoking_sniff(**arguments: object) -> object:
            guarded_callback = arguments["prn"]
            assert callable(guarded_callback)
            guarded_callback(object())
            return object()

        def interrupted_callback(_packet: object) -> None:
            raise KeyboardInterrupt

        capture = ScapyLiveCapture(None, None, sniff_function=invoking_sniff)
        with (
            patch.object(capture, "resolve_interface", return_value="test0"),
            patch("netsentry.capture.platform.system", return_value="TestOS"),
            self.assertRaises(KeyboardInterrupt),
        ):
            capture.run(interrupted_callback, threading.Event())


if __name__ == "__main__":
    unittest.main()

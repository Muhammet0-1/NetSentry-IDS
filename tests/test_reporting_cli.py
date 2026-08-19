from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from netsentry.cli import build_parser, main
from netsentry.models import Alert
from netsentry.reporting import ConsoleReporter, JsonlReporter, ReportingError


def alert() -> Alert:
    return Alert(
        observed_at=0,
        rule_id="tcp_syn_rate",
        severity="medium",
        reason="synthetic test alert",
        source_ip="198.51.100.1",
        destination_ip="192.0.2.1",
        signals={"syn_count": 3, "threshold": 3},
    )


def descriptor_count() -> int:
    descriptor_directory = Path("/proc/self/fd")
    if not descriptor_directory.is_dir():
        raise unittest.SkipTest("descriptor accounting requires /proc/self/fd")
    return len(list(descriptor_directory.iterdir()))


class SecureJsonlReporterTests(unittest.TestCase):
    def test_normal_output_is_valid_metadata_only_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "alerts.jsonl"
            with JsonlReporter(output) as reporter:
                reporter.report(alert())
                reporter.report(alert())
            lines = output.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            record = json.loads(lines[0])
            self.assertEqual(record["rule_id"], "tcp_syn_rate")
            self.assertNotIn("payload", record)

    def test_new_output_file_has_exactly_0600_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "alerts.jsonl"
            reporter = JsonlReporter(output)
            try:
                self.assertEqual(stat.S_IMODE(os.stat(output).st_mode), 0o600)
            finally:
                reporter.close()

    def test_final_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.write_text("untouched\n", encoding="utf-8")
            target.chmod(0o600)
            link = root / "alerts.jsonl"
            link.symlink_to(target)
            with self.assertRaises(ReportingError):
                JsonlReporter(link)
            self.assertEqual(target.read_text(encoding="utf-8"), "untouched\n")

    def test_direct_parent_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe_target = root / "safe-target"
            safe_target.mkdir(mode=0o700)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(safe_target, target_is_directory=True)
            with self.assertRaises(ReportingError):
                JsonlReporter(linked_parent / "alerts.jsonl")

    def test_grandparent_symlink_to_safe_owned_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe_target = root / "safe-target"
            safe_target.mkdir(mode=0o700)
            (safe_target / "nested").mkdir(mode=0o700)
            linked_grandparent = root / "linked-grandparent"
            linked_grandparent.symlink_to(safe_target, target_is_directory=True)
            with self.assertRaises(ReportingError):
                JsonlReporter(linked_grandparent / "nested" / "alerts.jsonl")

    def test_normal_multicomponent_directory_path_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_parent = Path(directory) / "one" / "two" / "three"
            output_parent.mkdir(parents=True, mode=0o700)
            output = output_parent / "alerts.jsonl"
            with JsonlReporter(output) as reporter:
                reporter.report(alert())
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(record["rule_id"], "tcp_syn_rate")

    def test_relative_path_is_anchored_to_initial_working_directory(self) -> None:
        original_working_directory = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial = root / "initial"
            initial.mkdir(mode=0o700)
            (initial / "logs").mkdir(mode=0o700)
            replacement = root / "replacement"
            replacement.mkdir(mode=0o700)
            os.chdir(initial)
            try:
                reporter = JsonlReporter(Path("logs/alerts.jsonl"))
                os.chdir(replacement)
                try:
                    reporter.report(alert())
                finally:
                    reporter.close()
            finally:
                os.chdir(original_working_directory)
            self.assertTrue((initial / "logs" / "alerts.jsonl").is_file())
            self.assertFalse((replacement / "logs" / "alerts.jsonl").exists())

    def test_parent_traversal_component_is_rejected(self) -> None:
        with self.assertRaisesRegex(ReportingError, "unsafe parent traversal"):
            JsonlReporter(Path("safe/../alerts.jsonl"))

    def test_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "alerts.jsonl"
            os.mkfifo(fifo, 0o600)
            errors: list[Exception] = []

            def attempt_open() -> None:
                try:
                    JsonlReporter(fifo)
                except Exception as exc:
                    errors.append(exc)

            worker = threading.Thread(target=attempt_open, daemon=True)
            worker.start()
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive(), "FIFO open blocked the reporter")
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ReportingError)

    def test_parent_path_replacement_does_not_redirect_open_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validated_parent = root / "validated"
            validated_parent.mkdir(mode=0o700)
            redirected_parent = root / "redirected"
            redirected_parent.mkdir(mode=0o700)
            output = validated_parent / "alerts.jsonl"
            reporter = JsonlReporter(output)

            anchored_parent = root / "anchored"
            validated_parent.rename(anchored_parent)
            validated_parent.symlink_to(redirected_parent, target_is_directory=True)
            try:
                reporter.report(alert())
            finally:
                reporter.close()

            anchored_record = json.loads(
                (anchored_parent / "alerts.jsonl").read_text(encoding="utf-8")
            )
            self.assertEqual(anchored_record["rule_id"], "tcp_syn_rate")
            self.assertFalse((redirected_parent / "alerts.jsonl").exists())

    def test_opened_nonregular_target_is_rejected_after_fstat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "alerts.jsonl"
            real_fstat = os.fstat

            def replace_regular_mode(descriptor: int) -> os.stat_result:
                details = real_fstat(descriptor)
                if stat.S_ISREG(details.st_mode):
                    return os.stat_result(
                        (
                            stat.S_IFIFO | 0o600,
                            details.st_ino,
                            details.st_dev,
                            details.st_nlink,
                            details.st_uid,
                            details.st_gid,
                            details.st_size,
                            details.st_atime,
                            details.st_mtime,
                            details.st_ctime,
                        )
                    )
                return details

            with (
                patch("netsentry.reporting.os.fstat", side_effect=replace_regular_mode),
                self.assertRaisesRegex(ReportingError, "not a regular file"),
            ):
                JsonlReporter(output)

    def test_nonregular_file_modes_are_rejected(self) -> None:
        for file_type in (stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFDIR):
            details = os.stat_result(
                (file_type | 0o600, 0, 0, 1, os.geteuid(), 0, 0, 0, 0, 0)
            )
            with self.subTest(file_type=file_type), self.assertRaises(ReportingError):
                JsonlReporter._validate_file(details)

    def test_insecure_existing_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "alerts.jsonl"
            output.write_text("existing\n", encoding="utf-8")
            output.chmod(0o640)
            with self.assertRaisesRegex(ReportingError, "permissions must not exceed 0600"):
                JsonlReporter(output)

    def test_hard_linked_existing_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.touch(mode=0o600)
            linked_output = root / "alerts.jsonl"
            os.link(target, linked_output)
            with self.assertRaisesRegex(ReportingError, "exactly one hard link"):
                JsonlReporter(linked_output)

    def test_insecure_output_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "unsafe"
            output_directory.mkdir(mode=0o777)
            output_directory.chmod(0o777)
            with self.assertRaisesRegex(ReportingError, "group- or world-writable"):
                JsonlReporter(output_directory / "alerts.jsonl")

    def test_unsupported_safe_open_platform_fails_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("netsentry.reporting.os.supports_dir_fd", set()),
            self.assertRaisesRegex(ReportingError, "unsupported on this platform"),
        ):
            JsonlReporter(Path(directory) / "alerts.jsonl")

    def test_error_and_close_paths_do_not_leak_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.touch(mode=0o600)
            before = descriptor_count()
            for index in range(5):
                link = root / f"bad-{index}.jsonl"
                link.symlink_to(target)
                with self.assertRaises(ReportingError):
                    JsonlReporter(link)
            self.assertEqual(descriptor_count(), before)

            reporter = JsonlReporter(root / "valid.jsonl")
            reporter.close()
            reporter.close()
            self.assertEqual(descriptor_count(), before)

    def test_ancestor_symlink_error_does_not_leak_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir(mode=0o700)
            (target / "nested").mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(target, target_is_directory=True)
            before = descriptor_count()
            for _attempt in range(5):
                with self.assertRaises(ReportingError):
                    JsonlReporter(linked / "nested" / "alerts.jsonl")
            self.assertEqual(descriptor_count(), before)

    def test_closed_reporter_rejects_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            reporter = JsonlReporter(Path(directory) / "alerts.jsonl")
            reporter.close()
            with self.assertRaisesRegex(ReportingError, "reporter is closed"):
                reporter.report(alert())


class ConsoleAndCliTests(unittest.TestCase):
    def test_console_report_is_valid_json(self) -> None:
        stream = io.StringIO()
        reporter = ConsoleReporter(stream)
        reporter.report(alert())
        reporter.close()
        self.assertEqual(json.loads(stream.getvalue())["signals"]["syn_count"], 3)

    def test_cli_rejects_disabling_all_outputs_without_capture(self) -> None:
        self.assertEqual(main(["--quiet", "--no-file-output"]), 2)

    def test_cli_rejects_invalid_cross_field_configuration(self) -> None:
        self.assertEqual(main(["--scan-threshold", "1"]), 2)

    def test_cli_rejects_unexpandable_output_before_reporter_or_capture(self) -> None:
        standard_error = io.StringIO()
        invalid_path = "~netsentry_user_that_cannot_exist_7f9c/alerts.jsonl"
        with (
            patch("netsentry.cli.ConsoleReporter") as console_reporter,
            patch("netsentry.cli.JsonlReporter") as jsonl_reporter,
            patch("netsentry.cli.ScapyLiveCapture") as live_capture,
            redirect_stderr(standard_error),
        ):
            self.assertEqual(main(["--output", invalid_path]), 2)
        console_reporter.assert_not_called()
        jsonl_reporter.assert_not_called()
        live_capture.assert_not_called()
        message = standard_error.getvalue()
        self.assertIn("invalid configuration", message)
        self.assertIn("output path could not be expanded", message)
        self.assertNotIn("Traceback", message)

    def test_cli_startup_message_describes_payload_handling_accurately(self) -> None:
        standard_error = io.StringIO()
        with (
            patch("netsentry.cli.ScapyLiveCapture.resolve_interface", return_value="synthetic0"),
            patch("netsentry.cli.ScapyLiveCapture.run"),
            redirect_stderr(standard_error),
        ):
            self.assertEqual(main(["--no-file-output"]), 0)
        message = standard_error.getvalue().lower()
        self.assertIn("payload persistence and reporting are disabled", message)
        self.assertIn("transiently materialize full packet payloads", message)
        self.assertNotIn("payload capture", message)

    def test_cli_returns_failure_for_reporting_error_from_capture_callback(self) -> None:
        standard_error = io.StringIO()
        with (
            patch("netsentry.cli.ScapyLiveCapture.resolve_interface", return_value="synthetic0"),
            patch(
                "netsentry.cli.ScapyLiveCapture.run",
                side_effect=ReportingError("synthetic callback write failure"),
            ),
            redirect_stderr(standard_error),
        ):
            exit_code = main(["--no-file-output"])
        self.assertEqual(exit_code, 1)
        self.assertNotEqual(exit_code, 0)
        self.assertIn("synthetic callback write failure", standard_error.getvalue())

    def test_cli_help_and_readme_share_accurate_payload_terms(self) -> None:
        help_text = build_parser().format_help().lower()
        readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8").lower()
        for content in (help_text, readme):
            self.assertIn("store=false", content)
            self.assertNotIn("payload capture is disabled", content)
        self.assertIn("transiently materialize full packets", help_text)
        self.assertIn("payload persistence and reporting", readme)


if __name__ == "__main__":
    unittest.main()

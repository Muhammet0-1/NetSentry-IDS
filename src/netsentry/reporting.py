"""Minimal-metadata alert reporters with fail-closed file handling."""

from __future__ import annotations

import json
import os
import stat
import sys
from contextlib import suppress
from pathlib import Path
from types import TracebackType
from typing import Protocol, TextIO

from netsentry.models import Alert


class ReportingError(RuntimeError):
    """Raised when an alert cannot be persisted safely."""


class Reporter(Protocol):
    def report(self, alert: Alert) -> None: ...


class ManagedReporter(Reporter, Protocol):
    def close(self) -> None: ...


class ConsoleReporter:
    def __init__(self, stream: TextIO = sys.stdout) -> None:
        self._stream = stream

    def report(self, alert: Alert) -> None:
        print(json.dumps(alert.as_dict(), sort_keys=True), file=self._stream, flush=True)

    def close(self) -> None:
        """Do not close a caller-owned console stream."""


class JsonlReporter:
    """Append JSONL through pinned, verified directory and file descriptors."""

    _REQUIRED_FLAGS = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")

    def __init__(self, path: Path) -> None:
        self._path = path
        self._directory_fd: int | None = None
        self._file_fd: int | None = None
        self._open_securely()

    def _open_securely(self) -> None:
        self._ensure_supported_platform()
        filename = self._path.name
        if filename in {"", ".", ".."}:
            raise ReportingError(f"invalid alert output filename: {filename!r}")
        if ".." in self._path.parts:
            raise ReportingError("alert output path contains an unsafe parent traversal component")

        existing_file_flags = (
            os.O_APPEND
            | os.O_WRONLY
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
            | os.O_NONBLOCK
        )
        directory_fd: int | None = None
        file_fd: int | None = None
        try:
            directory_fd = self._open_directory_chain(self._path.parent)
            try:
                file_fd = os.open(
                    filename,
                    existing_file_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                file_fd = os.open(filename, existing_file_flags, dir_fd=directory_fd)
            else:
                os.fchmod(file_fd, 0o600)
            self._validate_file(os.fstat(file_fd))
        except ReportingError:
            self._close_fd(file_fd)
            self._close_fd(directory_fd)
            raise
        except OSError as exc:
            self._close_fd(file_fd)
            self._close_fd(directory_fd)
            raise ReportingError(f"could not safely open alert output {self._path}: {exc}") from exc

        self._directory_fd = directory_fd
        self._file_fd = file_fd

    @classmethod
    def _open_directory_chain(cls, directory: Path) -> int:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        if directory.is_absolute():
            if directory.anchor != os.sep:
                raise ReportingError(
                    f"unsupported absolute output path anchor: {directory.anchor!r}"
                )
            start = os.sep
            components = directory.parts[1:]
        else:
            start = "."
            components = tuple(component for component in directory.parts if component != ".")
        if any(component in {"", ".", ".."} for component in components):
            raise ReportingError("alert output path contains an unsafe directory component")

        opened: list[int] = []
        final_fd: int | None = None
        try:
            start_fd = os.open(start, directory_flags)
            opened.append(start_fd)
            cls._validate_directory_type(os.fstat(start_fd))
            for component in components:
                next_fd = os.open(component, directory_flags, dir_fd=opened[-1])
                opened.append(next_fd)
                cls._validate_directory_type(os.fstat(next_fd))

            final_fd = opened.pop()
            while opened:
                os.close(opened.pop())
            cls._validate_directory(os.fstat(final_fd))
            result = final_fd
            final_fd = None
            return result
        finally:
            cls._close_fd(final_fd)
            while opened:
                cls._close_fd(opened.pop())

    @classmethod
    def _ensure_supported_platform(cls) -> None:
        missing = [name for name in cls._REQUIRED_FLAGS if not hasattr(os, name)]
        if not hasattr(os, "geteuid"):
            missing.append("geteuid")
        if not hasattr(os, "fchmod"):
            missing.append("fchmod")
        supports_dir_fd: set[object] = getattr(os, "supports_dir_fd", set())
        if os.open not in supports_dir_fd:
            missing.append("open(dir_fd=...)")
        if missing:
            names = ", ".join(missing)
            raise ReportingError(f"secure alert output is unsupported on this platform: {names}")

    @staticmethod
    def _validate_directory_type(details: os.stat_result) -> None:
        if not stat.S_ISDIR(details.st_mode):
            raise ReportingError("alert output parent is not a directory")

    @classmethod
    def _validate_directory(cls, details: os.stat_result) -> None:
        cls._validate_directory_type(details)
        if details.st_uid != os.geteuid():
            raise ReportingError("alert output directory must be owned by the effective user")
        if stat.S_IMODE(details.st_mode) & 0o022:
            raise ReportingError("alert output directory cannot be group- or world-writable")

    @staticmethod
    def _validate_file(details: os.stat_result) -> None:
        if not stat.S_ISREG(details.st_mode):
            raise ReportingError("alert output target is not a regular file")
        if details.st_uid != os.geteuid():
            raise ReportingError("alert output file must be owned by the effective user")
        if stat.S_IMODE(details.st_mode) & ~0o600:
            raise ReportingError("alert output file permissions must not exceed 0600")
        if details.st_nlink != 1:
            raise ReportingError("alert output file must have exactly one hard link")

    def report(self, alert: Alert) -> None:
        descriptor = self._file_fd
        if descriptor is None:
            raise ReportingError("alert output reporter is closed")
        serialized = json.dumps(alert.as_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        remaining = memoryview(serialized.encode("utf-8"))
        try:
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("zero-byte alert output write")
                remaining = remaining[written:]
            os.fsync(descriptor)
        except OSError as exc:
            self._close_descriptors(ignore_errors=True)
            raise ReportingError(f"could not write alert output {self._path}: {exc}") from exc

    def close(self) -> None:
        errors = self._close_descriptors(ignore_errors=False)
        if errors:
            raise ReportingError(f"could not close alert output cleanly: {errors[0]}")

    def _close_descriptors(self, *, ignore_errors: bool) -> list[OSError]:
        errors: list[OSError] = []
        file_fd, self._file_fd = self._file_fd, None
        directory_fd, self._directory_fd = self._directory_fd, None
        for descriptor in (file_fd, directory_fd):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as exc:
                if not ignore_errors:
                    errors.append(exc)
        return errors

    @staticmethod
    def _close_fd(descriptor: int | None) -> None:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)

    def __enter__(self) -> JsonlReporter:
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self._close_descriptors(ignore_errors=True)


class CompositeReporter:
    def __init__(self, reporters: tuple[ManagedReporter, ...]) -> None:
        self._reporters = reporters

    def report(self, alert: Alert) -> None:
        for reporter in self._reporters:
            reporter.report(alert)

    def close(self) -> None:
        errors: list[ReportingError] = []
        for reporter in reversed(self._reporters):
            try:
                reporter.close()
            except ReportingError as exc:
                errors.append(exc)
        if errors:
            raise ReportingError(str(errors[0]))

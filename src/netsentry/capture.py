"""Scapy live-capture adapter and capability checks."""

from __future__ import annotations

import os
import platform
import threading
from collections.abc import Callable


class CaptureError(RuntimeError):
    """A safe, user-facing live capture error."""


def _has_linux_capture_capability() -> bool:
    if os.geteuid() == 0:
        return True
    try:
        with open("/proc/self/status", encoding="utf-8") as status_file:
            capability_line = next(
                line for line in status_file if line.startswith("CapEff:")
            )
        effective = int(capability_line.split()[1], 16)
        cap_net_raw = 1 << 13
        return bool(effective & cap_net_raw)
    except (OSError, StopIteration, ValueError):
        return False


class ScapyLiveCapture:
    def __init__(
        self,
        interface: str | None,
        bpf_filter: str | None,
        sniff_function: Callable[..., object] | None = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._sniff_function = sniff_function

    def resolve_interface(self) -> str:
        try:
            from scapy.all import conf, get_if_list

            available = [str(name) for name in get_if_list()]
            selected = self.interface or str(conf.iface)
        except ImportError as exc:
            raise CaptureError("Scapy is not installed; install the netsentry package") from exc
        except Exception as exc:
            raise CaptureError(f"could not query network interfaces: {exc}") from exc
        if selected not in available:
            choices = ", ".join(available) if available else "none detected"
            raise CaptureError(
                f"network interface {selected!r} was not found (available: {choices})"
            )
        self.interface = selected
        return selected

    def run(self, callback: Callable[[object], None], stop_event: threading.Event) -> None:
        selected = self.resolve_interface()
        if platform.system() == "Linux" and not _has_linux_capture_capability():
            raise CaptureError("live capture requires root or an appropriate CAP_NET_RAW setup")
        if self._sniff_function is not None:
            self._invoke_sniff(self._sniff_function, selected, callback, stop_event)
            return
        try:
            from scapy.all import sniff
            from scapy.error import Scapy_Exception
        except ImportError as exc:
            raise CaptureError("Scapy is not installed; install the netsentry package") from exc

        try:
            self._invoke_sniff(sniff, selected, callback, stop_event)
        except Scapy_Exception as exc:
            filter_hint = " and BPF filter" if self.bpf_filter is not None else ""
            raise CaptureError(
                f"capture could not start; check the interface{filter_hint}: {exc}"
            ) from exc

    def _invoke_sniff(
        self,
        sniff_function: Callable[..., object],
        interface: str,
        callback: Callable[[object], None],
        stop_event: threading.Event,
    ) -> None:
        callback_error: Exception | None = None

        def guarded_callback(packet: object) -> None:
            nonlocal callback_error
            try:
                callback(packet)
            except Exception as exc:
                if callback_error is None:
                    callback_error = exc
                stop_event.set()
                raise

        arguments: dict[str, object] = {
            "iface": interface,
            "prn": guarded_callback,
            "store": False,
            "stop_filter": lambda _packet: stop_event.is_set(),
        }
        if self.bpf_filter is not None:
            arguments["filter"] = self.bpf_filter
        try:
            sniff_function(**arguments)
        except PermissionError as exc:
            if callback_error is not None:
                raise callback_error from None
            raise CaptureError("permission denied while opening the capture interface") from exc
        except OSError as exc:
            if callback_error is not None:
                raise callback_error from None
            raise CaptureError(f"capture failed: {exc}") from exc
        if callback_error is not None:
            raise callback_error

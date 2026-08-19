"""Compatibility launcher; prefer the installed ``netsentry`` command."""

import sys
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
main = import_module("netsentry.cli").main


if __name__ == "__main__":
    raise SystemExit(main())

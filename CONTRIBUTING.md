# Contributing

Thank you for improving NetSentry. Keep changes defensive, narrowly scoped, and testable
without access to live networks.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Before submitting a change, run:

```bash
python -m pytest
ruff check .
mypy
python -m compileall -q src tests net_sentry.py
python -m build
```

## Expectations

- Add unit tests for detection thresholds, time windows, cleanup, and malformed input.
- Do not use live capture, scanning, attack traffic, or firewall changes in tests.
- Do not add packet payloads, credentials, real traffic captures, private infrastructure
  details, or personal data to fixtures, logs, issues, or commits.
- Document behavior and defaults without unsupported security or accuracy claims.
- Keep active response out of default behavior. A future active-response proposal must be
  separately reviewed and require explicit operator opt-in.
- Update `CHANGELOG.md` for user-visible changes.

Pull requests should explain the motivation, behavioral changes, verification performed,
privacy impact, and any operational compatibility concerns.

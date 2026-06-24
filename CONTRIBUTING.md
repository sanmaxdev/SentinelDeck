# Contributing to SentinelDeck

Thanks for taking the time to contribute. SentinelDeck is a passive,
safety-first scanner, and contributions are very welcome — especially new
checks, accuracy fixes, and better remediation guidance.

## Ground rules

- **Stay passive.** SentinelDeck only performs normal DNS lookups and standard
  HTTP/TLS metadata requests against the target. We do not accept features that
  perform intrusive scanning, brute forcing, exploitation, or anything that a
  domain owner would not expect from a routine connection.
- **Accuracy over noise.** A false positive in a client-facing report is worse
  than a missed finding. If a check cannot be determined conclusively, mark the
  finding `indeterminate` so it is reported but not scored.
- **No new heavy dependencies** without discussion. The runtime depends only on
  `dnspython` and `cryptography`.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

```bash
ruff check .
pytest -q
```

Both must pass. New behaviour needs tests; network calls in tests must be
mocked (see `tests/` for the resolver/fetcher injection patterns).

## Adding a new check

1. Add or extend a scanner under `src/sentineldeck/scanners/`. Keep the network
   call injectable so it can be tested offline.
2. Turn its result into findings in `src/sentineldeck/risk/scoring.py`.
3. Wire the scanner into `src/sentineldeck/scanner.py`.
4. Add tests and update the checks list in the `README`.

## Commit messages

Write in plain, descriptive language: a short summary line, then a paragraph or
two explaining what changed and why.

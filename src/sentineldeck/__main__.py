"""Allow ``python -m sentineldeck`` as an alternative to the ``sentineldeck``
console script. Handy when pip did a user install and the Scripts directory is
not on PATH, so the command is not found but the package still imports.
"""
from sentineldeck.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

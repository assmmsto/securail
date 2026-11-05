#!/usr/bin/env python3
"""Launcher so the tool can be run as `python -X utf8 securail.py [...]`
without installing the package. Equivalent to `python -m securail`."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from securail.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

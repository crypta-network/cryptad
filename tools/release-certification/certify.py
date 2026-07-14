#!/usr/bin/env python3
"""Run Cryptad release-certification collectors, gates, and release workflows."""

import sys

sys.dont_write_bytecode = True

from cryptad_certification.cli import main


if __name__ == "__main__":
    raise SystemExit(main())

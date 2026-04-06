#!/usr/bin/env python3
"""Backwards-compatible command-line entrypoint for libPQC."""

from src.app.cli import main


if __name__ == "__main__":
    raise SystemExit(main())

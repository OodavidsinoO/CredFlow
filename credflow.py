#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests>=2.31.0",
#     "urllib3>=2.0.0",
#     "python-dotenv>=1.0.0",
# ]
# ///
"""CredFlow — single-file entry point for `uv run credflow.py <command>`.

Usage:
    uv run credflow.py check
    uv run credflow.py run --targets targets.csv
    uv run credflow.py status
    uv run credflow.py retry

This script auto-imports the credflow package from the sibling `credflow/` directory.
uv adds the script's directory to sys.path, so sibling imports work transparently.
"""

from credflow.cli import main

if __name__ == "__main__":
    main()

"""PyInstaller entry point kept outside the package for reliable imports."""

from mcp_buddy.cli import main


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Consistent SQLite backup/restore with integrity checks and restore rollback copy."""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import sqlite3
import sys


def verify(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise RuntimeError(f"SQLite integrity check failed: {result!r}")


def copy_database(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as destination_db:
        verify(source_db)
        source_db.backup(destination_db)
        verify(destination_db)


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    backup = subcommands.add_parser("backup")
    backup.add_argument("database", type=pathlib.Path)
    backup.add_argument("output", type=pathlib.Path)
    restore = subcommands.add_parser("restore")
    restore.add_argument("backup", type=pathlib.Path)
    restore.add_argument("database", type=pathlib.Path)
    args = parser.parse_args()

    if args.command == "backup":
        if not args.database.is_file():
            raise FileNotFoundError(args.database)
        copy_database(args.database, args.output)
        print(f"verified backup: {args.output}")
        return 0

    if not args.backup.is_file():
        raise FileNotFoundError(args.backup)
    rollback = None
    if args.database.exists():
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rollback = args.database.with_name(args.database.name + f".pre-restore-{stamp}.sqlite3")
        copy_database(args.database, rollback)
    copy_database(args.backup, args.database)
    print(f"verified restore: {args.database}")
    if rollback:
        print(f"rollback copy: {rollback}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"database operation failed: {error}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Offline signature verification + single-use approval reservation.

Development-only component: this does NOT grant release, signing, publishing or
deployment authority. The ledger must reside on Owner-controlled *persistent*
trusted storage before any future controller activation. GitHub-hosted runners
do not provide durable cross-run ledger storage.
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import sqlite3
import stat
import sys

from verify_approval import Denied, unique_pairs, verify


SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_approvals (
    approval_id TEXT PRIMARY KEY NOT NULL,
    controller_sha TEXT NOT NULL,
    candidate_sha TEXT NOT NULL,
    candidate_ref TEXT NOT NULL,
    consumed_at TEXT NOT NULL
)
"""


def require(ok, why):
    if not ok:
        raise Denied(why)


def safe_ledger_path(ledger_path):
    path = pathlib.Path(ledger_path)
    require(path.is_absolute(), "ledger path must be absolute")
    directory = path.parent
    parent = os.lstat(directory)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
            parent.st_mode & 0o077 == 0, "ledger parent must be owner-only directory")
    require(path.name not in ("", ".", ".."), "invalid ledger filename")
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        # sqlite3.connect() honors process umask and could create a 0644 file.
        # Pre-create exclusively with owner-only mode, never following symlinks.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise Denied("concurrent ledger initialization refused") from exc
        else:
            os.close(fd)
    else:
        require(stat.S_ISREG(existing.st_mode) and existing.st_uid == os.geteuid()
                and existing.st_mode & 0o077 == 0, "ledger must be private regular file")
    return path


def reserve_once(path, payload):
    """Reserve exactly once, fail closed for every replay or database error.

    SQLite UNIQUE index + BEGIN IMMEDIATE enforce single-winner concurrency
    within one protected persistent database. A wiped or replicated-out-of-sync
    database cannot provide global replay prevention.
    """
    safe_path = safe_ledger_path(path)
    conn = None
    try:
        conn = sqlite3.connect(str(safe_path), timeout=10, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(SCHEMA)
        conn.execute(
            "INSERT INTO consumed_approvals "
            "(approval_id,controller_sha,candidate_sha,candidate_ref,consumed_at) "
            "VALUES (?,?,?,?,?)",
            (payload["approval_id"], payload["controller_sha"],
             payload["candidate_sha"], payload["candidate_ref"],
             dt.datetime.now(dt.timezone.utc).isoformat()))
        conn.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        if conn is not None and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise Denied("approval ID replay or duplicate") from exc
    except sqlite3.Error as exc:
        if conn is not None and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise Denied("trusted replay ledger unavailable") from exc
    finally:
        if conn is not None:
            conn.close()
    # The database is never used if its owner/mode changed during reservation.
    st = os.lstat(safe_path)
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
            st.st_mode & 0o077 == 0, "ledger file permissions invalid")


def verify_and_reserve(envelope, owner_public_key, controller_sha,
                       candidate_sha, candidate_ref, ledger_path):
    # Clock can only be sourced from the trusted host, not request-supplied.
    now = dt.datetime.now(dt.timezone.utc)
    verify(envelope, owner_public_key, controller_sha, candidate_sha, candidate_ref, now)
    reserve_once(ledger_path, envelope["payload"])
    return True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--approval", required=True)
    parser.add_argument("--owner-public-key", required=True)
    parser.add_argument("--controller-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--ledger", required=True)
    args = parser.parse_args(argv)
    try:
        approval = pathlib.Path(args.approval)
        require(approval.is_file() and approval.stat().st_size <= 65536,
                "approval missing or oversized")
        envelope = json.loads(approval.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_pairs)
        verify_and_reserve(envelope, args.owner_public_key, args.controller_sha,
                           args.candidate_sha, args.candidate_ref, args.ledger)
    except (Denied, OSError, ValueError, sqlite3.Error) as exc:
        print("APPROVAL_RESERVATION=DENIED: " + str(exc), file=sys.stderr)
        return 1
    print("OWNER_APPROVAL_SIGNATURE=PASS")
    print("APPROVAL_SINGLE_USE_RESERVATION=PASS")
    print("RELEASE_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    sys.exit(main())

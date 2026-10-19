#!/usr/bin/env python3
"""Temporary-key/synthetic-only, no real Owner signing authority."""
import base64
import datetime as dt
import importlib.util
import json
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(BASE))
import reserve_approval as reserve
import verify_approval as policy


CONTROL = "b" * 40
CANDIDATE = "a" * 40
REF = "refs/heads/release/candidate/fixture"
PROFILE = policy.SOLO_OWNER_OPEN_BETA


class ReplayLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        root = pathlib.Path(cls.keys.name)
        cls.private = root / "synthetic-only.pem"
        cls.public = root / "synthetic-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(cls.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private),
                        "-pubout", "-out", str(cls.public)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.owner = self.root / "owner_only"
        self.owner.mkdir(mode=0o700)
        self.ledger = self.owner / "consumed.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def signed(self, approval_id="synthetic-approval-0001", sha=CANDIDATE):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        payload = {
            "version": 1, "repository": "ihacked07/mantrix",
            "controller_repository": "ihacked07/mantrix-release-controller",
            "controller_ref": "refs/heads/main", "controller_sha": CONTROL,
            "candidate_ref": REF, "candidate_sha": sha, "trust_profile": PROFILE,
            "purpose": "authorize_isolated_release_build",
            "signer": "owner:ihacked07", "approval_id": approval_id,
            "issued_at": (now-dt.timedelta(minutes=5)).isoformat().replace("+00:00","Z"),
            "expires_at": (now+dt.timedelta(minutes=5)).isoformat().replace("+00:00","Z"),
        }
        with tempfile.TemporaryDirectory() as workspace:
            document = pathlib.Path(workspace)/"payload.json"
            signature = pathlib.Path(workspace)/"signature.bin"
            document.write_bytes(policy.canonical(payload))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin",
                            "-inkey", str(self.private), "-in", str(document),
                            "-out", str(signature)], check=True, capture_output=True)
            return {"payload": payload,
                    "signature_b64": base64.b64encode(signature.read_bytes()).decode("ascii")}

    def reserve(self, envelope):
        return reserve.verify_and_reserve(envelope, self.public, CONTROL,
                                          CANDIDATE, REF, PROFILE, self.ledger)

    def test_first_valid_reservation_and_persistent_replay_rejected(self):
        approval = self.signed()
        self.assertTrue(self.reserve(approval))
        with self.assertRaises(policy.Denied):
            self.reserve(approval)
        with sqlite3.connect(self.ledger) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM consumed_approvals")
                             .fetchone()[0], 1)

    def test_distinct_signed_approvals_can_each_be_consumed_once(self):
        self.assertTrue(self.reserve(self.signed("synthetic-approval-0001")))
        self.assertTrue(self.reserve(self.signed("synthetic-approval-0002")))

    def test_same_id_different_signed_payload_is_replay(self):
        self.reserve(self.signed())
        modified = self.signed(sha="c" * 40)
        with self.assertRaises(policy.Denied):
            reserve.verify_and_reserve(modified, self.public, CONTROL,
                                       "c" * 40, REF, PROFILE, self.ledger)

    def test_profile_is_signature_bound(self):
        with self.assertRaises(policy.Denied):
            reserve.verify_and_reserve(self.signed(), self.public, CONTROL,
                                       CANDIDATE, REF,
                                       policy.INDEPENDENT_REVIEW_RELEASE, self.ledger)

    def test_tampering_denied_before_ledger_access(self):
        approval = self.signed()
        approval["payload"]["approval_id"] = "modified-approval-00001"
        with self.assertRaises(policy.Denied):
            self.reserve(approval)
        self.assertFalse(self.ledger.exists())

    def test_public_directory_refused(self):
        self.owner.chmod(0o755)
        with self.assertRaises(policy.Denied):
            self.reserve(self.signed())

    def test_symlink_ledger_refused(self):
        target = self.owner/"real.sqlite3"
        target.touch(mode=0o600)
        self.ledger.symlink_to(target)
        with self.assertRaises(policy.Denied):
            self.reserve(self.signed())

    def test_preexisting_world_readable_database_refused(self):
        self.ledger.touch(mode=0o644)
        with self.assertRaises(policy.Denied):
            self.reserve(self.signed())

    def test_clock_override_not_offered(self):
        with self.assertRaises(SystemExit) as rejected:
            reserve.main(["--approval", "/nonexistent", "--owner-public-key",
                          str(self.public), "--controller-sha", CONTROL,
                          "--candidate-sha", CANDIDATE, "--candidate-ref", REF,
                          "--trust-profile", PROFILE, "--ledger", str(self.ledger),
                          "--now", "2026-10-19T12:00:00Z"])
        self.assertEqual(rejected.exception.code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

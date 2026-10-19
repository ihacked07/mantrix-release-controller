#!/usr/bin/env python3
"""Offline contract cases; all private Ed25519 keys are ephemeral fixtures."""
import base64
import copy
import datetime as dt
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "verify_approval.py"
SPEC = importlib.util.spec_from_file_location("verify_approval", PATH)
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
CONTROL = "b" * 40
CANDIDATE = "a" * 40
REF = "refs/heads/release/candidate/mantrix-20261019"
NOW = dt.datetime(2026, 10, 19, 12, 0, 0, tzinfo=dt.timezone.utc)


def fixture():
    return {
        "version": 1, "repository": "ihacked07/mantrix",
        "controller_repository": "ihacked07/mantrix-release-controller",
        "controller_ref": "refs/heads/main", "controller_sha": CONTROL,
        "candidate_ref": REF, "candidate_sha": CANDIDATE,
        "purpose": "authorize_isolated_release_build",
        "signer": "owner:ihacked07", "approval_id": "fixture-approval-0001",
        "issued_at": "2026-10-19T11:00:00Z", "expires_at": "2026-10-19T13:00:00Z",
    }


class OwnerApprovalContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        root = pathlib.Path(cls.folder.name)
        cls.key = root / "private.pem"
        cls.pub = root / "public.pem"
        cls.wrong_key = root / "wrong-private.pem"
        cls.wrong_pub = root / "wrong-public.pem"
        for key, pub in [(cls.key, cls.pub), (cls.wrong_key, cls.wrong_pub)]:
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
                           check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(key),
                            "-pubout", "-out", str(pub)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def signed(self, payload=None):
        body = copy.deepcopy(payload) if payload is not None else fixture()
        with tempfile.TemporaryDirectory() as folder:
            src = pathlib.Path(folder) / "payload.json"
            sig = pathlib.Path(folder) / "signature"
            src.write_bytes(policy.canonical(body))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
                            str(self.key), "-in", str(src), "-out", str(sig)],
                           capture_output=True, check=True)
            return {"payload": body,
                    "signature_b64": base64.b64encode(sig.read_bytes()).decode("ascii")}

    def check(self, envelope, **overrides):
        return policy.verify(
            envelope,
            overrides.get("public_key", self.pub),
            overrides.get("controller_sha", CONTROL),
            overrides.get("candidate_sha", CANDIDATE),
            overrides.get("candidate_ref", REF),
            overrides.get("now", NOW),
        )

    def denied(self, envelope, **kwargs):
        with self.assertRaises(policy.Denied):
            self.check(envelope, **kwargs)

    def test_cli_rejects_clock_override(self):
        # A caller must never revive an expired approval by overriding the clock.
        with self.assertRaises(SystemExit) as caught:
            policy.main(["--approval", "/nonexistent", "--owner-public-key",
                         str(self.pub), "--controller-sha", CONTROL,
                         "--candidate-sha", CANDIDATE, "--candidate-ref", REF,
                         "--now", "2026-10-19T12:00:00Z"])
        self.assertEqual(caught.exception.code, 2)

    def test_valid_ed25519_fixture(self):
        self.assertTrue(self.check(self.signed()))

    def test_payload_tamper_after_signing(self):
        env = self.signed()
        env["payload"]["candidate_sha"] = "c" * 40
        self.denied(env, candidate_sha="c" * 40)

    def test_wrong_public_key(self):
        self.denied(self.signed(), public_key=self.wrong_pub)

    def test_wrong_candidate_sha(self):
        self.denied(self.signed(), candidate_sha="c" * 40)

    def test_wrong_controller_sha(self):
        self.denied(self.signed(), controller_sha="c" * 40)

    def test_wrong_candidate_ref(self):
        self.denied(self.signed(), candidate_ref="refs/heads/release/candidate/other")

    def test_untrusted_branch_ref(self):
        self.denied(self.signed(), candidate_ref="refs/heads/codex/untrusted")

    def test_expired_approval(self):
        self.denied(self.signed(), now=dt.datetime(2026,10,20,tzinfo=dt.timezone.utc))

    def test_future_approval(self):
        self.denied(self.signed(), now=dt.datetime(2026,10,19,9,tzinfo=dt.timezone.utc))

    def test_overlong_approval(self):
        payload = fixture()
        payload["expires_at"] = "2026-10-21T13:00:00Z"
        self.denied(self.signed(payload))

    def test_other_repo(self):
        payload = fixture()
        payload["repository"] = "another/repo"
        self.denied(self.signed(payload))

    def test_other_controller(self):
        payload = fixture()
        payload["controller_repository"] = "other/controller"
        self.denied(self.signed(payload))

    def test_unexpected_owner_signer(self):
        payload = fixture()
        payload["signer"] = "untrusted:actor"
        self.denied(self.signed(payload))

    def test_wrong_purpose(self):
        payload = fixture()
        payload["purpose"] = "deploy_prod"
        self.denied(self.signed(payload))

    def test_missing_required_field(self):
        payload = fixture()
        del payload["approval_id"]
        self.denied(self.signed(payload))

    def test_unknown_field(self):
        payload = fixture()
        payload["allow_publish"] = True
        self.denied(self.signed(payload))

    def test_signature_corruption(self):
        env = self.signed()
        env["signature_b64"] = base64.b64encode(b"\x00" * 64).decode()
        self.denied(env)

    def test_signature_malformed(self):
        env = self.signed()
        env["signature_b64"] = "!?"
        self.denied(env)

    def test_wrong_sha_format(self):
        self.denied(self.signed(), controller_sha="not-a-SHA")

    def test_duplicate_json_key(self):
        with self.assertRaises(policy.Denied):
            json.loads('{"version":1,"version":2}', object_pairs_hook=policy.unique_pairs)

    def test_canonical_json_deterministic(self):
        self.assertEqual(policy.canonical({"b":2,"a":1}), b'{"a":1,"b":2}')

    def test_approval_time_non_utc_rejected(self):
        with self.assertRaises(policy.Denied):
            policy.time_utc("2026-10-19T11:00:00+07:00")

    def test_no_release_or_publish_callable(self):
        self.assertFalse(hasattr(policy, "publish"))
        self.assertFalse(hasattr(policy, "release"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

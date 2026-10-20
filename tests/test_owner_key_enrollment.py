#!/usr/bin/env python3
"""Synthetic Ed25519 fixtures only; no Owner key is read or enrolled."""
import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("enrollment", BASE / "owner_key_enrollment.py")
enrollment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(enrollment)


class OwnerKeyEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.private = self.root / "synthetic-private.pem"
        self.public = self.root / "synthetic-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.private)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout",
                        "-out", str(self.public)], check=True, capture_output=True)
        self.public.chmod(0o600)
        self.expected = enrollment.fingerprint(self.public)

    def tearDown(self):
        self.temp.cleanup()

    def test_synthetic_ed25519_key_matches_out_of_band_fingerprint(self):
        result = enrollment.validate_enrollment(self.public, self.expected)
        self.assertEqual(result["algorithm"], "Ed25519")
        self.assertEqual(result["fingerprint"], self.expected)
        self.assertFalse(result["release_authorized"])

    def test_mismatched_or_malformed_fingerprint_is_refused(self):
        with self.assertRaises(enrollment.Refused):
            enrollment.validate_enrollment(self.public, "SHA256:" + "A" * 43)
        with self.assertRaises(enrollment.Refused):
            enrollment.validate_enrollment(self.public, "not-a-fingerprint")

    def test_public_key_file_must_be_private_regular_owner_file(self):
        self.public.chmod(0o644)
        with self.assertRaises(enrollment.Refused):
            enrollment.fingerprint(self.public)
        self.public.chmod(0o600)
        link = self.root / "key-link.pem"
        link.symlink_to(self.public)
        with self.assertRaises(enrollment.Refused):
            enrollment.fingerprint(link)

    def test_non_ed25519_public_key_is_refused(self):
        rsa_private = self.root / "synthetic-rsa-private.pem"
        rsa_public = self.root / "synthetic-rsa-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(rsa_private)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(rsa_private), "-pubout",
                        "-out", str(rsa_public)], check=True, capture_output=True)
        rsa_public.chmod(0o600)
        with self.assertRaises(enrollment.Refused):
            enrollment.fingerprint(rsa_public)


if __name__ == "__main__":
    unittest.main(verbosity=2)

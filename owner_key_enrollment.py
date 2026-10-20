#!/usr/bin/env python3
"""Validate an Owner-supplied Ed25519 public-key enrollment fingerprint.

Development-only: this tool neither stores a key nor enables a controller. It
provides a fail-closed ceremony check before an Owner manually pins a public
key in a separately approved, protected controller configuration.
"""
import argparse
import base64
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import tempfile


class Refused(ValueError):
    pass


def require(condition, detail):
    if not condition:
        raise Refused(detail)


def private_regular_file(value):
    path = pathlib.Path(value)
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            not info.st_mode & 0o077 and 0 < info.st_size <= 16384,
            "Owner public-key file must be private, regular, and bounded")
    return path


def spki_der(public_key_path):
    path = private_regular_file(public_key_path)
    with tempfile.TemporaryDirectory(prefix="mantrix-owner-key-") as folder:
        output = pathlib.Path(folder) / "public.der"
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(path), "-pubout",
             "-outform", "DER", "-out", str(output)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=10)
        require(result.returncode == 0 and output.is_file(),
                "invalid Owner public-key PEM")
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(path), "-text_pub", "-noout"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            check=False, timeout=10)
        require(result.returncode == 0 and "ED25519 Public-Key:" in result.stdout,
                "Owner public key must be Ed25519")
        return output.read_bytes()


def fingerprint(public_key_path):
    digest = hashlib.sha256(spki_der(public_key_path)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def validate_enrollment(public_key_path, expected_fingerprint):
    require(isinstance(expected_fingerprint, str) and
            re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected_fingerprint) is not None,
            "expected fingerprint format invalid")
    observed = fingerprint(public_key_path)
    require(observed == expected_fingerprint, "Owner public-key fingerprint mismatch")
    return {"algorithm": "Ed25519", "fingerprint": observed,
            "enrollment_verified": True, "release_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner-public-key", required=True)
    parser.add_argument("--expected-fingerprint", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_enrollment(args.owner_public_key, args.expected_fingerprint)
    except (Refused, OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("OWNER_KEY_ENROLLMENT=REFUSED: " + str(exc))
    print("OWNER_KEY_ENROLLMENT=PASS")
    print("OWNER_KEY_ALGORITHM=" + result["algorithm"])
    print("OWNER_KEY_FINGERPRINT=" + result["fingerprint"])
    print("RELEASE_AUTHORIZED=NO")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Offline Ed25519 Owner approval verifier for an ISOLATED controller.

This checks a signed build-authorization record only. It is not a GitHub API
collector, container verification, publishing, or deployment authorization.
The trusted controller must independently pin all CLI values and its public key.
"""
import argparse
import base64
import binascii
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import tempfile

REPO = "ihacked07/mantrix"
CONTROLLER_REPO = "ihacked07/mantrix-release-controller"
CONTROL_REF = "refs/heads/main"
CANDIDATE_REF = re.compile(r"^refs/heads/release/candidate/[a-z0-9][a-z0-9._-]{0,63}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
FIELDS = {"version", "repository", "controller_repository", "controller_ref",
          "controller_sha", "candidate_ref", "candidate_sha", "purpose",
          "signer", "approval_id", "issued_at", "expires_at"}
MAX_ENVELOPE_BYTES = 65536
MAX_VALIDITY = dt.timedelta(hours=24)


class Denied(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Denied(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def time_utc(value):
    need(isinstance(value, str) and value.endswith("Z"), "non-UTC timestamp")
    try:
        timestamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Denied("invalid timestamp") from exc
    need(timestamp.utcoffset() == dt.timedelta(0), "non-UTC timestamp")
    return timestamp


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def verify(envelope, public_key_path, controller_sha, candidate_sha, candidate_ref, now):
    need(isinstance(envelope, dict) and set(envelope) == {"payload", "signature_b64"},
         "envelope fields invalid")
    payload = envelope["payload"]
    need(isinstance(payload, dict) and set(payload) == FIELDS,
         "approval payload schema mismatch")
    need(type(payload["version"]) is int and payload["version"] == 1,
         "approval version mismatch")
    need(payload["repository"] == REPO, "private repository mismatch")
    need(payload["controller_repository"] == CONTROLLER_REPO, "controller repository mismatch")
    need(payload["controller_ref"] == CONTROL_REF, "protected controller ref mismatch")
    need(isinstance(controller_sha, str) and SHA.fullmatch(controller_sha) is not None,
         "controller SHA not pinned")
    need(isinstance(candidate_sha, str) and SHA.fullmatch(candidate_sha) is not None,
         "candidate SHA not pinned")
    need(payload["controller_sha"] == controller_sha, "controller SHA mismatch")
    need(payload["candidate_sha"] == candidate_sha, "candidate SHA mismatch")
    need(isinstance(candidate_ref, str) and CANDIDATE_REF.fullmatch(candidate_ref) is not None,
         "candidate ref not approved")
    need(payload["candidate_ref"] == candidate_ref, "candidate ref mismatch")
    need(payload["purpose"] == "authorize_isolated_release_build", "purpose not permitted")
    need(payload["signer"] == "owner:ihacked07", "unexpected signer")
    need(isinstance(payload["approval_id"], str)
         and re.fullmatch(r"[A-Za-z0-9_-]{12,80}", payload["approval_id"]) is not None,
         "approval ID invalid")
    issued, expires = time_utc(payload["issued_at"]), time_utc(payload["expires_at"])
    need(issued <= now < expires, "approval not currently valid")
    need(dt.timedelta(0) < expires - issued <= MAX_VALIDITY, "approval validity too long")

    signature_text = envelope["signature_b64"]
    need(isinstance(signature_text, str) and len(signature_text) < 256, "signature malformed")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Denied("signature not valid base64") from exc
    need(len(signature) == 64, "invalid Ed25519 signature size")
    need(pathlib.Path(public_key_path).is_file(), "pinned public key unavailable")
    # Do not pass signatures/approval payload via process arguments or shell.
    with tempfile.TemporaryDirectory(prefix="mantrix-approval-") as folder:
        data_path = pathlib.Path(folder) / "payload.json"
        sig_path = pathlib.Path(folder) / "signature.bin"
        data_path.write_bytes(canonical(payload))
        sig_path.write_bytes(signature)
        result = subprocess.run([
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(public_key_path), "-in", str(data_path),
            "-sigfile", str(sig_path),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=10)
        need(result.returncode == 0, "owner approval signature invalid")
    return True


def main(argv=None):
    cli = argparse.ArgumentParser()
    cli.add_argument("--approval", required=True)
    cli.add_argument("--owner-public-key", required=True)
    cli.add_argument("--controller-sha", required=True)
    cli.add_argument("--candidate-sha", required=True)
    cli.add_argument("--candidate-ref", required=True)
    args = cli.parse_args(argv)
    try:
        source = pathlib.Path(args.approval)
        need(source.is_file() and source.stat().st_size <= MAX_ENVELOPE_BYTES,
             "approval missing or oversized")
        envelope = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
        # Protected executable code must use the host UTC clock, not CLI fixture time.
        now = dt.datetime.now(dt.timezone.utc)
        verify(envelope, args.owner_public_key, args.controller_sha,
               args.candidate_sha, args.candidate_ref, now)
    except (Denied, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print("OWNER_APPROVAL=DENIED: " + str(exc), file=sys.stderr)
        return 1
    print("OWNER_APPROVAL_SIGNATURE=PASS")
    print("RELEASE_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    sys.exit(main())

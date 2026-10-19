#!/usr/bin/env python3
"""All requests are injected synthetic responses; no network or live tokens."""
import importlib.util
import json
import pathlib
import tempfile
import unittest

FILE = pathlib.Path(__file__).resolve().parents[1] / "collect_source_evidence.py"
SPEC = importlib.util.spec_from_file_location("collector", FILE)
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
SOURCE_SHA = "a" * 40
CONTROL_SHA = "b" * 40
REF = "refs/heads/release/candidate/test"
RUNS = {"ci": 101, "container": 102, "supply": 103}


class FakeApi:
    def __init__(self):
        self.error = ""
        self.ref_reads = 0
        self.main_reads = 0

    def get(self, path):
        if path == "/repos/" + c.SOURCE:
            return {"full_name": c.SOURCE, "private": True}
        if path == "/repos/" + c.CONTROLLER:
            return {"full_name": c.CONTROLLER, "private": False, "default_branch": "main"}
        if path.endswith("/branches/main"):
            self.main_reads += 1
            return {"name": "main", "protected": self.error != "unprotected",
                    "commit": {"sha": CONTROL_SHA if self.error != "controller_drift" or
                               self.main_reads == 1 else SOURCE_SHA}}
        if path.endswith("/branches/main/protection"):
            return {
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "required_status_checks": {"strict": True, "checks": [{"context": "Policy Tests"}]},
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
            }
        if "/contents/.github/workflows/" in path:
            import_path, _, candidate_sha = path.rpartition("?ref=")
            label = next((k for k, v in c.WORKFLOWS.items()
                          if import_path.endswith("/contents/" + v)), None)
            if label is None or candidate_sha != SOURCE_SHA:
                raise AssertionError("Unexpected workflow contents API request")
            return {"type": "file", "path": c.WORKFLOWS[label],
                    "sha": ("c" * 40 if self.error == "tampered_workflow" and
                            label == "ci" else c.TRUSTED_WORKFLOW_BLOBS[label]),
                    "size": 7891}
        if "/git/ref/heads/release/candidate/" in path:
            self.ref_reads += 1
            return {"ref": REF, "object": {"sha": "c" * 40 if self.error == "drift" and
                    self.ref_reads >= 2 else SOURCE_SHA}}
        if "/commits/" in path:
            return {"sha": SOURCE_SHA, "commit": {"tree": {"sha": "d" * 40}}}
        if "/actions/runs/" in path:
            ident = int(path.rsplit("/", 1)[-1])
            label = next(label for label, run_id in RUNS.items() if run_id == ident)
            return {
                "id": ident, "workflow_id": 100, "run_attempt": 1,
                "repository": {"full_name": c.SOURCE},
                "head_sha": "c" * 40 if self.error == "bad_run_sha" else SOURCE_SHA,
                "head_branch": "release/candidate/test",
                "path": c.WORKFLOWS[label],
                "event": "push" if self.error == "push_instead_dispatch" else "workflow_dispatch",
                "status": "completed", "conclusion": "success",
            }
        raise AssertionError("Unexpected API request: " + path)

    def jobs(self, run_id):
        label = next(label for label, ident in RUNS.items() if ident == run_id)
        names = sorted(c.REQUIRED_JOBS[label] | c.EXPECTED_SKIPPED[label])
        records = [
            {"id": run_id * 100 + i, "name": name, "run_id": run_id,
             "head_sha": SOURCE_SHA, "run_attempt": 1, "status": "completed",
             "conclusion": "skipped" if name in c.EXPECTED_SKIPPED[label]
             else "success", "labels": ["ubuntu-latest"]}
            for i, name in enumerate(names)
        ]
        if self.error == "missing_job": records.pop()
        if self.error == "duplicate_name": records[-1]["name"] = records[0]["name"]
        if self.error == "skipped_required": records[0]["conclusion"] = "skipped"
        if self.error == "failed_required": records[0]["conclusion"] = "failure"
        if self.error == "untrusted_runner": records[0]["labels"] = ["self-hosted"]
        if self.error == "job_sha_drift": records[0]["head_sha"] = "c" * 40
        if self.error == "job_run_mismatch": records[0]["run_id"] = 999
        if self.error == "job_attempt_mismatch": records[0]["run_attempt"] = 2
        if self.error == "unexpected_native_success" and label == "supply":
            native = next(job for job in records
                          if job["name"] == "Dependency Review (Native Capability)")
            native["conclusion"] = "success"
        return records


class ControllerEvidenceTests(unittest.TestCase):
    def capture(self, error=""):
        api = FakeApi()
        api.error = error
        return c.collect(api, CONTROL_SHA, REF, SOURCE_SHA, RUNS)

    def test_synthetic_capture_does_not_authorize_release(self):
        value = self.capture()
        self.assertEqual(value["source_tree_sha"], "d" * 40)
        self.assertEqual(len(value["canonical_runs"]), 3)
        self.assertFalse(value["release_authorized"])
        self.assertFalse(value["owner_signature_verified"])
        self.assertFalse(value["cosign_verified"])
        self.assertFalse(value["workflow_dependency_policy_verified"])
        self.assertEqual(len(value["reviewed_workflow_blob_pins"]), 3)

    def test_rejects_wrong_runner_or_run_metadata(self):
        for error in ("unprotected", "controller_drift", "drift",
                      "bad_run_sha", "push_instead_dispatch",
                      "missing_job", "duplicate_name", "skipped_required",
                      "failed_required", "unexpected_native_success",
                      "untrusted_runner", "job_sha_drift", "job_run_mismatch",
                      "job_attempt_mismatch", "tampered_workflow"):
            with self.subTest(error=error), self.assertRaises(c.Refused):
                self.capture(error)

    def test_rejects_non_candidate_refs_and_unpinned_sha(self):
        for ref in ("refs/heads/main", "refs/heads/release/candidate/../oops",
                    "refs/heads/release/candidate/Upper"):
            with self.subTest(ref=ref), self.assertRaises(c.Refused):
                c.collect(FakeApi(), CONTROL_SHA, ref, SOURCE_SHA, RUNS)
        with self.assertRaises(c.Refused):
            c.collect(FakeApi(), "not-pinned", REF, SOURCE_SHA, RUNS)

    def test_rejects_duplicate_canonical_run_ids(self):
        with self.assertRaises(c.Refused):
            c.collect(FakeApi(), CONTROL_SHA, REF, SOURCE_SHA,
                      {"ci": 1, "container": 1, "supply": 2})

    def test_supply_native_skip_is_exactly_allowlisted(self):
        result = self.capture()
        supply = result["canonical_runs"]["supply"]["jobs"]
        native = [job for job in supply
                  if job["name"] == "Dependency Review (Native Capability)"]
        self.assertEqual(len(native), 1)
        self.assertEqual(native[0]["conclusion"], "skipped")
        self.assertEqual(len(supply), 10)

    def test_workflow_blob_pins_require_independent_review(self):
        self.assertEqual(c.TRUSTED_WORKFLOW_BLOBS["ci"],
                         "0725a12dd0bf3aec273a2f17c808ffb6bad6e87e")
        self.assertEqual(len(c.TRUSTED_WORKFLOW_BLOBS), 3)
        with self.assertRaisesRegex(c.Refused, "reviewed trust pin"):
            self.capture("tampered_workflow")

    def test_required_job_counts_match_pinned_workflows(self):
        self.assertEqual(len(c.REQUIRED_JOBS["ci"]), 8)
        self.assertEqual(len(c.REQUIRED_JOBS["container"]), 11)
        self.assertEqual(len(c.REQUIRED_JOBS["supply"]), 9)
        self.assertEqual(len(c.EXPECTED_SKIPPED["supply"]), 1)

    def test_git_api_requires_token_and_rejects_unknown_path(self):
        with self.assertRaises(c.Refused):
            c.GitHub("", None)
        github = c.GitHub("fixture-only", None)
        for path in ("/users/me", "/repos/other/repo",
                     "/repos/ihacked07/mantrix/../something"):
            with self.subTest(path=path), self.assertRaises(c.Refused):
                github.get(path)

    def test_output_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as root:
            folder = pathlib.Path(root) / "owner"
            folder.mkdir(mode=0o700)
            target = folder / "evidence.json"
            c.save_no_clobber({"release_authorized": False}, target)
            self.assertEqual(json.loads(target.read_text()), {"release_authorized": False})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(c.Refused):
                c.save_no_clobber({"release_authorized": True}, target)
            folder.chmod(0o755)
            with self.assertRaises(c.Refused):
                c.save_no_clobber({}, folder / "public.json")

    def test_job_pages_fail_closed(self):
        class FakeResponse:
            def __init__(self, url, body):
                self.url = url
                self.body = json.dumps(body).encode()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return self.url
            def read(self, size): return self.body
        class FakeOpener:
            def __init__(self, scenario): self.scenario = scenario
            def open(self, req, timeout):
                body = {"total_count": 2, "jobs": [
                    {"id": 1, "run_attempt": 1, "status": "completed",
                     "conclusion": "failure" if self.scenario == "failed" else "success",
                     "labels": ["self-hosted"] if self.scenario == "self_hosted"
                     else ["ubuntu-latest"]}]}
                return FakeResponse(req.full_url, body)
        for scenario in ("self_hosted", "incomplete"):
            with self.subTest(scenario=scenario), self.assertRaises(c.Refused):
                c.GitHub("fixture-only", FakeOpener(scenario)).jobs(101)


if __name__ == "__main__":
    unittest.main()

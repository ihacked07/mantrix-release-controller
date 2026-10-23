#!/usr/bin/env python3
"""Synthetic descriptor metadata tests; no private source network access."""
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load("collect_source_evidence")
d = load("release_dependency_contract")
SHA = "a" * 40


class FakeApi:
    def __init__(self, error=""):
        self.error = error
        self.requests = []

    def get(self, path):
        self.requests.append(path)
        if self.error == "api_error":
            raise OSError("synthetic API failure")
        prefix = "/repos/" + c.SOURCE + "/contents/"
        if not path.startswith(prefix): raise AssertionError(path)
        file_path, _, ref = path[len(prefix):].partition("?ref=")
        if not ref or file_path not in d.RELEASE_DESCRIPTOR_BLOBS: raise AssertionError(path)
        if self.error == "malformed" and file_path == "apps/web/Dockerfile": return []
        if self.error == "missing" and file_path == "apps/web/Dockerfile": return {"type": "dir"}
        if self.error == "unexpected_type" and file_path == "apps/web/Dockerfile": return {"type": "symlink"}
        if self.error == "partial" and file_path == "apps/web/Dockerfile": return {"type": "file", "path": file_path, "sha": d.RELEASE_DESCRIPTOR_BLOBS[file_path]}
        actual_path = "other/path" if self.error == "wrong_path" and file_path == "apps/web/Dockerfile" else file_path
        digest = "b" * 40 if (self.error == "changed" and file_path == ".github/workflows/release-images.yml") or ref != SHA else d.RELEASE_DESCRIPTOR_BLOBS[file_path]
        return {"type": "file", "path": actual_path, "sha": digest, "size": 1}


class ReleaseDependencyTests(unittest.TestCase):
    def test_exact_descriptors_and_explicit_external_gap(self):
        value = d.verify(FakeApi(), SHA)
        self.assertEqual(len(value["verified_descriptor_blobs"]), 27)
        self.assertFalse(value["release_authorized"])
        self.assertFalse(value["release_dependency_policy_verified"])
        self.assertTrue(value["unverified_external_dependencies"])

    def test_changed_or_missing_descriptor_refused(self):
        for error in ("changed", "missing", "unexpected_type", "malformed", "wrong_path", "partial", "api_error"):
            with self.subTest(error=error), self.assertRaises((d.source.Refused, OSError)):
                d.verify(FakeApi(error), SHA)

    def test_wrong_candidate_sha_refused(self):
        with self.assertRaises(d.source.Refused):
            d.verify(FakeApi(), "b" * 40)

    def test_all_requests_pin_exact_private_repository_and_ref(self):
        api = FakeApi()
        d.verify(api, SHA)
        self.assertEqual(len(api.requests), len(d.RELEASE_DESCRIPTOR_BLOBS))
        self.assertEqual(set(api.requests), {
            "/repos/" + c.SOURCE + "/contents/" + path + "?ref=" + SHA
            for path in d.RELEASE_DESCRIPTOR_BLOBS
        })

    def test_digest_consumer_executable_inputs_are_pinned(self):
        self.assertEqual({
            "cmd/digest-deploy-consumer/main.go",
            "cmd/digest-deploy-consumer/open_trusted_compose_linux.go",
            "cmd/digest-deploy-consumer/open_trusted_compose_unsupported.go",
        }, {
            path for path in d.RELEASE_DESCRIPTOR_BLOBS
            if path.startswith("cmd/digest-deploy-consumer/")
        })

    def test_duplicate_metadata_json_refused_before_contract_receives_it(self):
        with self.assertRaises(d.source.Refused):
            d.source.unique_json([("sha", "a"), ("sha", "b")])


if __name__ == "__main__":
    unittest.main()

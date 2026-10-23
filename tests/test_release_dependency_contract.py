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
    def get(self, path):
        prefix = "/repos/" + c.SOURCE + "/contents/"
        if not path.startswith(prefix): raise AssertionError(path)
        file_path, _, ref = path[len(prefix):].partition("?ref=")
        if ref != SHA or file_path not in d.RELEASE_DESCRIPTOR_BLOBS: raise AssertionError(path)
        if self.error == "missing" and file_path == "apps/web/Dockerfile": return {"type": "dir"}
        digest = "b" * 40 if self.error == "changed" and file_path == ".github/workflows/release-images.yml" else d.RELEASE_DESCRIPTOR_BLOBS[file_path]
        return {"type": "file", "path": file_path, "sha": digest, "size": 1}


class ReleaseDependencyTests(unittest.TestCase):
    def test_exact_descriptors_and_explicit_external_gap(self):
        value = d.verify(FakeApi(), SHA)
        self.assertEqual(len(value["verified_descriptor_blobs"]), 24)
        self.assertFalse(value["release_authorized"])
        self.assertFalse(value["release_dependency_policy_verified"])
        self.assertTrue(value["unverified_external_dependencies"])

    def test_changed_or_missing_descriptor_refused(self):
        for error in ("changed", "missing"):
            with self.subTest(error=error), self.assertRaises(d.source.Refused): d.verify(FakeApi(error), SHA)


if __name__ == "__main__":
    unittest.main()

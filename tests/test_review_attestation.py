#!/usr/bin/env python3
"""Synthetic review evidence only; no GitHub call or credential."""
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
r = load("review_attestation")
SHA = "a" * 40
AUTHOR = 10
REVIEWER = 20


def ruleset(minimum=1, enabled=True):
    return {"id": 1, "name": "protect-main", "source": c.CONTROLLER, "source_type": "Repository",
            "target": "branch", "enforcement": "active" if enabled else "disabled", "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}, "rules": [
                {"type": "deletion"}, {"type": "non_fast_forward"},
                {"type": "pull_request", "parameters": {"required_approving_review_count": minimum,
                 "dismiss_stale_reviews_on_push": True, "required_review_thread_resolution": True,
                 "allowed_merge_methods": ["squash"]}},
                {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": True,
                 "do_not_enforce_on_create": False, "required_status_checks": [
                     {"context": "offline-owner-approval", "integration_id": 15368}]}}]}


class FakeApi:
    def __init__(self, error=""):
        self.error = error
        self.reads = 0

    def get(self, path):
        if self.error == "api_error":
            raise OSError("synthetic API failure")
        if path == "/repos/" + c.CONTROLLER + "/branches/main":
            return {"name": "main", "protected": True}
        if path == "/repos/" + c.CONTROLLER + "/rulesets":
            return [{"id": 1, "name": "protect-main", "target": "branch", "enforcement": "active", "source_type": "Repository"}]
        if path == "/repos/" + c.CONTROLLER + "/rulesets/1":
            self.reads += 1
            return ruleset(0 if self.error == "insufficient_rules" else 1,
                           enabled=not (self.error == "disabled_rules" or self.error == "changed_rules" and self.reads > 1))
        if path == "/repos/" + c.SOURCE + "/pulls/7":
            repo = "other/repo" if self.error == "wrong_repository" else c.SOURCE
            return {"number": 8 if self.error == "wrong_pr" else 7, "state": "open", "draft": False,
                    "head": {"sha": "b" * 40 if self.error == "old_head" else SHA, "ref": "candidate", "repo": {"full_name": repo}},
                    "base": {"repo": {"full_name": repo}}, "user": {"id": AUTHOR}}
        if path == "/repos/" + c.SOURCE + "/commits/" + SHA:
            return {"sha": SHA, "commit": {"committer": {"date": "2026-10-23T00:00:00Z"}}}
        prefix = "/repos/" + c.SOURCE + "/pulls/7/reviews?per_page=100&page="
        if path.startswith(prefix):
            page = int(path[len(prefix):])
            if self.error == "malformed_page": return [{}] * 101
            if self.error == "incomplete_page":
                return [self.review(index + 100 * (page - 1)) for index in range(100)]
            return self.rows() if page == 1 else []
        raise AssertionError("unexpected path " + path)

    def review(self, ident=1, actor=REVIEWER, state="APPROVED", commit=SHA, submitted="2026-10-23T00:01:00Z"):
        return {"id": ident, "user": {"id": actor, "login": "synthetic"}, "state": state,
                "commit_id": commit, "submitted_at": submitted,
                "pull_request_url": "https://api.github.com/repos/" + c.SOURCE + "/pulls/7"}

    def rows(self):
        if self.error in ("missing", "forged_candidate_json"): return []
        if self.error == "self": return [self.review(actor=AUTHOR)]
        if self.error == "ineligible": return [self.review(actor=99)]
        if self.error == "old_commit": return [self.review(commit="b" * 40)]
        if self.error == "dismissed": return [self.review(state="DISMISSED")]
        if self.error == "superseded": return [self.review(1), self.review(2, state="COMMENTED", submitted="2026-10-23T00:02:00Z")]
        if self.error == "old_timestamp": return [self.review(submitted="2026-10-22T00:00:00Z")]
        if self.error == "wrong_review_pr":
            row = self.review(); row["pull_request_url"] += "-wrong"; return [row]
        return [self.review()]


class ReviewAttestationTests(unittest.TestCase):
    def verify(self, error="", ids=frozenset({REVIEWER})):
        return r.review_attestation(FakeApi(error), 7, SHA, eligible_ids=ids)

    def test_valid_independent_review(self):
        value = self.verify()
        self.assertTrue(value["independent_review_verified"])
        self.assertFalse(value["release_authorized"])
        self.assertEqual(value["reviewer_actor_ids"], [REVIEWER])

    def test_refuses_bad_review_and_governance_evidence(self):
        for error in ("missing", "self", "ineligible", "wrong_pr", "wrong_repository", "old_head",
                      "old_commit", "dismissed", "superseded", "old_timestamp", "insufficient_rules",
                      "disabled_rules", "changed_rules", "malformed_page", "incomplete_page", "api_error",
                      "wrong_review_pr", "forged_candidate_json"):
            with self.subTest(error=error), self.assertRaises((r.source.Refused, OSError)):
                self.verify(error)

    def test_empty_or_candidate_controlled_eligibility_refused(self):
        with self.assertRaises(r.source.Refused): self.verify(ids=frozenset())
        with self.assertRaises(r.source.Refused): self.verify(ids=frozenset({"not-an-actor"}))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Read-only GitHub evidence capture for a future isolated public controller.

This file NEVER authorizes release, signs, publishes, or deploys. Authenticated
API observations are necessary but not sufficient for Owner authorization.
"""
import argparse
import json
import os
import pathlib
import re
import stat
import tempfile
import urllib.error
import urllib.request

API = "https://api.github.com"
SOURCE = "ihacked07/mantrix"
CONTROLLER = "ihacked07/mantrix-release-controller"
SOURCE_REF = re.compile(r"^refs/heads/release/candidate/[a-z0-9][a-z0-9._-]{0,63}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_BODY = 4 * 1024 * 1024
MAX_JOB_PAGES = 100
WORKFLOWS = {
    "ci": ".github/workflows/ci.yml",
    "container": ".github/workflows/container-security.yml",
    "supply": ".github/workflows/supply-chain.yml",
}


# Bootstrap trusted-file identities taken from the independently reviewed frozen
# Mantrix source SHA 4f0e3f0f2debe91d02a89aaac5af8f00f6381402.
# GitHub's exact Git blob SHA is read via an authenticated Contents API lookup.
# If an integrated candidate changes any workflow, this check MUST FAIL until
# the new workflow/policy is independently reviewed and these pins are updated
# on the separately protected controller. Do not auto-learn values from a PR.
TRUSTED_WORKFLOW_BLOBS = {
    "ci": "0725a12dd0bf3aec273a2f17c808ffb6bad6e87e",
    "container": "c4c5e7ab00de1f6d395e3220bc8356908097c954",
    "supply": "318d6d4b7cf7d5ae74d34f66d5687d9bcd69d612",
}

# Pinned to the reviewed workflow job matrix; unexpected/missing jobs fail closed.
# Update only together with an independently reviewed canonical workflow change.
REQUIRED_JOBS = {
    "ci": {
        "Go Build & Test", "Go Vulnerability Check", "Web App (Next.js)",
        "Public Site (Next.js)", "Admin Console (Next.js)",
        "Internal Frontend (apps/operator)",
        "Internal Frontend (apps/accounting)", "Docker Build Check",
    },
    "container": {
        "Trivy Repository Config Scan",
        *{"Trivy Image Scan (" + image + ")" for image in (
            "coordinator", "web", "admin", "site", "operator", "accounting",
            "seed-node", "partner-node", "private-node", "caddy-cloudflare",
        )},
    },
    "supply": {
        "Dependency Review Fallback (Full-Tree Policy)",
        "Raw OSV, Go Reachability, and Vulnerability Policy",
        *{"npm audit (" + app + ")" for app in (
            "apps/web", "apps/admin", "apps/operator", "apps/accounting",
            "apps/site",
        )},
        "License, Notice, and Provenance",
        "Repository Policy Checks",
    },
}
# Supply-chain native dependency-review is intentionally disabled for
# workflow_dispatch; the full-tree fallback remains mandatory.
EXPECTED_SKIPPED = {"ci": set(), "container": set(),
                    "supply": {"Dependency Review (Native Capability)"}}


class Refused(ValueError):
    """Fail-closed refusal; never silently downgrade verification."""


def require(condition, detail):
    if not condition:
        raise Refused(detail)


def unique_json(pairs):
    values = {}
    for key, value in pairs:
        require(key not in values, "duplicate API JSON field")
        values[key] = value
    return values


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("GitHub API redirect refused")


class GitHub:
    def __init__(self, token, opener):
        require(isinstance(token, str) and token.strip(), "read-only GitHub App token required")
        self.token = token
        self.opener = opener

    def get(self, path):
        require(path.startswith("/repos/") and "//" not in path and ".." not in path,
                "untrusted GitHub API path")
        require(path.startswith("/repos/" + SOURCE + "/") or
                path.startswith("/repos/" + CONTROLLER + "/") or
                path in ("/repos/" + SOURCE, "/repos/" + CONTROLLER),
                "GitHub API repository not allowlisted")
        url = API + path
        req = urllib.request.Request(
            url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.token,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Mantrix-Controller-Evidence/1",
            }, method="GET")
        with self.opener.open(req, timeout=20) as response:
            require(response.geturl() == url, "redirected GitHub response")
            data = response.read(MAX_BODY + 1)
            require(len(data) <= MAX_BODY, "oversized GitHub response")
            return json.loads(data.decode("utf-8"), object_pairs_hook=unique_json)

    def jobs(self, run_id):
        records = []
        seen = set()
        expected = None
        for page in range(1, MAX_JOB_PAGES + 1):
            data = self.get(f"/repos/{SOURCE}/actions/runs/{run_id}/jobs?per_page=100&page={page}")
            require(isinstance(data, dict) and isinstance(data.get("jobs"), list),
                    "missing GitHub workflow jobs")
            count = data.get("total_count")
            require(type(count) is int and 0 < count <= 10000,
                    "invalid GitHub workflow job total")
            expected = count if expected is None else expected
            require(count == expected and len(data["jobs"]) <= 100,
                    "inconsistent GitHub job pagination")
            for job in data["jobs"]:
                require(isinstance(job, dict) and type(job.get("id")) is int and
                        job["id"] > 0 and job["id"] not in seen,
                        "duplicate or invalid GitHub job ID")
                seen.add(job["id"])
                labels = job.get("labels")
                require(isinstance(labels, list) and "self-hosted" not in labels and
                        any(isinstance(label, str) and label.startswith("ubuntu-")
                            for label in labels), "canonical job runner not isolated GitHub-hosted")
                require(type(job.get("run_attempt")) is int and
                        job["run_attempt"] >= 1, "missing job attempt identity")
                records.append(job)
            require(len(records) <= expected, "too many GitHub jobs")
            if len(records) == expected:
                return records
            require(data["jobs"], "empty intermediate GitHub job page")
        raise Refused("incomplete GitHub job pagination")


def verify_protection(api):
    branch = api.get(f"/repos/{CONTROLLER}/branches/main")
    require(isinstance(branch, dict) and branch.get("name") == "main" and
            branch.get("protected") is True, "public controller main not protected")
    protection = api.get(f"/repos/{CONTROLLER}/branches/main/protection")
    require(isinstance(protection, dict), "unreadable controller branch protection")
    reviews = protection.get("required_pull_request_reviews")
    checks = protection.get("required_status_checks")
    admins = protection.get("enforce_admins")
    require(isinstance(reviews, dict) and type(reviews.get("required_approving_review_count")) is int
            and reviews["required_approving_review_count"] >= 1,
            "controller review requirement missing")
    require(isinstance(checks, dict) and checks.get("strict") is True and
            bool(checks.get("checks") or checks.get("contexts")),
            "controller required status checks missing")
    require(isinstance(admins, dict) and admins.get("enabled") is True,
            "controller admin bypass not constrained")
    require(protection.get("allow_force_pushes", {}).get("enabled") is False and
            protection.get("allow_deletions", {}).get("enabled") is False,
            "controller force-push or deletion is allowed")
    return {"branch": branch, "protection": protection}



def check_source_workflow_pins(api, candidate_sha):
    """Reject candidate-supplied workflow changes not reviewed by controller.

    This verifies *workflow YAML file identity only*. Scripts/config executed
    by those YAML files remain separate dependencies that still require
    independent source-policy attestation before operational activation.
    """
    evidence = {}
    for label, path in WORKFLOWS.items():
        record = api.get(f"/repos/{SOURCE}/contents/{path}?ref={candidate_sha}")
        expected = TRUSTED_WORKFLOW_BLOBS[label]
        require(isinstance(record, dict) and record.get("type") == "file" and
                record.get("path") == path and record.get("sha") == expected and
                type(record.get("size")) is int and record["size"] > 0,
                "canonical workflow file differs from reviewed trust pin: " + label)
        evidence[label] = {"path": path, "git_blob_sha": expected}
    return evidence


def run_evidence(api, label, run_id, candidate_sha, branch):
    require(type(run_id) is int and run_id > 0, "invalid run ID")
    run = api.get(f"/repos/{SOURCE}/actions/runs/{run_id}")
    require(isinstance(run, dict) and run.get("id") == run_id and
            run.get("repository", {}).get("full_name") == SOURCE and
            run.get("head_sha") == candidate_sha and
            run.get("head_branch") == branch and
            run.get("path") == WORKFLOWS[label] and
            run.get("event") == "workflow_dispatch" and
            run.get("status") == "completed" and
            run.get("conclusion") == "success" and
            type(run.get("workflow_id")) is int and run["workflow_id"] > 0 and
            type(run.get("run_attempt")) is int and run["run_attempt"] > 0,
            "wrong or incomplete canonical workflow evidence: " + label)
    jobs = api.jobs(run_id)
    names = [job.get("name") for job in jobs]
    expected = REQUIRED_JOBS[label] | EXPECTED_SKIPPED[label]
    require(all(isinstance(name, str) for name in names) and
            len(names) == len(expected) and set(names) == expected,
            "missing, duplicate, or unexpected canonical workflow jobs: " + label)
    require(all(job.get("run_attempt") == run["run_attempt"] and
                job.get("run_id") == run_id and
                job.get("head_sha") == candidate_sha for job in jobs),
            "workflow job run/attempt/SHA does not match canonical evidence")
    for job in jobs:
        labels = job.get("labels")
        require(isinstance(labels, list) and "self-hosted" not in labels and
                any(isinstance(item, str) and item.startswith("ubuntu-")
                    for item in labels),
                "canonical job is not GitHub-hosted: " + job["name"])
        expected_conclusion = ("skipped" if job["name"] in EXPECTED_SKIPPED[label]
                               else "success")
        require(job.get("status") == "completed" and
                job.get("conclusion") == expected_conclusion,
                "unexpected failed/skipped canonical job: " + job["name"])
    return {"run": run, "jobs": jobs}


def collect(api, controller_sha, candidate_ref, candidate_sha, run_ids):
    require(isinstance(controller_sha, str) and SHA.fullmatch(controller_sha) is not None,
            "controller SHA not pinned")
    require(isinstance(candidate_sha, str) and SHA.fullmatch(candidate_sha) is not None,
            "candidate SHA not pinned")
    require(isinstance(candidate_ref, str) and SOURCE_REF.fullmatch(candidate_ref) is not None,
            "candidate branch not allowlisted")
    require(set(run_ids) == set(WORKFLOWS) and
            len(set(run_ids.values())) == len(run_ids), "canonical run set is invalid")
    control_meta = api.get(f"/repos/{CONTROLLER}")
    require(control_meta.get("full_name") == CONTROLLER and control_meta.get("private") is False
            and control_meta.get("default_branch") == "main",
            "controller repository identity incorrect")
    private_meta = api.get(f"/repos/{SOURCE}")
    require(private_meta.get("full_name") == SOURCE and private_meta.get("private") is True,
            "private source repository identity incorrect")
    public = verify_protection(api)
    require(public["branch"]["commit"]["sha"] == controller_sha,
            "controller branch drifted from pinned SHA")
    branch = candidate_ref.removeprefix("refs/heads/")
    ref_path = f"/repos/{SOURCE}/git/ref/heads/{branch}"
    before = api.get(ref_path)
    require(before.get("ref") == candidate_ref and
            before.get("object", {}).get("sha") == candidate_sha,
            "candidate branch tip does not match Owner-signed SHA")
    commit = api.get(f"/repos/{SOURCE}/commits/{candidate_sha}")
    tree_sha = commit.get("commit", {}).get("tree", {}).get("sha")
    require(commit.get("sha") == candidate_sha and
            isinstance(tree_sha, str) and SHA.fullmatch(tree_sha) is not None,
            "candidate commit and source tree not established")
    workflow_pins = check_source_workflow_pins(api, candidate_sha)
    collected = {label: run_evidence(api, label, run_ids[label], candidate_sha, branch)
                 for label in WORKFLOWS}
    after = api.get(ref_path)
    require(after.get("ref") == candidate_ref and
            after.get("object", {}).get("sha") == candidate_sha,
            "source branch changed while collecting evidence")
    control_after = api.get(f"/repos/{CONTROLLER}/branches/main")
    require(control_after.get("protected") is True and
            control_after.get("commit", {}).get("sha") == controller_sha,
            "controller moved during evidence collection")
    return {
        "status": "READ_ONLY_OBSERVATIONS_NOT_RELEASE_AUTHORITY",
        "source_repository": SOURCE,
        "controller_repository": CONTROLLER,
        "candidate_sha": candidate_sha,
        "candidate_ref": candidate_ref,
        "source_tree_sha": tree_sha,
        "controller_sha": controller_sha,
        "github_api_protection_snapshot": public,
        "canonical_runs": collected,
        "reviewed_workflow_blob_pins": workflow_pins,
        "workflow_dependency_policy_verified": False,
        "owner_signature_verified": False,
        "cosign_verified": False,
        "release_authorized": False,
    }


def save_no_clobber(data, destination):
    output = pathlib.Path(destination)
    directory = output.parent
    info = os.lstat(directory)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            not info.st_mode & 0o077, "evidence directory must be owner-only")
    require(not os.path.lexists(output), "evidence output already exists")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=directory, delete=False,
                                         encoding="utf-8") as handle:
            temporary = handle.name
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--candidate-sha", required=True)
    for label in WORKFLOWS:
        parser.add_argument("--" + label + "-run-id", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    token = os.environ.get("MANTRIX_READONLY_APP_TOKEN", "")
    require(token, "authorized read-only GitHub App token not configured")
    runs = {label: getattr(args, label + "_run_id") for label in WORKFLOWS}
    observation = collect(GitHub(token, urllib.request.build_opener(NoRedirect())),
                          args.controller_sha, args.candidate_ref, args.candidate_sha, runs)
    save_no_clobber(observation, args.output)
    print("GITHUB_EVIDENCE_CAPTURE=PASS")
    print("RELEASE_AUTHORIZED=NO")


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise SystemExit("GITHUB_EVIDENCE_CAPTURE=REFUSED: " + str(exc))

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

# A profile is evidence policy, not a release switch.  The controller always
# emits RELEASE_AUTHORIZED=NO; a separately protected future workflow must
# bind every remaining prerequisite before it can perform a privileged action.
SOLO_OWNER_OPEN_BETA = "SOLO_OWNER_OPEN_BETA"
INDEPENDENT_REVIEW_RELEASE = "INDEPENDENT_REVIEW_RELEASE"
TRUST_PROFILES = {
    SOLO_OWNER_OPEN_BETA: {"minimum_reviewers": 0},
    INDEPENDENT_REVIEW_RELEASE: {"minimum_reviewers": 1},
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

# Reviewed security-policy scripts executed by canonical workflows.
# Pins originate from frozen Mantrix commit
# 4f0e3f0f2debe91d02a89aaac5af8f00f6381402.
# This is a narrow executable-policy pin set, NOT a dependency closure:
# package lockfiles, Docker build contexts, Go/JS application tests, security
# scanner binaries, and invoked programs require separate independent review.
TRUSTED_SECURITY_SCRIPT_BLOBS = {
    "scripts/dependency_scope.mjs": "0dd293584e32cd11c31297c5fc78ce4273364173",
    "scripts/vulnerability_policy_gate.mjs": "896ee165788fc964954b479b9fcce2c259337dcd",
    "scripts/vulnerability_policy_gate.test.mjs": "5607979b9a67f0115b3d7e85b639322ab9d153c1",
    "scripts/run_vulnerability_policy_gate.sh": "514ead10aafb332db80d2d4eb3fce8c8e62ecdda",
    "scripts/generate_source_sbom.mjs": "e18fb05f1de1210741b0164892442feaaa459d0d",
    "scripts/supply_chain_policy.sh": "0622705edc00fb1584e5ea5a69878800c54ed4c2",
    "scripts/caddy_vulnerability_policy_gate.mjs": "bd64b0ece1e7268ee7be830f7244710df8248ce8",
    "scripts/caddy_vulnerability_policy_gate.test.mjs": "fc93693dbc51bcd9f47d564c3444185ba378bcd6",
    "scripts/run_caddy_vulnerability_policy_gate.sh": "e7cf3ccca0e92e669e35a076b324e533d73fd1f4",
    "scripts/generate_caddy_openpgp_evidence.sh": "8841a1f4e62bf1ba0efd911d654a5925248f7e34",
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


def verify_profile(profile):
    require(profile in TRUST_PROFILES, "unknown trust profile")
    return TRUST_PROFILES[profile]


def verify_protection(api, profile):
    """Verify GitHub's effective protected branch and reviewed branch ruleset.

    The repository ruleset APIs are readable with least-privilege repository
    metadata access. The branch protection endpoint requires Administration
    read and cannot be assumed accessible to a minimum-scope GitHub App.

    GitHub repository admins can still edit/disable rulesets: re-check on
    every operation and require independent offline Owner authorization.
    """
    branch = api.get(f"/repos/{CONTROLLER}/branches/main")
    require(isinstance(branch, dict) and branch.get("name") == "main" and
            branch.get("protected") is True, "public controller main not protected")
    listing = api.get(f"/repos/{CONTROLLER}/rulesets")
    require(isinstance(listing, list), "cannot read controller ruleset inventory")
    candidates = [item for item in listing if
                  isinstance(item, dict) and item.get("name") == "protect-main" and
                  item.get("target") == "branch" and
                  item.get("enforcement") == "active" and
                  item.get("source_type") == "Repository"]
    require(len(candidates) == 1 and type(candidates[0].get("id")) is int and
            candidates[0]["id"] > 0, "missing unique active controller ruleset")
    rule_id = candidates[0]["id"]
    ruleset = api.get(f"/repos/{CONTROLLER}/rulesets/{rule_id}")
    require(isinstance(ruleset, dict) and ruleset.get("id") == rule_id and
            ruleset.get("name") == "protect-main" and
            ruleset.get("source") == CONTROLLER and
            ruleset.get("source_type") == "Repository" and
            ruleset.get("target") == "branch" and
            ruleset.get("enforcement") == "active" and
            ruleset.get("bypass_actors") == [],
            "active controller ruleset does not match Owner trust policy")
    conditions = ruleset.get("conditions")
    ref_match = conditions.get("ref_name") if isinstance(conditions, dict) else None
    require(isinstance(ref_match, dict) and
            ref_match.get("include") == ["~DEFAULT_BRANCH"] and
            ref_match.get("exclude") == [],
            "controller ruleset does not exclusively cover default branch")
    rules = ruleset.get("rules")
    require(isinstance(rules, list) and all(isinstance(x, dict) for x in rules),
            "controller rules absent")
    by_type = {}
    for row in rules:
        name = row.get("type")
        require(isinstance(name, str) and name not in by_type,
                "duplicate/invalid controller rule")
        by_type[name] = row
    require("deletion" in by_type and "non_fast_forward" in by_type,
            "controller deletion/force-push protection missing")
    require("pull_request" in by_type and
            isinstance(by_type["pull_request"].get("parameters"), dict),
            "controller PR approval policy missing")
    reviews = by_type["pull_request"]["parameters"]
    required_reviews = reviews.get("required_approving_review_count")
    policy = verify_profile(profile)
    require(type(required_reviews) is int and required_reviews >= policy["minimum_reviewers"] and
            reviews.get("dismiss_stale_reviews_on_push") is True and
            reviews.get("required_review_thread_resolution") is True and
            reviews.get("allowed_merge_methods") == ["squash"],
            "trust-profile reviewer gate not enforced")
    require("required_status_checks" in by_type and
            isinstance(by_type["required_status_checks"].get("parameters"), dict),
            "controller required checks absent")
    checks = by_type["required_status_checks"]["parameters"]
    require(checks.get("strict_required_status_checks_policy") is True and
            checks.get("do_not_enforce_on_create") is False,
            "controller required status checks are not strict")
    statuses = checks.get("required_status_checks")
    require(isinstance(statuses, list) and any(
            isinstance(c, dict) and c.get("context") == "offline-owner-approval" and
            c.get("integration_id") == 15368 for c in statuses),
            "controller GitHub Actions policy test is not required")
    return {
        "branch": branch,
        "ruleset": ruleset,
        "trust_profile": profile,
        "minimum_reviewers": policy["minimum_reviewers"],
        "observed_reviewers": required_reviews,
        "independent_review_required": policy["minimum_reviewers"] > 0,
    }


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



def check_security_script_pins(api, candidate_sha):
    """Refuse candidate changes to reviewed security-policy scripts.

    These identities are independent of the proposed candidate commit SHA,
    and only change through a separately reviewed protected-controller update.
    Call-site/runtime dependency closure is NOT proven by these source pins.
    """
    verified = {}
    for path, expected_sha in TRUSTED_SECURITY_SCRIPT_BLOBS.items():
        record = api.get(f"/repos/{SOURCE}/contents/{path}?ref={candidate_sha}")
        require(isinstance(record, dict) and record.get("type") == "file" and
                record.get("path") == path and record.get("sha") == expected_sha and
                type(record.get("size")) is int and record["size"] > 0,
                "reviewed security policy script changed: " + path)
        verified[path] = expected_sha
    return verified


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


def collect(api, controller_sha, candidate_ref, candidate_sha, run_ids,
            profile=INDEPENDENT_REVIEW_RELEASE):
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
    verify_profile(profile)
    public = verify_protection(api, profile)
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
    security_script_pins = check_security_script_pins(api, candidate_sha)
    collected = {label: run_evidence(api, label, run_ids[label], candidate_sha, branch)
                 for label in WORKFLOWS}
    after = api.get(ref_path)
    require(after.get("ref") == candidate_ref and
            after.get("object", {}).get("sha") == candidate_sha,
            "source branch changed while collecting evidence")
    # Re-check the entire effective ruleset, not only the controller main SHA.
    # An administrator may edit a ruleset without moving the protected branch.
    # Detect any change observed across this bounded collection window.
    protection_after = verify_protection(api, profile)
    require(protection_after["branch"]["commit"]["sha"] == controller_sha,
            "controller moved during evidence collection")
    require(protection_after == public,
            "controller security ruleset drifted during evidence collection")
    return {
        "status": "READ_ONLY_OBSERVATIONS_NOT_RELEASE_AUTHORITY",
        "security_state": "DEVELOPMENT_ONLY_NOT_ACTIVATED",
        "source_repository": SOURCE,
        "controller_repository": CONTROLLER,
        "candidate_sha": candidate_sha,
        "candidate_ref": candidate_ref,
        "source_tree_sha": tree_sha,
        "controller_sha": controller_sha,
        "trust_profile": profile,
        "github_api_protection_snapshot": public,
        "canonical_runs": collected,
        "reviewed_workflow_blob_pins": workflow_pins,
        "reviewed_security_script_blob_pins": security_script_pins,
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
    parser.add_argument("--trust-profile", choices=sorted(TRUST_PROFILES),
                        default=INDEPENDENT_REVIEW_RELEASE)
    for label in WORKFLOWS:
        parser.add_argument("--" + label + "-run-id", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    token = os.environ.get("MANTRIX_READONLY_APP_TOKEN", "")
    require(token, "authorized read-only GitHub App token not configured")
    runs = {label: getattr(args, label + "_run_id") for label in WORKFLOWS}
    observation = collect(GitHub(token, urllib.request.build_opener(NoRedirect())),
                          args.controller_sha, args.candidate_ref, args.candidate_sha, runs,
                          args.trust_profile)
    save_no_clobber(observation, args.output)
    print("GITHUB_EVIDENCE_CAPTURE=PASS")
    print("RELEASE_AUTHORIZED=NO")


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise SystemExit("GITHUB_EVIDENCE_CAPTURE=REFUSED: " + str(exc))

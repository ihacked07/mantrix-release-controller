#!/usr/bin/env python3
"""Read-only, fail-closed GitHub review attestation for a future controller.

This program never authorizes a release.  It refuses unless a separately
reviewed controller policy pins eligible GitHub actor IDs.
"""
import argparse
import datetime
import os

import collect_source_evidence as source

MAX_REVIEW_PAGES = 100
ELIGIBLE_INDEPENDENT_REVIEWER_IDS = frozenset()


def utc(value):
    source.require(isinstance(value, str) and value.endswith("Z"), "invalid GitHub timestamp")
    try:
        return datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise source.Refused("invalid GitHub timestamp") from exc


def review_pages(api, number):
    source.require(type(number) is int and number > 0, "invalid pull request number")
    records = []
    seen = set()
    for page in range(1, MAX_REVIEW_PAGES + 1):
        rows = api.get(f"/repos/{source.SOURCE}/pulls/{number}/reviews?per_page=100&page={page}")
        source.require(isinstance(rows, list) and len(rows) <= 100, "invalid review pagination")
        for row in rows:
            source.require(isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0 and row["id"] not in seen,
                           "duplicate or invalid review ID")
            seen.add(row["id"])
            records.append(row)
        if len(rows) < 100:
            return records
    raise source.Refused("incomplete GitHub review pagination")


def review_attestation(api, pull_number, candidate_sha, profile=source.INDEPENDENT_REVIEW_RELEASE,
                       eligible_ids=ELIGIBLE_INDEPENDENT_REVIEWER_IDS):
    source.require(source.SHA.fullmatch(candidate_sha) is not None, "invalid candidate SHA")
    policy = source.verify_profile(profile)
    source.require(policy["minimum_reviewers"] >= 1, "independent review profile required")
    source.require(isinstance(eligible_ids, frozenset) and eligible_ids and
                   all(type(actor) is int and actor > 0 for actor in eligible_ids),
                   "no independently pinned eligible reviewer IDs")

    protection_before = source.verify_protection(api, profile)
    pr = api.get(f"/repos/{source.SOURCE}/pulls/{pull_number}")
    source.require(isinstance(pr, dict) and pr.get("number") == pull_number and pr.get("state") == "open" and
                   pr.get("draft") is False, "reviewed pull request is not an open non-draft candidate")
    for side in ("head", "base"):
        record = pr.get(side)
        source.require(isinstance(record, dict) and isinstance(record.get("repo"), dict) and
                       record["repo"].get("full_name") == source.SOURCE, "reviewed pull request repository mismatch")
    head = pr["head"]
    source.require(head.get("sha") == candidate_sha and isinstance(head.get("ref"), str) and head["ref"],
                   "reviewed pull request head SHA mismatch")
    author = pr.get("user")
    source.require(isinstance(author, dict) and type(author.get("id")) is int and author["id"] > 0,
                   "reviewed pull request author missing")
    commit = api.get(f"/repos/{source.SOURCE}/commits/{candidate_sha}")
    source.require(isinstance(commit, dict) and commit.get("sha") == candidate_sha and
                   isinstance(commit.get("commit"), dict) and isinstance(commit["commit"].get("committer"), dict),
                   "candidate commit metadata missing")
    commit_time = utc(commit["commit"]["committer"].get("date"))

    expected_url = f"https://api.github.com/repos/{source.SOURCE}/pulls/{pull_number}"
    latest = {}
    for review in review_pages(api, pull_number):
        user = review.get("user")
        source.require(isinstance(user, dict) and type(user.get("id")) is int and user["id"] > 0 and
                       isinstance(user.get("login"), str) and user["login"], "review author identity missing")
        source.require(review.get("pull_request_url") == expected_url and review.get("commit_id") == candidate_sha,
                       "review is not bound to exact pull request head")
        submitted = utc(review.get("submitted_at"))
        source.require(submitted >= commit_time, "review predates candidate commit")
        key = user["id"]
        sort_key = (submitted, review["id"])
        if key not in latest or sort_key > latest[key][0]:
            latest[key] = (sort_key, review)

    approvals = []
    for actor, (_, review) in latest.items():
        if review.get("state") != "APPROVED":
            continue
        source.require(actor != author["id"], "self-approval is not independent")
        source.require(actor in eligible_ids, "reviewer is not independently eligible")
        approvals.append({"id": review["id"], "actor_id": actor, "submitted_at": review["submitted_at"],
                          "commit_id": review["commit_id"]})
    source.require(len(approvals) >= policy["minimum_reviewers"], "insufficient current independent approvals")
    protection_after = source.verify_protection(api, profile)
    source.require(protection_before == protection_after, "controller ruleset changed during review collection")
    return {"release_authorized": False, "independent_review_verified": True,
            "candidate_sha": candidate_sha, "pull_request_number": pull_number,
            "reviewer_actor_ids": sorted(row["actor_id"] for row in approvals),
            "approvals": approvals, "github_api_protection_snapshot": protection_after}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--pull-request", required=True, type=int)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    token = os.environ.get("MANTRIX_READONLY_APP_TOKEN", "")
    source.require(token, "authorized read-only GitHub App token not configured")
    value = review_attestation(source.GitHub(token, source.urllib.request.build_opener(source.NoRedirect())),
                               args.pull_request, args.candidate_sha)
    source.save_no_clobber(value, args.output)


if __name__ == "__main__":
    try:
        main()
    except (source.Refused, OSError, ValueError) as exc:
        raise SystemExit(f"REFUSED: {exc}")

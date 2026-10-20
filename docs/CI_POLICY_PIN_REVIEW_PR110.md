# Gate 3 — proposed CI YAML trust-pin update for PR #110

**Status: OWNER_APPROVED_FOR_CONTROLLER_DEVELOPMENT; TRUSTED_RELEASE_NOT_ACTIVATED**

This file is a development review proposal in a *stacked Draft PR* targeting
the existing unmerged Public Controller PR #1 branch. It is **not** independent
human approval, an Owner signature, a production release authorization or an
approval to merge Public Controller PR #1.

## Exact sources

- Frozen Mantrix baseline: `4f0e3f0f2debe91d02a89aaac5af8f00f6381402`.
- Frozen baseline canonical `.github/workflows/ci.yml` Git blob: `0725a12dd0bf3aec273a2f17c808ffb6bad6e87e`.
- Private development candidate: [PR #110](https://github.com/ihacked07/mantrix/pull/110)
  at `9ab0e6ff9103d89ff57359d77495d2b05f624fc4`.
- Proposed new canonical CI Git blob: `c37404b8911efc3949e4e6f15dde1221a1d54c74`.
- Separate private [PR #111](https://github.com/ihacked07/mantrix/pull/111)
  currently reports the mismatch without automatically accepting it.
- Development CI on PR #110 [run 39314287459](https://github.com/ihacked07/mantrix/actions/runs/39314287459):
  8/8 successful jobs **on VM105, a self-hosted untrusted development runner**.

## Security-oriented diff review

The exact two YAML blobs were read from GitHub and compared. Observed
development changes:

1. A temporary Gate-2-specific push branch was added to the trigger allowlist.
2. The exact historical Gate-2 branch uses named VM105 on self-hosted runs,
   including a runner-name/OS preflight. All other `workflow_dispatch` refs
   continue to request `ubuntu-latest`, including future
   `release/candidate/*` refs.
3. The Go job now installs rclone v1.74.2 from the stated HTTPS distribution,
   checks its hardcoded ZIP SHA-256 before extraction, and runs mock-only backup
   safety plus local-backend no-overwrite regression tests.
4. Python Witness health-contract tests and the private trusted-candidate/
   collector **structural** tests were added to the mandatory Go job.
5. All eight canonical job names remain unchanged, the dependency chain and
   Go/frontend audits/tests/build steps remain present.
6. Repository-level workflow permission remains `contents: read`, checkout
   uses `persist-credentials: false`, and external GitHub Actions remain
   commit-pinned. No deployment, signing, registry write, release secrets or
   token-based privileged job was added in this change.

## Remaining risks and conditions

- VM105 passing CI is **not** proof of release-workflow isolation or security
  assurance. The controller must separately require authenticated GitHub-hosted
  `workflow_dispatch` runs on the final exact candidate SHA.
- The rclone dependency check establishes a pinned ZIP SHA, not a complete
  provenance statement about its original developer and distribution.
- Private structural trusted-candidate tests are currently an obsolete
  private-ref/Environment-Reviewer model; they do **not** authorize releases.
- Candidate-side modifications to CI logic, lockfiles, downloaded binaries,
  scripts and build contexts remain security-sensitive. The controller's
  policy-script pin coverage and dependency closure must be assessed separately.
- A new source commit or further CI YAML edit requires a **new exact Git blob
  review**. Do not silently update pins to whichever SHA the candidate reports.
- Solo-owner development profile retains explicit residual risk and cannot be
  presented as independent human review. Production activation still requires
  the Owner's deliberate policy decision, real verified signing/enrollment,
  durable replay ledger, authoritative source evidence, signed images and
  completed Pre-P10/P11 checks.

## Decision record

`CONTROLLER_CI_YAML_REPIN=PROPOSED_ONLY`
`REVIEWER_INDEPENDENT=NO`
`OWNER_RELEASE_TRUST_DECISION=NOT_RECORDED_FOR_THIS_REPIN`
`TRUSTED_CONTROLLER_ACTIVE=NO`
`P10_DEPLOY=BLOCKED`

Retain the original pinned value in Public Controller PR #1 until this stacked
review proposal is explicitly dispositioned. Never merge the proposed branch
automatically merely because its offline development tests pass.


## Owner decision and actual merge (2026-10-20)

The Owner explicitly approved the **exact Gate 3 CI workflow Git blob pin**
`c37404b8911efc3949e4e6f15dde1221a1d54c74`, as proposed in Public
Controller PR #2. That PR was merged into the **development branch**
`bootstrap/controller-policy-ci-20261020`, merge commit
`4efadcf10fabd2a4edffda11d6411c4a87472907`.

At this exact merge commit, authenticated GitHub tree comparison of the private
PR #111 source SHA `523c74033100ff0c3e690607656615eeb1c4ff52`
against controller constants returned **13/13 identical reviewed blob IDs**
(3 canonical workflow YAMLs, 10 security scripts). Push CI
[39360473516](https://github.com/ihacked07/mantrix-release-controller/actions/runs/39360473516)
and pull-request CI
[39360478648](https://github.com/ihacked07/mantrix-release-controller/actions/runs/39360478648)
both succeeded at merge commit. This is a **development policy acceptance**,
NOT independent reviewer approval, activation of `main`, cryptographic
Owner-signature enrollment, verified full dependency closure, or permission to
publish or deploy.

**Owner decision:** `OWNER_GATE3_CI_PIN=APPROVED_FOR_DEVELOPMENT`
**Public Controller main:** unchanged; protected, not activated.
**Release authority:** `NO`.
**Pre-P10:** `BLOCKED`.

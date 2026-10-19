# Mantrix Release Controller

**A small, public boundary for reviewing how Mantrix releases may be authorized.**

Software can change quickly. Release authority should not. This repository is intentionally narrow: it aims to make release decisions understandable, reviewable, and difficult to grant by accident.

> **Status: DEVELOPMENT ONLY — NOT RELEASE-AUTHORIZED.**
>
> The public repository exists and its `main` branch currently has an active `protect-main` ruleset. The controller implementation and read-only test workflow remain in [Draft PR #1](https://github.com/ihacked07/mantrix-release-controller/pull/1), **not merged into `main`**. Passing unit tests does not permit signing, publishing or deployment.

## Why this exists

Mantrix keeps private application development separate from the authority to release software. Public visibility makes this limited policy surface easier to inspect and permits branch rules on our current GitHub plan. Being public is **not** a security guarantee; the effective controls and independent approval must be verified.

We prefer evidence over assumptions, explicit boundaries over implicit trust, and a clear **BLOCKED** over pretending a missing security control has passed.

## What's included in the development proposal

The allowlisted bootstrap bundle in Draft PR #1 contains:

| Component | Purpose | Authority |
| --- | --- | --- |
| `verify_approval.py` | Verify a detached, strictly scoped Ed25519 Owner approval using an **externally pinned** public key | Offline verification only |
| `reserve_approval.py` | Demonstrate atomic, single-use approval-ID reservation | Local synthetic tests; **not** a production replay ledger |
| `collect_source_evidence.py` | Demonstrate fail-closed, read-only exact-SHA GitHub CI evidence collection | No live App installation; **not** a release decision |
| `tests/` | Positive and negative fixture tests with disposable, synthetic test keys | Development tests only |
| `.github/workflows/controller-policy-ci.yml` | Run the policy unit tests with `contents: read` on a GitHub-hosted runner | No signing, registry write or deployment |
| `docs/ACTIVATION_GATES.md` | Document required independent release and deployment gates | Draft requirements only |

The public CI has passed 41 synthetic/structural tests for the initially imported development SHA. Each subsequent change requires its **own exact-SHA** test result.

## Trust boundaries

- **Private source:** `ihacked07/mantrix` remains private. No proprietary application source, customer information or internal deployment configuration belongs here.
- **Protected policy:** `main` is the intended controller trust boundary, not an arbitrary PR branch. At bootstrap, the active ruleset requires `offline-owner-approval`, blocks forced updates/deletion and requires a PR. **Required human approvals remain at zero; independent review is not yet enforced.**
- **Owner intent:** a future Owner signature must bind an exact candidate SHA/ref, controller SHA/ref, purpose and short expiry. The Owner's **private signing key stays offline** and never enters GitHub, VM105 or CI.
- **Separate workers:** VM105 is a development/test worker, not a trusted publisher or independent release authority.
- **Authenticated observations:** any future private-source CI evidence needs separately authorized, least-privilege GitHub App access and independently verified source bytes. A public repository `GITHUB_TOKEN` cannot automatically read private Mantrix source.
- **Isolated release:** a future release builder must run from trusted, pinned policy in an isolated environment, not execute candidate-controlled workflow scripts with release credentials.
- **Independent post-build checks:** source-to-image digests, immutable manifests, SPDX provenance, Cosign signature/attestation and exact workflow identity must be verified independently.
- **Separate deployment gate:** even a valid signed build does not authorize Production or Gate 3 deployment.

## Known gaps — explicit release blockers

1. The controller code is in an **unmerged Draft PR**; current protections are not a claim that the controller is operational.
2. No independently enrolled Owner public verification key, real Owner approvals or trusted offline signing ceremony exist.
3. The SQLite proof is not a durable, independently controlled replay ledger. Hosted-runner filesystems are ephemeral; replay protection needs a trusted, recoverable single-writer store and continuity checks.
4. The source evidence collector has not authenticated real private-source runs using a least-privilege App.
5. Checking CI job names and conclusions alone cannot prove the **reviewed security workflow definition** ran; candidate-controlled policy changes must not become trusted evidence.
6. No isolated release build, real Cosign signature, digest-bound release manifest, attestation verification, independent reviewer gate or production consumer trust migration is active.
7. Existing production-only policies must not be weakened or silently repurposed to make the new model pass.

**If any release prerequisite is missing, the result is BLOCKED.** A green development CI badge is not an exception.

## Maintainer note

The point is not to make security sound impressive. It is to be able to explain exactly what has been verified, what has not, and who is allowed to make the next decision.

A slower, traceable release is preferable to an unproven shortcut. That is the standard this controller is being built toward.

## Development and disclosure

- Review changes through small pull requests and read-only checks. Do not include secrets in test fixtures, workflow logs, PR descriptions or commit history.
- No real Owner private key, API token, SSH credential, production publishing secret, customer data or internal infrastructure details may be committed.
- The public test workflow is intentionally unprivileged. Never give public PR-triggered jobs a trusted release token.
- No open-source license has been granted by the absence of a license file.
- This README documents *current development intent and known limits*, not a security certification. Reverify GitHub rules, source SHA, tests and effective permissions before granting any future authority.

See [Activation Gates](docs/ACTIVATION_GATES.md) for the release-stage threat boundaries and required owner decisions.

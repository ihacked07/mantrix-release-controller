# Gate 2B — Private Source / Public Controller Trust Policy (Draft)

Status: DEVELOPMENT_ONLY. The public controller repository now exists with an active `protect-main` ruleset, while this implementation remains an unmerged Draft PR. No privileged credentials, Owner key enrollment, signed release or deployment authority exists.

## Zero-paid-upgrade viability

Public GitHub Free permits branch protection/rulesets and public environment required reviewers. The Mantrix private repo on the current plan reports `protected=false`, including frozen production ref. **Never claim or fabricate private branch protection.** Model B replaces the need to trust a movable private branch with an exact SHA explicitly bound to an independently verified Owner-signed authorization. This is a new trust model and does not retroactively authorize existing production-only scripts.

## Principal and authority matrix

| Principal | Capability | Explicit prohibition |
|---|---|---|
| Owner offline signing device | Sign narrowly scoped SHA/ref/controller/purpose/expiry approval | Never upload signing private key to GitHub, VM105, Actions secrets or artifacts |
| VM105 `mantrix-gh-runner-01` | Private repo development CI, synthetic tests and unsigned build experiments | Never Owner key, publication credentials or privileged release authority |
| Private Mantrix GitHub workflow | Provide exact-SHA checked source + CI status; optional isolated GitHub-hosted image builder | No authority to decide release via unauthenticated payload |
| Public controller `main` (repository created; implementation still draft) | After separate approval, verify authenticated evidence and an offline Owner-signed approval | No candidate-controlled script or arbitrary PR checkout with secrets; no release authority today |
| Isolated GitHub-hosted publishing job (not yet created) | Only after verified Owner Gate: publish images by digest, sign and attest | No publishing solely because structural JSON says PASS |
| Production runtime | Future Owner-authorized Gate 3 rollout | No automatic deploy from Gate 2 |

## Trust profiles (development policy; neither is active)

The controller has two explicit, signed profiles. Selecting a profile collects
evidence only; it never enables signing, publishing, deployment, or a release
workflow.

| Profile | Reviewer requirement | Intended use | Residual risk |
|---|---|---|---|
| `SOLO_OWNER_OPEN_BETA` | No invented independent reviewer; public-controller rules, owner signature, exact SHA/ref, short expiry, trusted durable replay ledger, canonical GitHub-hosted evidence and immutable manifest verification remain mandatory | Solo-founder Open Beta only after separate Owner activation decision | One human controls source approval and key ceremony; no independent human review claim is permitted |
| `INDEPENDENT_REVIEW_RELEASE` | At least one approving human reviewer, stale-review dismissal and review-thread resolution | Higher-assurance/future release | Reviewer quality and GitHub configuration still require continuous verification |

`trust_profile` is part of the detached Owner-signed approval payload. A caller
cannot change profiles after signing. The default collector profile is
`INDEPENDENT_REVIEW_RELEASE`, preserving the stricter historical behavior.

Both profiles require a trusted controller commit/ref, source exact SHA/ref,
read-only authenticated evidence, policy pin checks, an offline Owner approval,
and a durable single-use approval ledger. The local SQLite implementation is a
tested adapter, not proof of production durability; activation needs an
Owner-controlled persistent store with backup, availability and continuity
checks. GitHub-hosted runners and VM105 are not that store and never become
release-signing authority.

## Security state machine

`DEVELOPMENT_ONLY_NOT_ACTIVATED` is the only current state. Collector output
always emits `release_authorized=false`. A future protected controller must
move only through: `EVIDENCE_COLLECTED` (all exact-SHA checks pass),
`OWNER_APPROVAL_VERIFIED` (profile-bound detached signature passes),
`APPROVAL_RESERVED` (durable one-time ledger succeeds), and
`POST_BUILD_VERIFIED` (real immutable-digest, manifest, Cosign and attestation
verification succeeds). Any mismatch returns to `DENIED`; no state implies
deployment authority.

## Pre-build release authorization (must fail closed)

1. Read only a GitHub-protected/public-controller commit and verify controller ref, SHA and OIDC workflow identity. Verify rulesets and admin-bypass restrictions using authorized API/UI evidence.
2. Fetch exact private candidate commit and Git tree with read-only installation identity. Candidate branch may be mutable; require the live candidate tip equal signed exact SHA immediately before use, and again before signing.
3. Verify detached Ed25519 signature with public key pinned in protected controller. Check signer intent, signed trust profile, purpose `authorize_isolated_release_build`, SHA/ref/controller binding, 24h maximum TTL, and replay prevention via approval ID ledger in trusted storage.
4. Fetch complete canonical CI/Container/Supply Chain runs and job pages, prove workflow paths, run IDs, attempts, SHA, conclusions and runner provenance from authenticated GitHub endpoints. PR CI or self-declared payload is insufficient.
5. Deny if candidate commit is unreachable, deleted, changed, build inputs not exactly SHA-bound, or source origin cannot be proven. Do not depend on a false `protected=true` for private ref.

## Post-build (not implemented)

Build with isolated GitHub-hosted ephemeral environment; use deterministic source→image digest mapping. Independently verify digest and signed release manifest, Cosign signature and attestation, SPDX, exact controller workflow identity + OIDC issuer. Sign only immutable digests from approved candidate SHA. Snapshot/verify native Witness byte hash separately. Do not substitute a VM105-built blob or a `cosign_verified:true` JSON field for real provenance.

**Migration hazard:** existing production-only `verify_release_invocation.sh`, `verify_canonical_run.sh` and digest consumer trust a different workflow identity/ref. No policy relaxation, release dispatch, signature publication or promotion is authorized by this draft. Any new consumer acceptance must be separately reviewed and owner-gated.

## External setup blockers

- **Completed bootstrap:** Owner created the separate public controller repository. Never make the private Mantrix source repository public. Controller files remain confined to Draft PR #1.
- **Partially completed:** `main` and active `protect-main` ruleset were read back from the GitHub API; deletion/force-push rules, PR requirements and one read-only CI check are configured. Required human approvals are still `0`; this is eligible only for the explicitly residual-risk `SOLO_OWNER_OPEN_BETA` development policy, never a claim of independent review or privileged activation.
- Private repo read-only GitHub App installation with least-privilege scopes must be approved; no public repo default token can automatically read private Mantrix.
- Owner public key enrollment, trusted durable approval-ID replay storage and an independent human reviewer remain Owner-gated. `owner_key_enrollment.py` is a synthetic-testable ceremony validator: it requires a private owner-controlled Ed25519 public-key file and an independently recorded SHA-256 SPKI fingerprint, emits no key copy, and always reports `RELEASE_AUTHORIZED=NO`.
- Isolated build and real Cosign verifier not active.
- No release artifacts until exact-SHA evidence, operational Pre-P10, source mapping and Owner release gate.
- Gate 3 remains independently authorized.

**Security claim permitted today:** synthetic cryptographic verifier code can reject changed signed approvals; not "Mantrix release ready" or "fully trusted controller".

## Ruleset stability throughout evidence capture (development-only)

The collector now reads and verifies the protected controller's **entire
effective `protect-main` ruleset twice**: before gathering the private
candidate's GitHub evidence and immediately after. Both protected controller
commit SHA and ruleset details must remain identical. This detects an
administrator disabling the ruleset, weakening reviewer policy, changing bypass
parameters, or changing the ruleset metadata **within the observed collection
window**, even when `main` stays on the same commit. Synthetic tests cover
post-first-read changes that previously went unnoticed.

This is bounded time-of-check evidence, **not** a guarantee against an
administrator changing the ruleset after the final read or an already-privileged
actor evading the separation of duties. A later release-signing/publishing
decision still requires a fresh trusted policy check, separate Owner approval,
authenticated exact-SHA provenance and replay protection. The implementation
remains unmerged, unprivileged and development-only.

## CI pin review: accepted for development only (2026-10-20)

The Owner accepted the CI YAML pin update originally proposed in
Public Controller PR #2 for exact private PR #110 development blob. It has a
security-oriented change assessment in
[`docs/CI_POLICY_PIN_REVIEW_PR110.md`](CI_POLICY_PIN_REVIEW_PR110.md).
PR #2 was merged into the unmerged PR #1 development branch at exact
commit `4efadcf10fabd2a4edffda11d6411c4a87472907`. The reviewed
CI blob now matches Private PR #110/#111; all thirteen policy blob pins
match Private PR #111. This was an Owner-approved **development pin change**,
not privileged release activation, independent human review, or permission
to merge Public PR #1 into protected `main`. Frozen/production refs remain
untouched.

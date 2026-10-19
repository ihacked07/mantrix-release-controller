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

## Pre-build release authorization (must fail closed)

1. Read only a GitHub-protected/public-controller commit and verify controller ref, SHA and OIDC workflow identity. Verify rulesets and admin-bypass restrictions using authorized API/UI evidence.
2. Fetch exact private candidate commit and Git tree with read-only installation identity. Candidate branch may be mutable; require the live candidate tip equal signed exact SHA immediately before use, and again before signing.
3. Verify detached Ed25519 signature with public key pinned in protected controller. Check signer intent, purpose `authorize_isolated_release_build`, SHA/ref/controller binding, 24h maximum TTL, and replay prevention via approval ID ledger in trusted storage (ledger not implemented).
4. Fetch complete canonical CI/Container/Supply Chain runs and job pages, prove workflow paths, run IDs, attempts, SHA, conclusions and runner provenance from authenticated GitHub endpoints. PR CI or self-declared payload is insufficient.
5. Deny if candidate commit is unreachable, deleted, changed, build inputs not exactly SHA-bound, or source origin cannot be proven. Do not depend on a false `protected=true` for private ref.

## Post-build (not implemented)

Build with isolated GitHub-hosted ephemeral environment; use deterministic source→image digest mapping. Independently verify digest and signed release manifest, Cosign signature and attestation, SPDX, exact controller workflow identity + OIDC issuer. Sign only immutable digests from approved candidate SHA. Snapshot/verify native Witness byte hash separately. Do not substitute a VM105-built blob or a `cosign_verified:true` JSON field for real provenance.

**Migration hazard:** existing production-only `verify_release_invocation.sh`, `verify_canonical_run.sh` and digest consumer trust a different workflow identity/ref. No policy relaxation, release dispatch, signature publication or promotion is authorized by this draft. Any new consumer acceptance must be separately reviewed and owner-gated.

## External setup blockers

- **Completed bootstrap:** Owner created the separate public controller repository. Never make the private Mantrix source repository public. Controller files remain confined to Draft PR #1.
- **Partially completed:** `main` and active `protect-main` ruleset were read back from the GitHub API; deletion/force-push rules, PR requirements and one read-only CI check are configured. Required human approvals are still `0`; effective independent review, privileged-workflow isolation and deployment environment protection are not proven.
- Private repo read-only GitHub App installation with least-privilege scopes must be approved; no public repo default token can automatically read private Mantrix.
- Owner public key enrollment, trusted durable approval-ID replay storage and an independent human reviewer remain Owner-gated.
- Isolated build and real Cosign verifier not active.
- No release artifacts until exact-SHA evidence, operational Pre-P10, source mapping and Owner release gate.
- Gate 3 remains independently authorized.

**Security claim permitted today:** synthetic cryptographic verifier code can reject changed signed approvals; not "Mantrix release ready" or "fully trusted controller".

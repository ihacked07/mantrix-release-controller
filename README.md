# Mantrix External Release Controller — Public-only bootstrap

Status: **unactivated development template**. This directory is the **entire allowed public export**. It is not a GitHub-hosted Controller today.

## Trust boundaries

1. **Private repository** \`ihacked07/mantrix\` retains all proprietary application source, private CI, production deployment and VM105 worker code. Never make it public.
2. **Proposed public repository** \`ihacked07/mantrix-release-controller\` holds only this reviewed controller source and a pinned Owner **public** verification key. Public GitHub Free protected \`main\`, separate required checks and no bypass are prerequisites; branch metadata \`protected=true\` must be observed.
3. **Trusted release workflow** executes from verified, protected controller ref and SHA on isolated GitHub-hosted runner, never VM105, with no checkout of candidate-controlled workflow definitions into a privileged runtime.
4. **Owner approval** is the detached Ed25519 signature of a canonical JSON payload specifying exact candidate SHA/ref, controller SHA/ref, purpose and a 24-hour or shorter validity. The Owner **private** key must never enter GitHub or any CI/VM105 worker. A public key alone is insufficient to authorize an action without verified signatures.
5. **Evidence collection** needs a separately authorized GitHub App installation with minimum required read permissions for private repository actions, content, and effective protection. The public repo's default \`GITHUB_TOKEN\` cannot read the private repository. Before activation, the Owner must approve GitHub App authorization and prove a **protected public controller** plus an **authenticated immutable private-source commit SHA**. The private repository remains unprotected on GitHub Free: the controller must NOT represent a private branch as protected, and must instead require an Owner-signed exact SHA, verified source bytes, stable SHA-bound approval and drift checks. An attempt to use the old production-only private-branch release gate MUST remain **BLOCKED**, never silently waived.
6. **Post-build** requires cryptographically verified immutable manifest, image digests, provenance, SPDX, Cosign signature and exact controller OIDC identity. Pre-build approval **cannot** be fulfilled by a fabricated \`cosign_verified=true\` field.
7. **VM105** is development CI and unsigned build worker only. Never load publication credentials or Owner signing key into VM105; it is not sufficient provenance for release signing.
8. **Gate 3 remains separately Owner-authorized** after C2 firewall effective ingress, portable offhost rollback, decrypt/scratch restore, legal/compliance and other Pre-P10 controls.

## Bootstrap sequence — no mutation by template

- Create a **new public** repository with exactly the proposed name; keep \`ihacked07/mantrix\` private. The connected GitHub integration has no create-repository action; do not treat this directory as the created repository. A separate Owner setup in GitHub UI or an authorized Work browser flow is required.
- Export **only** this allowlisted directory into that new repository after review; verify the Git tree contains no private Mantrix source, secrets or internal docs.
- Before privileged workflows are added: protect \`main\` (deny force-push/deletion, require PR and passing checks, no admin bypass); verify effective rulesets/branch status with an authorized GitHub account or App.
- Generate and retain Ed25519 **private key exclusively offline** with the Owner; export public PEM after out-of-band verification and pin its SHA256 in protected controller history. Do not commit a test key or Owner private key.
- Run the included negative tests via the isolated **read-only** CI template.
- Establish an independent, auditable GitHub App credentials path for private repository read-only evidence, then build a pre-release collector attesting actual GitHub responses rather than user JSON. **Private branch protection is NOT a required claim for Model B**; instead verify immutable SHA and detached Owner signature. This adaptation requires a separately reviewed controller policy. This step is **not implemented** in this bundle.
- Build a separate **post-build** real Cosign verifier, using SHA-bound manifest and trusted keyless identity. Not implemented and no real signing performed.
- Separately request explicit Owner activation approval. **No privileged workflow, signing, publishing, merge, deployment or billing change is authorized by this template.**

## Offline approval format

\`{"payload": {...}, "signature_b64": "..."}\`. The payload contains exact fields enforced by \`verify_approval.py\`. It is serialized using JSON keys sorted, no spacing, UTF-8 and \`ensure_ascii=False\` before signing. The verifier requires an exact separately pinned SHA/ref from the trusted controller. Deterministic tests inject a fixture time into the imported \`verify()\` function. The executable CLI has **no clock-override option** and always uses its UTC host clock. Unknown \`--now\` flags are rejected.

The signature validates *Owner-signed build intent only*. It is not a second-human reviewer, a deployment consent, a rollback proof or a substitute for protected Branch/Actions verification.

## CI

The included \`.github/workflows/controller-policy-ci.yml\` runs **only** the offline unit tests, with \`contents:read\`, no secrets, no \`id-token:write\`, no registry write, no publish/dispatch permissions. It becomes active only if the template is deliberately exported into the root of a separately created public repository.

## Development-only single-use approval ledger

`reserve_approval.py` verifies the same offline Owner Ed25519 approval and then
atomically reserves its unique `approval_id` using a SQLite primary-key constraint
and `BEGIN IMMEDIATE`. The DB parent must be an absolute, existing Owner-only
directory; symlink/database permission checks fail closed. Reuse of the ID is
rejected even if a new approval envelope with the same ID is signed.

**CRITICAL: This is only a local proof of the reservation mechanism.**
GitHub-hosted Actions jobs have ephemeral filesystems. A database placed in an
ephemeral job workspace does **not** implement global replay prevention.
Before any operational use, Owner must authorize a durable, independently
controlled, backed-up trusted ledger with exclusive writes, continuity checks,
recovery procedure, and a fail-closed policy during outages. No local test, PR
or synthetic reservation authorizes image signing, publishing or Gate 3.

## Canonical job completeness review

The read-only collector now requires exact job names for all three canonical
workflows: CI (8 jobs), Container Security (11 jobs), and Supply Chain
Security (9 required jobs plus 1 intentionally skipped native-dependency
review). The **only** permitted skipped job is `Dependency Review (Native
Capability)` in the canonical Supply Chain `workflow_dispatch` run. The
full-tree fallback and all other security jobs must succeed. This pinned
allowlist must be independently updated when workflows change; no automatic
relaxation or user-controlled job list is allowed. Neither this structural
contract nor development tests prove real hosted-runner provenance or release
signing authority.

# Gate 3 — New workflow policy pin proposal after Private PR #115 / #116

**Status: PROPOSED_ONLY; OWNER_POLICY_APPROVAL=NOT_GIVEN; DO_NOT_MERGE**
**Date:** 2026-10-20
**Protected public controller main:** UNCHANGED; public controller Draft PR #1 is NOT activated.

## Exact GitHub blob objects

- Previous Owner-approved development CI YAML Git blob: `c37404b8911efc3949e4e6f15dde1221a1d54c74` from Private PR #110/111 policy.
- Proposed new CI YAML blob: `6813a3dbf3296cb7922f0ce26b0bc6f71c4db11c`, read from Private PR #115 SHA `1d4a795ccf7db9ba3f2b2f102c8dd539f52b7f26` and stacked PR #116 SHA `2230a223ccd141a21dec0eb1ef2fabe90b5a87d7`.
- Private PR #114 GitHub-hosted dev-only CI [39399748132](https://github.com/ihacked07/mantrix/actions/runs/39399748132) passed 8/8 **on the earlier SHA** `858be39e72446b5de764a8871702c9fb95a9c5a6`; this is NOT proof that the modified workflow passed.
- Private PR #116 GitHub-hosted dev-only CI [39405090843](https://github.com/ihacked07/mantrix/actions/runs/39405090843) passed 8/8 on `2230a223ccd141a21dec0eb1ef2fabe90b5a87d7`; this remains development evidence, not controller activation or release authority.
- Four newly pinned **direct executable Python CI dependencies** are:

| Source path | Git blob SHA |
| --- | --- |
| `scripts/monitoring/replica_metadata_contract.py` | `77ce93239b2dd43019acf59cdc2af36636be66c8` |
| `scripts/monitoring/test_replica_metadata_contract.py` | `03840c0b71f48957b2619953f8b7a58cf417b728` |
| `scripts/monitoring/replica_metadata_sql_contract.py` | `db9a297a6776349465af729a9aeb27aca9c7c291` |
| `scripts/monitoring/test_replica_metadata_sql_contract.py` | `61c39a7384b7032c659b273f98b38bdb120cd7a6` |

This proposal expands pin coverage from **3 workflows + 10 scripts (13 total)** to **3 workflows + 14 scripts (17 total)**. All other 12 existing pins remain unchanged. This does not prove complete transitive dependencies, workflow trust, Owner signing or runtime integrity.

## Mandatory CI workflow delta

Only one new mandatory step was seen in the changed `.github/workflows/ci.yml` (Go CI job), following Witness tests:

```bash
python3 -m unittest \
  scripts/monitoring/test_replica_metadata_contract.py \
  scripts/monitoring/test_replica_metadata_sql_contract.py -v
```

Existing GitHub Actions permissions remain `contents: read`, existing 8 job names stay unchanged, and GitHub-hosted `workflow_dispatch` is the required development check. A historical temporary Gate-2 VM105 exception still exists in the workflow; never use that self-hosted runner as release proof.

## Separate review and acceptance gates

1. Owner reviews exact old/new CI YAML Git blobs and diff, as well as all 4 additional executable Python blobs and synthetic tests; ensure no hidden credential, data, publication or release permission changes.
2. Verify Private PR #116 final SHA's exact-head GitHub-hosted CI success **8/8** with the new mandatory contract step present and executed. CI runs on earlier SHAs do NOT count.
3. Verify Public Controller Draft proposal CI and **17/17** authenticated Git blob matches against Private PR #116 candidate; confirm mismatched script/workflow fail closed.
4. After **separate explicit Owner approval**, merge this proposal into Public Controller PR #1 development branch only. Reconcile private checker constants/count to new protected controller policy only after approved merge.
5. Main activation, live Owner Ed25519 key enrollment, trusted replay storage, Release Images, real signing, publishing and production P10 remain separately gated.

`PROPOSED_CI_BLOB=6813a3dbf3296cb7922f0ce26b0bc6f71c4db11c`
`PROPOSED_POLICY_PINS=17`
`OWNER_APPROVAL_FOR_THIS_REPIN=NO`
`PR116_CANONICAL_DEV_CI=PASS_8_OF_8_RUN_39405090843`
`PUBLIC_MAIN_MUTATION=NO`
`PRE_P10=BLOCKED`
`P10_DEPLOY=NO`

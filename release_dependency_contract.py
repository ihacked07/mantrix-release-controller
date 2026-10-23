#!/usr/bin/env python3
"""Exact private-source release descriptor inventory; never release authority."""
import argparse
import os

import collect_source_evidence as source

RELEASE_DESCRIPTOR_BLOBS = {
    ".github/workflows/release-images.yml": "f99770fb51d1072fd6845577c4bcb7dad70f6db9",
    "scripts/verify_release_invocation.sh": "57a6d063aed86d7527ebf81b1ad63f75281cd9e0",
    "scripts/verify_canonical_run.sh": "2e47e16f9c43af915e5c73eba11c97db7b1b06bc",
    "scripts/extract_imagetools_digest.sh": "a740bfb4207ec192e8b2c771ca2f2702170ba499",
    "deploy/docker/Dockerfile.core": "bb9d95704545ef578af296534f972fa6bde9ce98",
    "cmd/partner/Dockerfile": "d42c0a093e5cd6f735abfd43ea80ec7c4dae337e",
    "deploy/docker/Dockerfile.pg-backup": "942b4b54181aa6d2aff9af3d8f6ba765f0185e2d",
    "deploy/caddy/Dockerfile": "0781826b5daad38b9114bed9db31d50bf29693a5",
    "services/seed-node/Dockerfile": "dcbcaa09c3a7e458a714c4ad7024fffe411c1e59",
    "apps/web/Dockerfile": "7625678c62ce2a172f9394c6a605cf8d13e952a5",
    "apps/site/Dockerfile": "2fc7ef4f26d7eb4603c2cc58a45b54361fc53de7",
    "apps/admin/Dockerfile": "d1e473052dc2d17f0020c8ede5fac07cca6a25fd",
    "apps/operator/Dockerfile": "28c45ec0195bf0f88edc7dbd695ab2de593f7380",
    "apps/accounting/Dockerfile": "daf14a8cb7a1b23cbcc6ad21707b0a8911f61b2d",
    "apps/web/package-lock.json": "3c5b4de3384ceb96d57f03ad6fdbdff4dd0ac2aa",
    "apps/site/package-lock.json": "2504e02456e47b9b4f374ea05eb535ce0fe8069c",
    "apps/admin/package-lock.json": "e2dfb79aca39b9dd6554260bb9e62578f228718f",
    "apps/operator/package-lock.json": "3b8f94fed9c63cc2f717dbca84d2b2d31bf3e1d4",
    "apps/accounting/package-lock.json": "d8243b8313d974eb750272254784c8992755ac9d",
    "go.mod": "62d33d5be196800b7dad0979a050f8fbd3061c2f",
    "go.sum": "7aa13a9b149842713c1ab0326ef673de844976de",
    "cmd/go.mod": "e2412770ff458e25c2b4811517e54aaeec18eea5",
    "cmd/go.sum": "a31cb38f313389772c269a9818cd0b33d51ddc55",
    "services/seed-node/go.mod": "ed9f9e39c7e52ad65ed88ec33506057a0e21d2f9",
    "cmd/digest-deploy-consumer/main.go": "3f88c15a9999d21c24074a9e01a5a49b3f0c2833",
    "cmd/digest-deploy-consumer/open_trusted_compose_linux.go": "cbf9e72dbb1c1e825c88611c822ee53f89661d42",
    "cmd/digest-deploy-consumer/open_trusted_compose_unsupported.go": "d16cc91a200a757b2235971f933efcea2c4b05be",
}

UNVERIFIED_EXTERNAL = (
    "GitHub-hosted runner image and preinstalled tools",
    "GitHub Action transitive runtime dependencies",
    "registry/provider availability and provenance for npm, Go, Docker, GHCR, Trivy, Buildx, Cosign and Sigstore",
    "built image digest, final-image dependency contents, SBOM, provenance, signature and transparency-log evidence",
)


def verify(api, candidate_sha):
    source.require(source.SHA.fullmatch(candidate_sha) is not None, "invalid candidate SHA")
    observed = {}
    for path, expected in RELEASE_DESCRIPTOR_BLOBS.items():
        row = api.get(f"/repos/{source.SOURCE}/contents/{path}?ref={candidate_sha}")
        source.require(isinstance(row, dict) and row.get("type") == "file" and row.get("path") == path and
                       row.get("sha") == expected and type(row.get("size")) is int and row["size"] > 0,
                       "release dependency descriptor changed: " + path)
        observed[path] = row["sha"]
    return {"release_authorized": False, "release_dependency_policy_verified": False,
            "candidate_sha": candidate_sha, "verified_descriptor_blobs": observed,
            "unverified_external_dependencies": list(UNVERIFIED_EXTERNAL)}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    token = os.environ.get("MANTRIX_READONLY_APP_TOKEN", "")
    source.require(token, "authorized read-only GitHub App token not configured")
    value = verify(source.GitHub(token, source.urllib.request.build_opener(source.NoRedirect())), args.candidate_sha)
    source.save_no_clobber(value, args.output)


if __name__ == "__main__":
    try:
        main()
    except (source.Refused, OSError, ValueError) as exc:
        raise SystemExit(f"REFUSED: {exc}")

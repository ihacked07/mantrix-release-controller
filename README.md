# Mantrix Release Controller

Independent release policy and verification controller for Mantrix.

> **Status: NOT ACTIVATED — bootstrap only.**
>
> This repository does not currently authorize production releases,
> publish container images, sign release artifacts, or deploy Mantrix.

## Security boundaries

- Mantrix application source and customer data remain in a separate private repository.
- Never commit API tokens, credentials, private signing keys, customer information,
  production secrets, or internal deployment configuration here.
- A public repository is not a trust anchor without independently verified branch
  protection, review policy, and pinned workflow identity.
- Any future controller implementation must be reviewed before public export.
- Development CI success alone cannot authorize a production release.
- Only a separately verified, narrowly scoped, offline Owner approval may authorize
  a future isolated release build; Gate 3 deployment remains separate.
- VM105 remains a development worker, not a trusted release-signing authority.

## Initial state

This initial commit is documentation only. No privileged workflows, Owner public
key enrollment, publishing credentials, release policies, or private-source
integration have been activated.

License: No license has been granted for redistribution or reuse.

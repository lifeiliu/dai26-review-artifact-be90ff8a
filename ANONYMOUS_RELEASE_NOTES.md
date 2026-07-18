# Anonymous Review Release Notes

This directory is a generated release boundary. It contains source, protocols,
tests, and saved JSON/JSONL/CSV/Markdown evidence, including E-B24--E-B28.

The release builder deterministically replaces author emails, local user/home
paths, hostnames, public IP addresses, cloud resource IDs, AWS account IDs,
identity-center role names, and role-session names. AWS accounts use the
non-routable placeholder `000000000000`; roles use
`ANONYMOUS_REVIEW_ROLE`. Git history and remotes are not included.

SQLite databases, interpreter caches, Terraform state/plans, and source
checksum manifests are excluded because binary/state files can retain
identifiers and because text sanitization changes source bytes. Saved portable
evidence remains in JSON/JSONL/CSV/Markdown form. `CHECKSUMS.sha256` is rebuilt
over the released bytes. Workload hash locks are recomputed over the sanitized
portable traces so release-side loaders still enforce exact byte identity.
`RELEASE_MANIFEST.json` records exclusions and transformations.

This material is supplied solely for anonymous scholarly peer review. No
copyright or patent license is granted by its availability. A publication
license will be selected after double-blind review.

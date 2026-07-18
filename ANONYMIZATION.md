# Anonymization and Release Procedure

The private `artifact/` tree is the scientific source; it may contain raw
operational provenance. It must not be uploaded directly. The generated release
directory is the only publication boundary.

Build a fresh release from the parent repository:

```bash
python3 artifact/scripts/build_anonymous_release.py \
  --source artifact \
  --extra infra/e_b24=infra/e_b24 \
  --release-dir dist/anonymous-artifact \
  --archive dist/anonymous-revocation-completion-artifact.tar.gz

python3 artifact/scripts/check_anonymization.py \
  --root dist/anonymous-artifact
```

The builder removes Git metadata, interpreter caches, SQLite/state files,
Terraform state/plans, and checksums invalidated by transformation. It
deterministically anonymizes local paths/users/hosts, emails, public IPs, cloud
resource IDs, AWS account IDs, identity-center roles, and role sessions. It
then creates a new release checksum manifest and an archive with normalized
owner and timestamp metadata.

Before upload:

1. run the release scanner and `verify_checksums.py` against the generated
   directory;
2. extract the archive into a new temporary directory and scan it again;
3. inspect the archive listing for Git metadata and state databases;
4. upload only the archive, its SHA-256, and a neutral index page; and
5. perform an unauthenticated download, compare SHA-256, extract, and scan the
   downloaded bytes again.

The scanner rejects the known author account/email/user, non-placeholder AWS
accounts in ARNs/ECR URIs, identity-center role names, home paths, API-key
shapes, private keys, and non-placeholder email addresses. AWS account and role
placeholders are `000000000000` and `ANONYMOUS_REVIEW_ROLE`.

The artifact contains synthetic identities and no human-subject, customer, or
production-user data. Platform class and aggregate timing values are retained
because they are necessary to interpret E-B27 and do not identify an author.

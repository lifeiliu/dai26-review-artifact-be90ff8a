#!/usr/bin/env bash
set -euo pipefail

: "${AWS_PROFILE:?Set AWS_PROFILE to the IAM Identity Center profile}"
: "${AWS_REGION:?Set AWS_REGION to the workload region}"
: "${ECR_REPOSITORY:?Set ECR_REPOSITORY to the bootstrap output URL}"
: "${PYTHON_BASE:?Set PYTHON_BASE to an image pinned as name@sha256:digest}"
: "${IMAGE_TAG:?Set a unique immutable IMAGE_TAG}"

if [[ "${PYTHON_BASE}" != *@sha256:* ]]; then
  echo "PYTHON_BASE must be pinned by digest" >&2
  exit 2
fi

registry="${ECR_REPOSITORY%%/*}"
aws ecr get-login-password --profile "${AWS_PROFILE}" --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin "${registry}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
output_dir="${repo_root}/artifact/_outputs/e_b24_images/${IMAGE_TAG}"
mkdir -p "${output_dir}"

source_tree_sha256="$(python3 - "${repo_root}/artifact" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
paths = [root / "pyproject.toml", root / "README.md"]
paths.extend(sorted(path for path in (root / "src").rglob("*") if path.is_file()))
digest = hashlib.sha256()
for path in paths:
    digest.update(path.relative_to(root).as_posix().encode())
    digest.update(b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")
print(digest.hexdigest())
PY
)"
build_definition_sha256="$(python3 - "${repo_root}" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
paths = [
    root / "artifact" / ".dockerignore",
    root / "infra" / "e_b24" / "images" / "runtime" / "Dockerfile",
    root / "infra" / "e_b24" / "scripts" / "build_runtime_image.sh",
]
digest = hashlib.sha256()
for path in paths:
    digest.update(path.relative_to(root).as_posix().encode())
    digest.update(b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")
print(digest.hexdigest())
PY
)"
git_revision="$(git -C "${repo_root}" rev-parse HEAD)"
if [[ -n "$(git -C "${repo_root}" status --porcelain -- artifact/src artifact/pyproject.toml artifact/README.md)" ]]; then
  git_dirty=true
else
  git_dirty=false
fi

docker buildx build \
  --platform linux/amd64 \
  --build-arg "PYTHON_BASE=${PYTHON_BASE}" \
  --file "${repo_root}/infra/e_b24/images/runtime/Dockerfile" \
  --tag "${ECR_REPOSITORY}:${IMAGE_TAG}" \
  --label "org.opencontainers.image.revision=${git_revision}" \
  --label "org.opencontainers.image.source-tree-sha256=${source_tree_sha256}" \
  --label "org.opencontainers.image.build-definition-sha256=${build_definition_sha256}" \
  --provenance=true \
  --sbom=true \
  --push \
  "${repo_root}/artifact"

aws ecr describe-images \
  --profile "${AWS_PROFILE}" \
  --region "${AWS_REGION}" \
  --repository-name "paper-b-e-b24/runtime" \
  --image-ids "imageTag=${IMAGE_TAG}" \
  --query 'imageDetails[0].{digest:imageDigest,pushed_at:imagePushedAt,size_bytes:imageSizeInBytes}' \
  --output json > "${output_dir}/runtime-image.json"

python3 - "${output_dir}/runtime-image.json" "${ECR_REPOSITORY}" "${IMAGE_TAG}" "${PYTHON_BASE}" "${source_tree_sha256}" "${build_definition_sha256}" "${git_revision}" "${git_dirty}" <<'PY'
import json, pathlib, sys
path, repository, tag, base, source_tree_sha256, build_definition_sha256, git_revision, git_dirty = sys.argv[1:]
body = json.loads(pathlib.Path(path).read_text())
body["repository"] = repository
body["tag"] = tag
body["image_reference"] = f"{repository}@{body['digest']}"
body["python_base"] = base
body["source_tree_sha256"] = source_tree_sha256
body["build_definition_sha256"] = build_definition_sha256
body["git_revision"] = git_revision
body["git_dirty"] = git_dirty == "true"
pathlib.Path(path).write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
print(body["image_reference"])
PY

#!/usr/bin/env bash
set -euo pipefail

role="${1:-$(jq -r '.role' /etc/e-b24/host.json)}"
host_name="$(jq -r '.host' /etc/e-b24/host.json)"
region="${AWS_REGION:-us-east-1}"
parameter_root="/paper-b/e-b24/strict"
materials="/etc/e-b24/materials"
runtime_image="$(cat /etc/e-b24/runtime-image)"
postgres_image="pgvector/pgvector:0.8.0-pg17-bookworm@sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87"
keycloak_image="quay.io/keycloak/keycloak:26.7.0@sha256:2eb3cd316835c990e69e26ade292ffa78f6fb0db7d5fc6377463c162e1979ac0"
expected_allowlist_sha256="9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2"

umask 077
mkdir -p "${materials}" /var/lib/e-b24 /var/log/e-b24

parameter() {
  local name="$1"
  local destination="$2"
  aws ssm get-parameter \
    --region "${region}" \
    --name "${parameter_root}/${name}" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text > "${destination}"
  chmod 0400 "${destination}"
}

parameter_value() {
  aws ssm get-parameter \
    --region "${region}" \
    --name "${parameter_root}/$1" \
    --query 'Parameter.Value' \
    --output text
}

fetch_hashed_s3_object() {
  local key_parameter="$1"
  local destination="$2"
  local bucket key expected observed
  bucket="$(parameter_value config/evidence-bucket)"
  key="$(parameter_value "${key_parameter}")"
  expected="$(basename "$(dirname "${key}")")"
  aws s3 cp --region "${region}" --only-show-errors "s3://${bucket}/${key}" "${destination}"
  observed="$(sha256sum "${destination}" | awk '{print $1}')"
  if [[ "${observed}" != "${expected}" ]]; then
    echo "hashed S3 object mismatch for ${key_parameter}" >&2
    exit 3
  fi
  chmod 0444 "${destination}"
}

fetch_allowlist() {
  fetch_hashed_s3_object config/allowlist-key "${materials}/frozen-vector-allowlist.json"
  echo "${expected_allowlist_sha256}  ${materials}/frozen-vector-allowlist.json" | sha256sum -c -
}

pull_runtime() {
  local registry
  registry="${runtime_image%%/*}"
  aws ecr get-login-password --region "${region}" | docker login --username AWS --password-stdin "${registry}" >/dev/null
  docker pull "${runtime_image}" >/dev/null
  docker logout "${registry}" >/dev/null 2>&1 || true
  rm -f /root/.docker/config.json
}

wait_container_health() {
  local name="$1"
  for _ in $(seq 1 90); do
    if [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${name}" 2>/dev/null || true)" == "healthy" ]]; then
      return 0
    fi
    sleep 2
  done
  docker logs "${name}" >&2 || true
  return 1
}

wait_https() {
  local name="$1"
  local url="$2"
  local attempts="${3:-90}"
  for _ in $(seq 1 "${attempts}"); do
    if curl --silent --show-error --fail --cacert "${materials}/ca.crt" "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  docker logs "${name}" >&2 || true
  return 1
}

case "${role}" in
  keycloak-postgres)
    parameter secrets/keycloak-db-password "${materials}/keycloak-db-password"
    docker rm -f e-b24-keycloak-postgres >/dev/null 2>&1 || true
    docker pull "${postgres_image}" >/dev/null
    docker volume create e-b24-keycloak-pgdata >/dev/null
    docker run -d \
      --name e-b24-keycloak-postgres \
      --restart unless-stopped \
      --network host \
      --mount source=e-b24-keycloak-pgdata,target=/var/lib/postgresql/data \
      --mount type=bind,src="${materials}/keycloak-db-password",dst=/run/e-b24/keycloak-db-password,readonly \
      --env POSTGRES_DB=keycloak \
      --env POSTGRES_USER=keycloak \
      --env POSTGRES_PASSWORD_FILE=/run/e-b24/keycloak-db-password \
      --health-cmd='pg_isready -U keycloak -d keycloak' \
      --health-interval=2s \
      --health-timeout=2s \
      --health-retries=60 \
      "${postgres_image}" >/dev/null
    wait_container_health e-b24-keycloak-postgres
    ;;

  filesystem-effect-service)
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter pki/filesystem-effects-cert "${materials}/server.crt"
    parameter pki/filesystem-effects-key "${materials}/server.key"
    parameter secrets/effect-token "${materials}/effect-token"
    fetch_allowlist
    pull_runtime
    mkdir -p /var/lib/e-b24/filesystem-effects
    chown -R 24024:24024 "${materials}" /var/lib/e-b24/filesystem-effects
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${materials}/frozen-vector-allowlist.json"
    docker rm -f e-b24-filesystem-effects >/dev/null 2>&1 || true
    docker run -d \
      --name e-b24-filesystem-effects \
      --restart unless-stopped \
      --network host \
      --mount type=bind,src="${materials}",dst=/run/e-b24,readonly \
      --mount type=bind,src=/var/lib/e-b24/filesystem-effects,dst=/var/lib/e-b24/filesystem-effects \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_cloud_effects \
      --host 0.0.0.0 \
      --port 9443 \
      --vector-allowlist /run/e-b24/frozen-vector-allowlist.json \
      --bearer-token-file /run/e-b24/effect-token \
      --tls-cert /run/e-b24/server.crt \
      --tls-key /run/e-b24/server.key \
      --service filesystem \
      --filesystem-root /var/lib/e-b24/filesystem-effects >/dev/null
    wait_https e-b24-filesystem-effects "https://filesystem-effects:9443/health"
    ;;

  postgres-effect-service-database)
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter pki/postgres-effects-cert "${materials}/server.crt"
    parameter pki/postgres-effects-key "${materials}/server.key"
    parameter secrets/effect-token "${materials}/effect-token"
    parameter secrets/effect-db-password "${materials}/effect-db-password"
    fetch_allowlist
    pull_runtime
    chown -R 24024:24024 "${materials}"
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${materials}/frozen-vector-allowlist.json"
    docker network inspect e-b24-postgres-effects >/dev/null 2>&1 || docker network create e-b24-postgres-effects >/dev/null
    docker rm -f e-b24-postgres-effects e-b24-effect-postgres >/dev/null 2>&1 || true
    docker pull "${postgres_image}" >/dev/null
    docker volume create e-b24-effect-pgdata >/dev/null
    docker run -d \
      --name e-b24-effect-postgres \
      --restart unless-stopped \
      --network e-b24-postgres-effects \
      --mount source=e-b24-effect-pgdata,target=/var/lib/postgresql/data \
      --mount type=bind,src="${materials}/effect-db-password",dst=/run/e-b24/effect-db-password,readonly \
      --env POSTGRES_DB=effects \
      --env POSTGRES_USER=effects \
      --env POSTGRES_PASSWORD_FILE=/run/e-b24/effect-db-password \
      --health-cmd='pg_isready -U effects -d effects' \
      --health-interval=2s \
      --health-timeout=2s \
      --health-retries=60 \
      "${postgres_image}" >/dev/null
    wait_container_health e-b24-effect-postgres
    docker run -d \
      --name e-b24-postgres-effects \
      --restart unless-stopped \
      --network e-b24-postgres-effects \
      --publish 9443:9443 \
      --mount type=bind,src="${materials}",dst=/run/e-b24,readonly \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_cloud_effects \
      --host 0.0.0.0 \
      --port 9443 \
      --vector-allowlist /run/e-b24/frozen-vector-allowlist.json \
      --bearer-token-file /run/e-b24/effect-token \
      --tls-cert /run/e-b24/server.crt \
      --tls-key /run/e-b24/server.key \
      --service postgres \
      --postgres-host e-b24-effect-postgres \
      --postgres-database effects \
      --postgres-user effects \
      --postgres-password-file /run/e-b24/effect-db-password \
      --postgres-sslmode disable >/dev/null
    wait_https e-b24-postgres-effects "https://postgres-effects:9443/health"
    ;;

  gateway)
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter "pki/${host_name}-cert" "${materials}/server.crt"
    parameter "pki/${host_name}-key" "${materials}/server.key"
    parameter secrets/effect-token "${materials}/effect-token"
    parameter secrets/gateway-token "${materials}/gateway-token"
    fetch_allowlist
    pull_runtime
    mkdir -p /var/lib/e-b24/gateway
    chown -R 24024:24024 "${materials}" /var/lib/e-b24/gateway
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${materials}/frozen-vector-allowlist.json"
    docker rm -f "e-b24-${host_name}" >/dev/null 2>&1 || true
    docker run -d \
      --name "e-b24-${host_name}" \
      --restart unless-stopped \
      --network host \
      --add-host filesystem-effects:10.24.2.21 \
      --add-host postgres-effects:10.24.3.21 \
      --mount type=bind,src="${materials}",dst=/run/e-b24,readonly \
      --mount type=bind,src=/var/lib/e-b24/gateway,dst=/var/lib/e-b24/gateway \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_cloud_gateway \
      --gateway-id "${host_name}" \
      --mcp-port 8000 \
      --control-port 9444 \
      --control-tls-cert /run/e-b24/server.crt \
      --control-tls-key /run/e-b24/server.key \
      --control-bearer-token-file /run/e-b24/gateway-token \
      --state-db /var/lib/e-b24/gateway/gateway.sqlite3 \
      --vector-allowlist /run/e-b24/frozen-vector-allowlist.json \
      --filesystem-effect-url https://filesystem-effects:9443 \
      --postgres-effect-url https://postgres-effects:9443 \
      --effect-ca-file /run/e-b24/ca.crt \
      --effect-bearer-token-file /run/e-b24/effect-token >/dev/null
    wait_https "e-b24-${host_name}" "https://${host_name}:9444/health"
    ;;

  durable-receiver-a|durable-receiver-b)
    receiver_name="${host_name}"
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter "pki/${receiver_name}-cert" "${materials}/server.crt"
    parameter "pki/${receiver_name}-key" "${materials}/server.key"
    parameter "secrets/${receiver_name}-token" "${materials}/receiver-token"
    parameter secrets/gateway-token "${materials}/gateway-token"
    printf 'Bearer %s' "$(cat "${materials}/receiver-token")" > "${materials}/receiver-authorization"
    gateway_targets="${materials}/gateway-targets.json"
    if [[ "${receiver_name}" == "receiver-a" ]]; then
      first_gateway=1
      last_gateway=4
    else
      first_gateway=5
      last_gateway=8
    fi
    python3 -c 'import json,sys; first,last=map(int,sys.argv[2:4]); json.dump([{"gateway_id":f"gateway-{i}","gateway_url":f"https://gateway-{i}:9444"} for i in range(first,last+1)], open(sys.argv[1],"w"), separators=(",",":"))' "${gateway_targets}" "${first_gateway}" "${last_gateway}"
    gateway_host_args=(
      --add-host gateway-1:10.24.1.11
      --add-host gateway-2:10.24.1.12
      --add-host gateway-3:10.24.1.13
      --add-host gateway-4:10.24.2.11
      --add-host gateway-5:10.24.2.12
      --add-host gateway-6:10.24.2.13
      --add-host gateway-7:10.24.3.11
      --add-host gateway-8:10.24.3.12
    )
    pull_runtime
    mkdir -p /var/lib/e-b24/receiver
    chown -R 24024:24024 "${materials}" /var/lib/e-b24/receiver
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${gateway_targets}"
    docker rm -f "e-b24-${receiver_name}-ingress" "e-b24-${receiver_name}-worker" >/dev/null 2>&1 || true
    docker run -d \
      --name "e-b24-${receiver_name}-ingress" \
      --restart unless-stopped \
      --network host \
      --add-host keycloak:10.24.1.20 \
      --mount type=bind,src="${materials}",dst=/run/e-b24,readonly \
      --mount type=bind,src=/var/lib/e-b24/receiver,dst=/var/lib/e-b24/receiver \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_receiver ingress \
      --port 8443 \
      --state-db /var/lib/e-b24/receiver/receiver.sqlite3 \
      --issuer https://keycloak:8443/realms/ssf-smoke \
      --audience-prefix "${receiver_name}/" \
      --jwks-url https://keycloak:8443/realms/ssf-smoke/protocol/openid-connect/certs \
      --jwks-ca-file /run/e-b24/ca.crt \
      --gateway-targets /run/e-b24/gateway-targets.json \
      --push-authorization-file /run/e-b24/receiver-authorization \
      --evidence-jsonl /var/lib/e-b24/receiver/receiver-events.jsonl \
      --tls-cert /run/e-b24/server.crt \
      --tls-key /run/e-b24/server.key >/dev/null
    docker run -d \
      --name "e-b24-${receiver_name}-worker" \
      --restart unless-stopped \
      --network host \
      "${gateway_host_args[@]}" \
      --mount type=bind,src="${materials}/ca.crt",dst=/run/e-b24/ca.crt,readonly \
      --mount type=bind,src="${materials}/gateway-token",dst=/run/e-b24/gateway-token,readonly \
      --mount type=bind,src=/var/lib/e-b24/receiver,dst=/var/lib/e-b24/receiver \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_receiver worker \
      --state-db /var/lib/e-b24/receiver/receiver.sqlite3 \
      --gateway-bearer-token-file /run/e-b24/gateway-token \
      --gateway-ca-file /run/e-b24/ca.crt \
      --interval-seconds 0.25 >/dev/null
    wait_https "e-b24-${receiver_name}-ingress" "https://${receiver_name}:8443/health"
    ;;

  keycloak)
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter pki/keycloak-cert "${materials}/server.crt"
    parameter pki/keycloak-key "${materials}/server.key"
    parameter secrets/keycloak-admin-password "${materials}/keycloak-admin-password"
    parameter secrets/keycloak-db-password "${materials}/keycloak-db-password"
    fetch_hashed_s3_object config/keycloak-realm-key "${materials}/keycloak-realm.json"
    chown -R 1000:0 "${materials}"
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${materials}/keycloak-realm.json"
    docker rm -f e-b24-keycloak >/dev/null 2>&1 || true
    docker pull "${keycloak_image}" >/dev/null
    docker run -d \
      --name e-b24-keycloak \
      --restart unless-stopped \
      --network host \
      --add-host keycloak-postgres:10.24.2.20 \
      --mount type=bind,src="${materials}/ca.crt",dst=/run/e-b24/ca.crt,readonly \
      --mount type=bind,src="${materials}/server.crt",dst=/run/e-b24/server.crt,readonly \
      --mount type=bind,src="${materials}/server.key",dst=/run/e-b24/server.key,readonly \
      --mount type=bind,src="${materials}/keycloak-admin-password",dst=/run/e-b24/keycloak-admin-password,readonly \
      --mount type=bind,src="${materials}/keycloak-db-password",dst=/run/e-b24/keycloak-db-password,readonly \
      --mount type=bind,src="${materials}/keycloak-realm.json",dst=/opt/keycloak/data/import/ssf-smoke-realm.json,readonly \
      --env KC_DB=postgres \
      --env KC_DB_URL=jdbc:postgresql://keycloak-postgres:5432/keycloak \
      --env KC_DB_USERNAME=keycloak \
      --entrypoint /bin/bash \
      "${keycloak_image}" \
      -lc 'export KC_BOOTSTRAP_ADMIN_USERNAME=admin; export KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/e-b24/keycloak-admin-password)"; export KC_DB_PASSWORD="$(cat /run/e-b24/keycloak-db-password)"; exec /opt/keycloak/bin/kc.sh start --import-realm --features=ssf --hostname=https://keycloak:8443 --http-enabled=false --https-port=8443 --https-certificate-file=/run/e-b24/server.crt --https-certificate-key-file=/run/e-b24/server.key --truststore-paths=/run/e-b24/ca.crt' >/dev/null
    wait_https e-b24-keycloak "https://keycloak:8443/realms/ssf-smoke/.well-known/openid-configuration" 180
    ;;

  workload-driver)
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter secrets/effect-token "${materials}/effect-token"
    parameter secrets/receiver-a-token "${materials}/receiver-a-token"
    parameter secrets/receiver-b-token "${materials}/receiver-b-token"
    parameter secrets/keycloak-admin-password "${materials}/keycloak-admin-password"
    fetch_allowlist
    fetch_hashed_s3_object config/infrastructure-pilot-key "${materials}/infrastructure-pilot.py"
    pull_runtime
    chown -R 24024:24024 "${materials}"
    chmod 0444 "${materials}/ca.crt" "${materials}/frozen-vector-allowlist.json"
    ;;

  independent-fault-controller)
    parameter pki/ca-cert "${materials}/ca.crt"
    chmod 0444 "${materials}/ca.crt"
    ;;

  *)
    echo "unsupported strict role: ${role}" >&2
    exit 2
    ;;
esac

echo "${host_name}:${role}:bootstrap-complete"

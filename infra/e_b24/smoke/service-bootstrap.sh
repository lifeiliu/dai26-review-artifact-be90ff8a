#!/usr/bin/env bash
set -euo pipefail

role="${1:?usage: service-bootstrap.sh effects|gateway|receiver-gateway|driver|keycloak [peer-private-ip] [issuer-private-ip]}"
effects_private_ip="${2:-}"
issuer_private_ip="${3:-}"
region="${AWS_REGION:-us-east-1}"
parameter_root="/paper-b/e-b24/smoke"
materials="/etc/e-b24/materials"
runtime_image="$(cat /etc/e-b24/runtime-image)"
postgres_image="pgvector/pgvector:0.8.0-pg17-bookworm@sha256:40b404964359299eefdd5f8518facf1886c562848cf4de13b6eaf91cb70c2b87"
keycloak_image="quay.io/keycloak/keycloak:26.7.0@sha256:2eb3cd316835c990e69e26ade292ffa78f6fb0db7d5fc6377463c162e1979ac0"

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

fetch_allowlist() {
  local bucket key
  bucket="$(aws ssm get-parameter --region "${region}" --name "${parameter_root}/config/evidence-bucket" --query 'Parameter.Value' --output text)"
  key="$(aws ssm get-parameter --region "${region}" --name "${parameter_root}/config/allowlist-key" --query 'Parameter.Value' --output text)"
  aws s3 cp --region "${region}" --only-show-errors "s3://${bucket}/${key}" "${materials}/frozen-vector-allowlist.json"
  echo '9e76d237213e899486bfd65fad817cedd500cd0820535aa8e953519a24b8e9b2  /etc/e-b24/materials/frozen-vector-allowlist.json' | sha256sum -c -
  chmod 0444 "${materials}/frozen-vector-allowlist.json"
}

fetch_synthetic_jwks() {
  local bucket key expected observed
  bucket="$(aws ssm get-parameter --region "${region}" --name "${parameter_root}/config/evidence-bucket" --query 'Parameter.Value' --output text)"
  key="$(aws ssm get-parameter --region "${region}" --name "${parameter_root}/config/synthetic-jwks-key" --query 'Parameter.Value' --output text)"
  expected="$(basename "$(dirname "${key}")")"
  aws s3 cp --region "${region}" --only-show-errors "s3://${bucket}/${key}" "${materials}/jwks.json"
  observed="$(sha256sum "${materials}/jwks.json" | awk '{print $1}')"
  if [[ "${observed}" != "${expected}" ]]; then
    echo "synthetic JWKS hash mismatch" >&2
    exit 3
  fi
  chmod 0444 "${materials}/jwks.json"
}

fetch_keycloak_realm() {
  local bucket key expected observed
  bucket="$(aws ssm get-parameter --region "${region}" --name "${parameter_root}/config/evidence-bucket" --query 'Parameter.Value' --output text)"
  key="$(aws ssm get-parameter --region "${region}" --name "${parameter_root}/config/keycloak-realm-key" --query 'Parameter.Value' --output text)"
  expected="$(basename "$(dirname "${key}")")"
  aws s3 cp --region "${region}" --only-show-errors "s3://${bucket}/${key}" "${materials}/keycloak-realm.json"
  observed="$(sha256sum "${materials}/keycloak-realm.json" | awk '{print $1}')"
  if [[ "${observed}" != "${expected}" ]]; then
    echo "Keycloak realm hash mismatch" >&2
    exit 3
  fi
  chmod 0444 "${materials}/keycloak-realm.json"
}

wait_container_health() {
  local name="$1"
  for _ in $(seq 1 60); do
    if [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${name}" 2>/dev/null || true)" == "healthy" ]]; then
      return 0
    fi
    sleep 2
  done
  docker logs "${name}" >&2 || true
  return 1
}

case "${role}" in
  effects)
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter pki/smoke-3-cert "${materials}/server.crt"
    parameter pki/smoke-3-key "${materials}/server.key"
    parameter secrets/effect-token "${materials}/effect-token"
    parameter secrets/gateway-token "${materials}/gateway-token"
    parameter secrets/effect-db-password "${materials}/effect-db-password"
    fetch_allowlist
    chown -R 24024:24024 "${materials}"
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${materials}/frozen-vector-allowlist.json"
    mkdir -p /var/lib/e-b24/filesystem-effects
    chown -R 24024:24024 /var/lib/e-b24/filesystem-effects

    docker network inspect e-b24 >/dev/null 2>&1 || docker network create e-b24 >/dev/null
    docker rm -f e-b24-effects e-b24-effect-postgres >/dev/null 2>&1 || true
    docker pull "${postgres_image}" >/dev/null
    docker volume create e-b24-effect-pgdata >/dev/null
    docker run -d \
      --name e-b24-effect-postgres \
      --restart unless-stopped \
      --network e-b24 \
      --mount source=e-b24-effect-pgdata,target=/var/lib/postgresql/data \
      --mount type=bind,src="${materials}",dst=/run/e-b24,readonly \
      --env POSTGRES_DB=effects \
      --env POSTGRES_USER=effects \
      --env POSTGRES_PASSWORD_FILE=/run/e-b24/effect-db-password \
      --health-cmd='pg_isready -U effects -d effects' \
      --health-interval=2s \
      --health-timeout=2s \
      --health-retries=30 \
      "${postgres_image}" >/dev/null
    wait_container_health e-b24-effect-postgres

    docker run -d \
      --name e-b24-effects \
      --restart unless-stopped \
      --network e-b24 \
      --publish 9443:9443 \
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
      --service both \
      --filesystem-root /var/lib/e-b24/filesystem-effects \
      --postgres-host e-b24-effect-postgres \
      --postgres-database effects \
      --postgres-user effects \
      --postgres-password-file /run/e-b24/effect-db-password \
      --postgres-sslmode disable >/dev/null
    ;;
  gateway)
    if [[ -z "${effects_private_ip}" ]]; then
      echo "gateway role requires the effects private IP" >&2
      exit 2
    fi
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter pki/smoke-2-cert "${materials}/server.crt"
    parameter pki/smoke-2-key "${materials}/server.key"
    parameter secrets/effect-token "${materials}/effect-token"
    parameter secrets/gateway-token "${materials}/gateway-token"
    fetch_allowlist
    chown -R 24024:24024 "${materials}"
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${materials}/frozen-vector-allowlist.json"
    mkdir -p /var/lib/e-b24/gateway
    chown -R 24024:24024 /var/lib/e-b24/gateway

    docker rm -f e-b24-gateway >/dev/null 2>&1 || true
    docker run -d \
      --name e-b24-gateway \
      --restart unless-stopped \
      --network host \
      --mount type=bind,src="${materials}",dst=/run/e-b24,readonly \
      --mount type=bind,src=/var/lib/e-b24/gateway,dst=/var/lib/e-b24/gateway \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_cloud_gateway \
      --gateway-id smoke-gateway-1 \
      --mcp-port 8000 \
      --control-port 8443 \
      --control-tls-cert /run/e-b24/server.crt \
      --control-tls-key /run/e-b24/server.key \
      --control-bearer-token-file /run/e-b24/gateway-token \
      --state-db /var/lib/e-b24/gateway/gateway.sqlite3 \
      --vector-allowlist /run/e-b24/frozen-vector-allowlist.json \
      --filesystem-effect-url "https://${effects_private_ip}:9443" \
      --postgres-effect-url "https://${effects_private_ip}:9443" \
      --effect-ca-file /run/e-b24/ca.crt \
      --effect-bearer-token-file /run/e-b24/effect-token >/dev/null
    ;;
  receiver-gateway)
    if [[ -z "${effects_private_ip}" ]]; then
      echo "receiver-gateway role requires the effects private IP" >&2
      exit 2
    fi
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter pki/smoke-2-cert "${materials}/server.crt"
    parameter pki/smoke-2-key "${materials}/server.key"
    parameter secrets/effect-token "${materials}/effect-token"
    parameter secrets/gateway-token "${materials}/gateway-token"
    parameter secrets/receiver-token "${materials}/receiver-token"
    fetch_allowlist
    fetch_synthetic_jwks
    receiver_issuer=https://synthetic-issuer.e-b24.invalid/realms/smoke
    receiver_audience_prefix=urn:paper-b:e-b24:receiver/
    receiver_jwks_url=http://127.0.0.1:9000/jwks.json
    receiver_host_args=()
    receiver_jwks_ca_args=()
    if [[ -n "${issuer_private_ip}" ]]; then
      receiver_issuer=https://smoke-1:8443/realms/ssf-smoke
      receiver_audience_prefix=receiver-a/
      receiver_jwks_url="${receiver_issuer}/protocol/openid-connect/certs"
      receiver_host_args=(--add-host "smoke-1:${issuer_private_ip}")
      receiver_jwks_ca_args=(--jwks-ca-file /run/e-b24/ca.crt)
    fi
    printf 'Bearer %s' "$(cat "${materials}/receiver-token")" > "${materials}/receiver-authorization"
    chown -R 24024:24024 "${materials}"
    chmod 0444 \
      "${materials}/ca.crt" \
      "${materials}/server.crt" \
      "${materials}/frozen-vector-allowlist.json" \
      "${materials}/jwks.json"
    mkdir -p \
      /var/lib/e-b24/gateway \
      /var/lib/e-b24/receiver/jwks
    printf '%s\n' '[{"gateway_id":"smoke-gateway-1","gateway_url":"https://smoke-2:9444"}]' \
      > /var/lib/e-b24/receiver/gateway-targets.json
    cp "${materials}/jwks.json" /var/lib/e-b24/receiver/jwks/jwks.json
    chown -R 24024:24024 /var/lib/e-b24/gateway /var/lib/e-b24/receiver

    docker rm -f \
      e-b24-gateway \
      e-b24-receiver-ingress \
      e-b24-receiver-worker \
      e-b24-synthetic-jwks >/dev/null 2>&1 || true
    docker run -d \
      --name e-b24-gateway \
      --restart unless-stopped \
      --network host \
      --mount type=bind,src="${materials}/ca.crt",dst=/run/e-b24/ca.crt,readonly \
      --mount type=bind,src="${materials}/server.crt",dst=/run/e-b24/server.crt,readonly \
      --mount type=bind,src="${materials}/server.key",dst=/run/e-b24/server.key,readonly \
      --mount type=bind,src="${materials}/effect-token",dst=/run/e-b24/effect-token,readonly \
      --mount type=bind,src="${materials}/gateway-token",dst=/run/e-b24/gateway-token,readonly \
      --mount type=bind,src="${materials}/frozen-vector-allowlist.json",dst=/run/e-b24/frozen-vector-allowlist.json,readonly \
      --mount type=bind,src=/var/lib/e-b24/gateway,dst=/var/lib/e-b24/gateway \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_cloud_gateway \
      --gateway-id smoke-gateway-1 \
      --mcp-port 8000 \
      --control-host 127.0.0.1 \
      --control-port 9444 \
      --control-tls-cert /run/e-b24/server.crt \
      --control-tls-key /run/e-b24/server.key \
      --control-bearer-token-file /run/e-b24/gateway-token \
      --state-db /var/lib/e-b24/gateway/gateway.sqlite3 \
      --vector-allowlist /run/e-b24/frozen-vector-allowlist.json \
      --filesystem-effect-url "https://${effects_private_ip}:9443" \
      --postgres-effect-url "https://${effects_private_ip}:9443" \
      --effect-ca-file /run/e-b24/ca.crt \
      --effect-bearer-token-file /run/e-b24/effect-token >/dev/null
    if [[ -z "${issuer_private_ip}" ]]; then
      docker run -d \
        --name e-b24-synthetic-jwks \
        --restart unless-stopped \
        --network host \
        --mount type=bind,src=/var/lib/e-b24/receiver/jwks,dst=/run/jwks,readonly \
        "${runtime_image}" \
        -m http.server 9000 --bind 127.0.0.1 --directory /run/jwks >/dev/null
    fi
    docker run -d \
      --name e-b24-receiver-ingress \
      --restart unless-stopped \
      --network host \
      "${receiver_host_args[@]}" \
      --mount type=bind,src="${materials}/ca.crt",dst=/run/e-b24/ca.crt,readonly \
      --mount type=bind,src="${materials}/server.crt",dst=/run/e-b24/server.crt,readonly \
      --mount type=bind,src="${materials}/server.key",dst=/run/e-b24/server.key,readonly \
      --mount type=bind,src="${materials}/receiver-authorization",dst=/run/e-b24/receiver-authorization,readonly \
      --mount type=bind,src=/var/lib/e-b24/receiver,dst=/var/lib/e-b24/receiver \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_receiver ingress \
      --port 8443 \
      --state-db /var/lib/e-b24/receiver/receiver.sqlite3 \
      --issuer "${receiver_issuer}" \
      --audience-prefix "${receiver_audience_prefix}" \
      --jwks-url "${receiver_jwks_url}" \
      "${receiver_jwks_ca_args[@]}" \
      --gateway-targets /var/lib/e-b24/receiver/gateway-targets.json \
      --push-authorization-file /run/e-b24/receiver-authorization \
      --evidence-jsonl /var/lib/e-b24/receiver/receiver-events.jsonl \
      --tls-cert /run/e-b24/server.crt \
      --tls-key /run/e-b24/server.key >/dev/null
    docker run -d \
      --name e-b24-receiver-worker \
      --restart unless-stopped \
      --network host \
      --add-host smoke-2:127.0.0.1 \
      --mount type=bind,src="${materials}/ca.crt",dst=/run/e-b24/ca.crt,readonly \
      --mount type=bind,src="${materials}/gateway-token",dst=/run/e-b24/gateway-token,readonly \
      --mount type=bind,src=/var/lib/e-b24/receiver,dst=/var/lib/e-b24/receiver \
      "${runtime_image}" \
      -m revocation_propagation.e_b24_receiver worker \
      --state-db /var/lib/e-b24/receiver/receiver.sqlite3 \
      --gateway-bearer-token-file /run/e-b24/gateway-token \
      --gateway-ca-file /run/e-b24/ca.crt \
      --interval-seconds 0.25 >/dev/null
    ;;
  driver)
    driver_materials=/etc/e-b24/driver-materials
    mkdir -p "${driver_materials}"
    parameter pki/ca-cert "${driver_materials}/ca.crt"
    parameter secrets/effect-token "${driver_materials}/effect-token"
    parameter secrets/receiver-token "${driver_materials}/receiver-token"
    parameter secrets/keycloak-admin-password "${driver_materials}/keycloak-admin-password"
    parameter secrets/synthetic-set-private-key "${driver_materials}/synthetic-set-private-key.pem"
    chown -R 24024:24024 "${driver_materials}"
    chmod 0444 "${driver_materials}/ca.crt"
    ;;
  keycloak)
    receiver_private_ip="${effects_private_ip}"
    if [[ -z "${receiver_private_ip}" ]]; then
      echo "keycloak role requires the receiver private IP" >&2
      exit 2
    fi
    parameter pki/ca-cert "${materials}/ca.crt"
    parameter pki/smoke-1-cert "${materials}/server.crt"
    parameter pki/smoke-1-key "${materials}/server.key"
    parameter secrets/keycloak-admin-password "${materials}/keycloak-admin-password"
    parameter secrets/keycloak-db-password "${materials}/keycloak-db-password"
    fetch_keycloak_realm
    chown -R 1000:0 "${materials}"
    chmod 0444 "${materials}/ca.crt" "${materials}/server.crt" "${materials}/keycloak-realm.json"

    docker network inspect e-b24-keycloak >/dev/null 2>&1 || docker network create e-b24-keycloak >/dev/null
    docker rm -f e-b24-keycloak e-b24-keycloak-postgres >/dev/null 2>&1 || true
    docker pull "${postgres_image}" >/dev/null
    docker pull "${keycloak_image}" >/dev/null
    docker volume create e-b24-keycloak-pgdata >/dev/null
    docker run -d \
      --name e-b24-keycloak-postgres \
      --restart unless-stopped \
      --network e-b24-keycloak \
      --mount source=e-b24-keycloak-pgdata,target=/var/lib/postgresql/data \
      --mount type=bind,src="${materials}/keycloak-db-password",dst=/run/e-b24/keycloak-db-password,readonly \
      --env POSTGRES_DB=keycloak \
      --env POSTGRES_USER=keycloak \
      --env POSTGRES_PASSWORD_FILE=/run/e-b24/keycloak-db-password \
      --health-cmd='pg_isready -U keycloak -d keycloak' \
      --health-interval=2s \
      --health-timeout=2s \
      --health-retries=30 \
      "${postgres_image}" >/dev/null
    wait_container_health e-b24-keycloak-postgres

    docker run -d \
      --name e-b24-keycloak \
      --restart unless-stopped \
      --network e-b24-keycloak \
      --publish 8443:8443 \
      --add-host "smoke-2:${receiver_private_ip}" \
      --mount type=bind,src="${materials}/ca.crt",dst=/run/e-b24/ca.crt,readonly \
      --mount type=bind,src="${materials}/server.crt",dst=/run/e-b24/server.crt,readonly \
      --mount type=bind,src="${materials}/server.key",dst=/run/e-b24/server.key,readonly \
      --mount type=bind,src="${materials}/keycloak-admin-password",dst=/run/e-b24/keycloak-admin-password,readonly \
      --mount type=bind,src="${materials}/keycloak-db-password",dst=/run/e-b24/keycloak-db-password,readonly \
      --mount type=bind,src="${materials}/keycloak-realm.json",dst=/opt/keycloak/data/import/ssf-smoke-realm.json,readonly \
      --env KC_DB=postgres \
      --env KC_DB_URL=jdbc:postgresql://e-b24-keycloak-postgres:5432/keycloak \
      --env KC_DB_USERNAME=keycloak \
      --entrypoint /bin/bash \
      "${keycloak_image}" \
      -lc 'export KC_BOOTSTRAP_ADMIN_USERNAME=admin; export KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/e-b24/keycloak-admin-password)"; export KC_DB_PASSWORD="$(cat /run/e-b24/keycloak-db-password)"; exec /opt/keycloak/bin/kc.sh start --import-realm --features=ssf --hostname=https://smoke-1:8443 --http-enabled=false --https-port=8443 --https-certificate-file=/run/e-b24/server.crt --https-certificate-key-file=/run/e-b24/server.key --truststore-paths=/run/e-b24/ca.crt --spi-ssf-transmitter--default--allow-insecure-push-targets=true' >/dev/null
    ;;
  *)
    echo "unsupported role: ${role}" >&2
    exit 2
    ;;
esac

echo "${role}-bootstrap-complete"

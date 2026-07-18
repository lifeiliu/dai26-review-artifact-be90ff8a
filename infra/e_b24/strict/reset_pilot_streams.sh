#!/usr/bin/env bash
# Reset only the two setup-pilot SSF streams before a clean qualification run.
set -euo pipefail

materials="/etc/e-b24/materials"
keycloak="https://keycloak:8443"
realm="ssf-smoke"

admin_password="$(<"${materials}/keycloak-admin-password")"
admin_token="$(
  curl --silent --show-error --fail \
    --cacert "${materials}/ca.crt" \
    --data-urlencode grant_type=password \
    --data-urlencode client_id=admin-cli \
    --data-urlencode username=admin \
    --data-urlencode "password=${admin_password}" \
    "${keycloak}/realms/master/protocol/openid-connect/token" \
  | jq -er .access_token
)"
unset admin_password

for client_id in receiver-a receiver-b; do
  stream_url="${keycloak}/admin/realms/${realm}/ssf/clients/${client_id}/stream"
  delete_status="$(
    curl --silent --show-error \
      --output /dev/null \
      --write-out '%{http_code}' \
      --request DELETE \
      --cacert "${materials}/ca.crt" \
      --header "Authorization: Bearer ${admin_token}" \
      "${stream_url}"
  )"
  case "${delete_status}" in
    204|404) ;;
    *)
      echo "unexpected stream reset status for ${client_id}: ${delete_status}" >&2
      exit 1
      ;;
  esac

  verify_status="$(
    curl --silent --show-error \
      --output /dev/null \
      --write-out '%{http_code}' \
      --cacert "${materials}/ca.crt" \
      --header "Authorization: Bearer ${admin_token}" \
      "${stream_url}"
  )"
  if [[ "${verify_status}" != "404" ]]; then
    echo "stream reset verification failed for ${client_id}: ${verify_status}" >&2
    exit 1
  fi
  echo "e-b24-pilot-stream-reset=${client_id}:404"
done

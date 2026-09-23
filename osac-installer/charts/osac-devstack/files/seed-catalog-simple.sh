#!/usr/bin/env bash
# Seed the minimal dev-full catalog through the private REST API.
#
# The hook runs inside the cluster, but the private API uses TLS. A local
# port-forward lets curl authenticate with the short-lived admin token without
# requiring grpcurl in the hook image.
set -euo pipefail

NS="${1:-${NS:-osac}}"
INTERNAL_SVC="${INTERNAL_SVC:-fulfillment-internal-api}"
INTERNAL_PORT="${INTERNAL_PORT:-8001}"
LOCAL_PORT="${LOCAL_PORT:-8001}"

log() { echo "[+] $*"; }

# The REST gateway encodes gRPC AlreadyExists as status code 6 in its JSON body.
is_already_exists() {
  grep -Eq '"code"[[:space:]]*:[[:space:]]*6([[:space:]]*[,}])' "${response_file}"
}

admin_token=$(kubectl -n "${NS}" create token admin)
response_file=$(mktemp)

# cleanup removes the response file and stops the port-forward.
cleanup() {
  rm -f "${response_file}"
  kill "${pf_pid:-}" 2>/dev/null || true
  wait "${pf_pid:-}" 2>/dev/null || true
}
trap cleanup EXIT

kubectl -n "${NS}" port-forward "svc/${INTERNAL_SVC}" "${LOCAL_PORT}:${INTERNAL_PORT}" >/dev/null 2>&1 &
pf_pid=$!

API="https://localhost:${LOCAL_PORT}/api/private/v1"
for _ in $(seq 1 15); do
  if curl -sk --connect-timeout 1 -o /dev/null "${API}/disk_images"; then
    break
  fi
  sleep 1
done

if ! kill -0 "${pf_pid}" 2>/dev/null; then
  echo 'Catalog seed port-forward failed' >&2
  exit 1
fi

# post creates one catalog resource and accepts only gRPC AlreadyExists conflicts.
post() {
  local path="$1"
  local description="$2"
  local payload="$3"
  local status

  if ! status=$(curl -skS --max-time 30 -o "${response_file}" -w '%{http_code}' \
    -H "Authorization: Bearer ${admin_token}" \
    -H 'Content-Type: application/json' \
    -X POST "${API}/${path}" -d "${payload}"); then
    echo "Failed to create ${description}: request to ${path} did not complete" >&2
    return 1
  fi

  case "${status}" in
    2*) log "${description}: created" ;;
    409)
      if is_already_exists; then
        log "${description}: already exists"
      else
        echo "Failed to create ${description}: API returned HTTP ${status}" >&2
        return 1
      fi
      ;;
    *)
      echo "Failed to create ${description}: API returned HTTP ${status}" >&2
      return 1
      ;;
  esac
}

log "Seeding catalog into '${NS}'..."

post disk_images 'disk image fedora' '{
  "metadata": {"name": "fedora", "tenant": "shared"},
  "spec": {
    "source_type": "SOURCE_TYPE_REGISTRY",
    "source_ref": "quay.io/containerdisks/fedora:latest",
    "guest_os_family": "GUEST_OS_FAMILY_LINUX",
    "architecture": ["ARCHITECTURE_AMD64", "ARCHITECTURE_ARM64"],
    "lifecycle": "DISK_IMAGE_LIFECYCLE_AVAILABLE"
  }
}'

for entry in \
  'u1-small:2:4:2 cores, 4 GiB RAM' \
  'u1-medium:4:8:4 cores, 8 GiB RAM' \
  'u1-large:8:16:8 cores, 16 GiB RAM'; do
  name="${entry%%:*}"
  remainder="${entry#*:}"
  vcpus="${remainder%%:*}"
  remainder="${remainder#*:}"
  memory_gib="${remainder%%:*}"
  description="${remainder#*:}"

  post instance_types "instance type ${name}" "{
    \"metadata\": {\"name\": \"${name}\"},
    \"spec\": {
      \"vcpus\": ${vcpus},
      \"memory_gib\": ${memory_gib},
      \"description\": \"${description}\",
      \"state\": \"INSTANCE_TYPE_STATE_ACTIVE\"
    }
  }"
done

post compute_instance_templates 'compute instance template osac.templates.ocp_virt_vm' '{
  "id": "osac.templates.ocp_virt_vm",
  "title": "Virtual Machine Template (Linux and Windows)",
  "description": "VM template for OpenShift Virtualization supporting Linux and Windows guests.",
  "spec_defaults": {
    "boot_disk": {"size_gib": 10},
    "run_strategy": "Always",
    "instance_type": {"name": "u1-medium"},
    "disk_image": {"name": "fedora"}
  }
}'

post compute_instance_catalog_items 'compute instance catalog item linux-vm' '{
  "metadata": {"name": "linux-vm"},
  "title": "Linux Virtual Machine",
  "description": "Fedora-based virtual machine with KVM acceleration.",
  "template": {"id": "osac.templates.ocp_virt_vm"},
  "published": true
}'

log 'Catalog seeded — ready to create compute instances'

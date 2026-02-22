#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing ${ENV_FILE}. Run terraform apply in infra/terraform/aws first." >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source "${ENV_FILE}"
set +a

cd "${SCRIPT_DIR}"

EXTRA_ARGS=()
if [[ -f "${SCRIPT_DIR}/group_vars/all/vault.yml" ]]; then
  HAS_VAULT_FLAG=false
  for arg in "$@"; do
    if [[ "${arg}" == "--ask-vault-pass" || "${arg}" == --vault-password-file* ]]; then
      HAS_VAULT_FLAG=true
      break
    fi
  done
  if [[ "${HAS_VAULT_FLAG}" == false ]]; then
    EXTRA_ARGS+=(--ask-vault-pass)
  fi
fi

ansible-playbook playbooks/site.yml "${EXTRA_ARGS[@]}" "$@"

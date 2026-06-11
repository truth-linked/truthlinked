#!/usr/bin/env bash
# print-bootnode-addr.sh
# Usage:
#   ./print-bootnode-addr.sh [KEYFILE] [PUBLIC_IP] [P2P_PORT]
#
# For the single-node deployment (validator1 by default).
# Outputs the string you give to --bootnodes on other nodes/gateway:
#   IP:P2P_PORT:the_dilithium_public_hex
#
# Examples:
#   ./print-bootnode-addr.sh
#   ./print-bootnode-addr.sh /root/truthlinked-extras/keys/validator1_keys.json 167.86.90.123 19080
#   PUBLIC_IP=203.0.113.55 ./print-bootnode-addr.sh
set -euo pipefail

KEYFILE="${1:-/root/truthlinked-extras/keys/validator1_keys.json}"
PUBLIC_IP="${2:-${PUBLIC_IP:-$(hostname -I 2>/dev/null | awk "{print \$1}" || echo "127.0.0.1")}}"
P2P_PORT="${3:-${P2P_PORT:-19080}}"

if [[ ! -f "$KEYFILE" ]]; then
  echo "Keyfile not found: $KEYFILE" >&2
  exit 1
fi

PUBKEY=$(python3 - "$KEYFILE" <<PY
import json, sys
with open(sys.argv[1]) as f:
    print(json.load(f)["dilithium_public"])
PY
)

echo "${PUBLIC_IP}:${P2P_PORT}:${PUBKEY}"

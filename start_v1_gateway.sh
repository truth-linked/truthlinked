ulimit -n 65536
#!/usr/bin/env bash
# Public RPC/ingress front — absorbs indexer + tx load off validator1 consensus.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT/target/release/node-v1-gateway"
LOG="$ROOT/logs/node-v1-gateway.log"
PIDFILE="$ROOT/.node_v1_gateway.pid"
KEYS="${GATEWAY_KEYS:-$ROOT/keys/fresh_wallet.json}"
DATA="$ROOT/data1-gateway"
mkdir -p "$ROOT/logs" "$DATA"

: "${NETWORK:=devnet}"
case "$NETWORK" in
  devnet|testnet) export TRUTHLINKED_FORCE_TESTNET=1 ;;
  mainnet) unset TRUTHLINKED_FORCE_TESTNET 2>/dev/null || true ;;
esac
GENESIS="${GENESIS_FILE:-$ROOT/genesis_bootnode.json}"

if [[ ! -x "$BIN" ]]; then
  echo "Missing $BIN"
  exit 1
fi

if ss -tlnp 2>/dev/null | grep -q ":19944 "; then
  existing="$(pgrep -x node-v1-gateway | head -1 || true)"
  if [[ -n "$existing" ]]; then
    echo "$existing" > "$PIDFILE"
    echo "Gateway already running on 19944 (pid $existing)"
    exit 0
  fi
  echo "Port 19944 in use by another process"
  exit 1
fi

PK1=$(python3 -c "import json; print(json.load(open(\"$ROOT/validator1_keys.json\"))[\"dilithium_public\"])")
PK2=$(python3 -c "import json; print(json.load(open(\"$ROOT/validator2_keys.json\"))[\"dilithium_public\"])")
PK3=$(python3 -c "import json; print(json.load(open(\"$ROOT/validator3_keys.json\"))[\"dilithium_public\"])")
PK4=$(python3 -c "import json; print(json.load(open(\"$ROOT/validator4_keys.json\"))[\"dilithium_public\"])")
PK5=$(python3 -c "import json; print(json.load(open(\"$ROOT/validator5_keys.json\"))[\"dilithium_public\"])")
BOOTNODES="167.86.90.123:19080:${PK1},167.86.90.123:19082:${PK2},167.86.90.123:19084:${PK3},167.86.90.123:19086:${PK4},167.86.90.123:19088:${PK5}"

echo "Starting v1 gateway (rpc 19944, ingress 18080, p2p 29180)"
cd "$ROOT"
setsid env RUST_LOG=info \
  "$BIN" \
    --validator-keys "$KEYS" \
    --data-dir "$DATA" \
    --ingress-port 18080 \
    --rpc-port 19944 \
    --p2p-port 29180 \
    --bootnodes "$BOOTNODES" \
    --genesis-file "$GENESIS" \
    --full \
    >> "$LOG" 2>&1 < /dev/null &
echo $! > "$PIDFILE"
echo "Gateway PID $(cat "$PIDFILE")"

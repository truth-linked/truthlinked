ulimit -n 65536
#!/usr/bin/env bash
set -uo pipefail   # removed -e so one node failing doesn't abort the rest

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$ROOT_DIR/logs"
PID_FILE="$ROOT_DIR/.node_pids"
BIN="$ROOT_DIR/target/release/node"

mkdir -p "$LOG_DIR"
: > "$PID_FILE"

# ── Network selection ─────────────────────────────────────────────────────────
: "${NETWORK:=devnet}"
: "${VALIDATOR_COUNT:=5}"
: "${SINGLE_NODE:=0}"

if ! [[ "$VALIDATOR_COUNT" =~ ^[1-5]$ ]]; then
  echo "Invalid VALIDATOR_COUNT=$VALIDATOR_COUNT. Use a value from 1 to 5."
  exit 1
fi

case "$NETWORK" in
  devnet)
    export TRUTHLINKED_FORCE_TESTNET=1
    unset TRUTHLINKED_SYNC_LENIENT 2>/dev/null || true
    GENESIS_FILE="${GENESIS_FILE:-$ROOT_DIR/genesis_bootnode.json}"
    echo "Network: DEVNET"
    ;;
  testnet)
    export TRUTHLINKED_FORCE_TESTNET=1
    unset TRUTHLINKED_SYNC_LENIENT 2>/dev/null || true
    GENESIS_FILE="${GENESIS_FILE:-$ROOT_DIR/genesis_bootnode.json}"
    echo "Network: TESTNET"
    ;;
  mainnet)
    unset TRUTHLINKED_FORCE_TESTNET 2>/dev/null || true
    GENESIS_FILE="${GENESIS_FILE:-$ROOT_DIR/genesis_validator.json}"
    echo "Network: MAINNET"
    ;;
  *)
    echo "Unknown NETWORK=$NETWORK. Use devnet, testnet, or mainnet."
    exit 1
    ;;
esac

GENESIS_ARGS=(--genesis-file "$GENESIS_FILE")

if [[ ! -x "$BIN" ]]; then
  echo "Binary not found: $BIN — run: cargo build --release"
  exit 1
fi

# ── Read pubkeys ──────────────────────────────────────────────────────────────
read_pubkey() {
  python3 - "$1" <<'PY'
import json, sys
with open(sys.argv[1]) as f: print(json.load(f)["dilithium_public"])
PY
}

PK1="$(read_pubkey "$ROOT_DIR/validator1_keys.json")"
PK2="$(read_pubkey "$ROOT_DIR/validator2_keys.json")"
PK3="$(read_pubkey "$ROOT_DIR/validator3_keys.json")"
PK4="$(read_pubkey "$ROOT_DIR/validator4_keys.json")"
PK5="$(read_pubkey "$ROOT_DIR/validator5_keys.json")"

# Mesh bootnodes — all 5 validators on this host.
# TruthLinked uses a dedicated high-port block to avoid conflicts with nginx,
# gema, goalert, and other services on this machine.
ALL_BOOTNODES="167.86.90.123:19080:${PK1},167.86.90.123:19082:${PK2},167.86.90.123:19084:${PK3},167.86.90.123:19086:${PK4},167.86.90.123:19088:${PK5}"

# ── Start node ────────────────────────────────────────────────────────────────
start_node() {
  local idx="$1" keys="$2" data_dir="$3" ingress="$4" rpc="$5" p2p="$6" bootnodes="$7"
  local log="$LOG_DIR/node${idx}.log"
  local node_flags=()
  if [[ "$SINGLE_NODE" == "1" ]]; then
    node_flags+=(--single-node)
  else
    node_flags+=(--local-validator-count "$VALIDATOR_COUNT")
  fi
  if ss -tlnp | grep -q ":${rpc} "; then
    echo "Node ${idx} already running on port ${rpc}, skipping"
    return 0
  fi


  echo "Starting node ${idx} (${NETWORK}, rpc ${rpc}, p2p ${p2p})"
  cd "$ROOT_DIR"

  setsid env RUST_LOG=info \
    "$BIN" \
      --validator-keys "$keys" \
      --data-dir "$data_dir" \
      --ingress-port "$ingress" \
      --rpc-port "$rpc" \
      --p2p-port "$p2p" \
      ${bootnodes:+--bootnodes "$bootnodes"} \
      "${GENESIS_ARGS[@]}" \
      "${node_flags[@]}" \
      >> "$log" 2>&1 < /dev/null &
  local pid=$!
  echo $pid >> "$PID_FILE"
}

# ── Launch validators ─────────────────────────────────────────────────────────
if (( VALIDATOR_COUNT >= 1 )); then
  if [[ "$SINGLE_NODE" == "1" || "$VALIDATOR_COUNT" == "1" ]]; then
    start_node 1 "$ROOT_DIR/validator1_keys.json" "$ROOT_DIR/data1" 18081 19941 19080 ""
  else
    start_node 1 "$ROOT_DIR/validator1_keys.json" "$ROOT_DIR/data1" 18081 19941 19080 "$ALL_BOOTNODES"
  fi
fi
if (( VALIDATOR_COUNT >= 2 )); then
  start_node 2 "$ROOT_DIR/validator2_keys.json" "$ROOT_DIR/data2" 18082 19954 19082 "$ALL_BOOTNODES"
fi
if (( VALIDATOR_COUNT >= 3 )); then
  start_node 3 "$ROOT_DIR/validator3_keys.json" "$ROOT_DIR/data3" 18084 19964 19084 "$ALL_BOOTNODES"
fi
if (( VALIDATOR_COUNT >= 4 )); then
  start_node 4 "$ROOT_DIR/validator4_keys.json" "$ROOT_DIR/data4" 18086 19974 19086 "$ALL_BOOTNODES"
fi
if (( VALIDATOR_COUNT >= 5 )); then
  start_node 5 "$ROOT_DIR/validator5_keys.json" "$ROOT_DIR/data5" 18088 19984 19088 "$ALL_BOOTNODES"
fi

echo "Nodes started (NETWORK=$NETWORK, VALIDATOR_COUNT=$VALIDATOR_COUNT, SINGLE_NODE=$SINGLE_NODE). PIDs: $PID_FILE"
echo "Logs: $LOG_DIR/node*.log"

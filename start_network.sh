#!/bin/bash
set -e
cd /root/truthlinked

V1=$(python3 -c "import json; d=json.load(open('validator1_keys.json')); print(d['dilithium_public'])")
V2=$(python3 -c "import json; d=json.load(open('validator2_keys.json')); print(d['dilithium_public'])")
V3=$(python3 -c "import json; d=json.load(open('validator3_keys.json')); print(d['dilithium_public'])")
V4=$(python3 -c "import json; d=json.load(open('validator4_keys.json')); print(d['dilithium_public'])")
V5=$(python3 -c "import json; d=json.load(open('validator5_keys.json')); print(d['dilithium_public'])")

IP="127.0.0.1"
NODE=./target/release/node

echo "Stopping existing nodes..."
pkill -f "target/release/node" 2>/dev/null || true
sleep 3

echo "Starting 5-node devnet..."

RUST_LOG=info nohup $NODE --validator-keys validator1_keys.json --data-dir data1 --ingress-port 18081 --rpc-port 19941 --p2p-port 19080 --genesis-file genesis.json \
  --bootnodes "${IP}:19090:${V2}" --bootnodes "${IP}:19100:${V3}" --bootnodes "${IP}:19110:${V4}" --bootnodes "${IP}:19120:${V5}" > logs/node1.log 2>&1 &

RUST_LOG=info nohup $NODE --validator-keys validator2_keys.json --data-dir data2 --ingress-port 18091 --rpc-port 19951 --p2p-port 19090 --genesis-file genesis.json \
  --bootnodes "${IP}:19080:${V1}" --bootnodes "${IP}:19100:${V3}" --bootnodes "${IP}:19110:${V4}" --bootnodes "${IP}:19120:${V5}" > logs/node2.log 2>&1 &

RUST_LOG=info nohup $NODE --validator-keys validator3_keys.json --data-dir data3 --ingress-port 18101 --rpc-port 19961 --p2p-port 19100 --genesis-file genesis.json \
  --bootnodes "${IP}:19080:${V1}" --bootnodes "${IP}:19090:${V2}" --bootnodes "${IP}:19110:${V4}" --bootnodes "${IP}:19120:${V5}" > logs/node3.log 2>&1 &

RUST_LOG=info nohup $NODE --validator-keys validator4_keys.json --data-dir data4 --ingress-port 18111 --rpc-port 19971 --p2p-port 19110 --genesis-file genesis.json \
  --bootnodes "${IP}:19080:${V1}" --bootnodes "${IP}:19090:${V2}" --bootnodes "${IP}:19100:${V3}" --bootnodes "${IP}:19120:${V5}" > logs/node4.log 2>&1 &

RUST_LOG=info nohup $NODE --validator-keys validator5_keys.json --data-dir data5 --ingress-port 18121 --rpc-port 19981 --p2p-port 19120 --genesis-file genesis.json \
  --bootnodes "${IP}:19080:${V1}" --bootnodes "${IP}:19090:${V2}" --bootnodes "${IP}:19100:${V3}" --bootnodes "${IP}:19110:${V4}" > logs/node5.log 2>&1 &

sleep 8
echo "=== Node status ==="
for port in 19941 19951 19961 19971 19981; do
  echo -n "  Node $port: "
  curl -s http://localhost:$port/chain_info | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"peers={d['peer_count']} height={d['height']} status={d['sync_status']}\")"
done

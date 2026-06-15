#!/bin/bash
# Single validator dev node — no peers needed, instant startup
set -e
cd /root/truthlinked

NODE=./target/release/node

pkill -f "target/release/node" 2>/dev/null || true
sleep 2

nohup $NODE \
  --validator-keys validator1_keys.json \
  --data-dir data1 \
  --ingress-port 18081 \
  --rpc-port 19941 \
  --p2p-port 19080 \
  --genesis-file genesis.json \
  > logs/node1.log 2>&1 &

echo "Dev node started. RPC: http://localhost:19941"
sleep 3
curl -s http://localhost:19941/chain_info | python3 -m json.tool

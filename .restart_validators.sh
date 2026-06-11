#!/usr/bin/env bash
cd /root/truthlinked || exit 2
set -o pipefail
printf "restart_time="; date -Is
printf "pre_nodes=\n"; ps -eo pid,ppid,stat,etime,args --width 320 | grep '[/]root/truthlinked/target/release/node --validator-keys' || true
printf "stopping_nodes=\n"
for pid in $(pgrep -f '/root/truthlinked/target/release/node --validator-keys' || true); do
  echo TERM:$pid
  kill -TERM "$pid" 2>/dev/null || true
done
sleep 5
for pid in $(pgrep -f '/root/truthlinked/target/release/node --validator-keys' || true); do
  echo KILL:$pid
  kill -KILL "$pid" 2>/dev/null || true
done
sleep 2
printf "remaining_after_stop=\n"; ps -eo pid,ppid,stat,etime,args --width 320 | grep '[/]root/truthlinked/target/release/node --validator-keys' || true
printf "start_network=\n"
NETWORK=devnet VALIDATOR_COUNT=5 bash ./start_network.sh
code=$?
printf "start_exit=%s\n" "$code"
sleep 20
printf "post_nodes=\n"; ps -eo pid,ppid,stat,etime,args --width 320 | grep '[/]root/truthlinked/target/release/node --validator-keys' || true
printf "post_rpc=\n"
for p in 19944 19954 19964 19974 19984; do
  printf "%s " "$p"
  curl -fsS --max-time 4 http://127.0.0.1:$p/chain_info 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print("height=%s finalized=%s sync=%s peers=%s"%(d.get("height"),d.get("finalized_height"),d.get("sync_status"),d.get("peer_count")))' 2>/dev/null || echo rpc_failed
done
exit "$code"

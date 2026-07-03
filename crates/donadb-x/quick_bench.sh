#!/bin/bash
cd /root/donadb-x

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  DonaDbX OPTIMIZED Performance Benchmark                   ║"
echo "║  Parallel Fold • CLOCK Cache • Lock-Free Index             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Quick focused benchmark
cargo test --release --lib optimization_benchmark -- --nocapture --test-threads=1 2>&1 | grep -A 50 "DonaDbX Optimization"


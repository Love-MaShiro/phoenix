#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "== Building ref benchmark =="
make -C "$ROOT_DIR/ref" test/benchmark
echo

echo "== Building shake-avx2 benchmarks =="
make -C "$ROOT_DIR/shake-avx2" test/benchmark test/x4_benchmark
echo

echo "== ref keypair/sign/verify =="
"$ROOT_DIR/ref/test/benchmark"
echo

echo "== shake-avx2 keypair/sign/verify =="
"$ROOT_DIR/shake-avx2/test/benchmark"
echo

echo "== shake-avx2 x4 microbenchmarks =="
"$ROOT_DIR/shake-avx2/test/x4_benchmark"

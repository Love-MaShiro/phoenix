#!/bin/bash
# Phoenix — Full Benchmark Runner
# Runs keygen/sign/verify cycle counts for all 40 instances.
# Output: CSV in results/

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESDIR="$ROOT/bench/results"
mkdir -p "$RESDIR"

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
CSV="$RESDIR/phoenix_benchmark_${TIMESTAMP}.csv"
LOG="$RESDIR/run_${TIMESTAMP}.log"

echo "Phoenix Benchmark — $(date)" | tee "$LOG"
echo "CPU: $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2- | xargs)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

HEADER="Scheme,Impl,Level,Mode,KeyGen_med,KeyGen_avg,Sign_med,Sign_avg,Verify_med,Verify_avg"
echo "$HEADER" > "$CSV"

parse_one() {
    # Extract "median X cycles" and "avg. Y us" from a benchmark line
    local line="$1"
    local med=$(echo "$line" | grep -oP 'median\s+\K[0-9,]+(?=\s+cycles)' || echo "0")
    med=$(echo "$med" | tr -d ',')
    # Use "1x:" value as the single-run reference (close to median for consistent runs)
    local sng=$(echo "$line" | grep -oP '1x:\s+\K[0-9,]+(?=\s+cycles)' || echo "0")
    sng=$(echo "$sng" | tr -d ',')
    # Average from "avg. X us"
    local avg_us=$(echo "$line" | grep -oP 'avg\.\s+\K[0-9.]+(?=\s+us)' || echo "0")
    if [ -n "$avg_us" ] && [ "$avg_us" != "0" ]; then
        avg=$(python3 -c "print(int(float($avg_us) * 2900))" 2>/dev/null || echo "0")
    else
        avg="0"
    fi
    echo "$med,$avg"
}

parse_bench_output() {
    local out="$1"
    local kg=""; local sg=""; local vf=""

    while IFS= read -r line; do
        case "$line" in
            *"Generating keypair"*) kg=$(parse_one "$line") ;;
            *"Signing"* | *"Signing.."*) sg=$(parse_one "$line") ;;
            *"Verifying"*) vf=$(parse_one "$line") ;;
        esac
    done <<< "$out"

    echo "${kg:-0,0},${sg:-0,0},${vf:-0,0}"
}

run_one() {
    local scheme="$1"    # SHAKE or SM3
    local level="$2"     # 128, 192, 256, 384, 512
    local mode="$3"      # f or s
    local impl="$4"      # Ref or AVX2

    local inst="Phoenix-${scheme}-${level}${mode}"
    local label="${scheme}-${level}${mode}"

    if [ "$impl" = "AVX2" ]; then
        # AVX2 目录命名: Phoenix-SHAKE-128f-avx2
        local dir="$ROOT/Implementations/Optimized_Implementation/avx2/${inst}-avx2"
        local impl_label="AVX2"
        # 如果目录不存在，尝试不带 -avx2 后缀
        if [ ! -d "$dir" ]; then
            dir="$ROOT/Implementations/Optimized_Implementation/avx2/${inst}"
        fi
    else
        local dir="$ROOT/Implementations/Reference_Implementation/${inst}"
        local impl_label="Ref"
    fi

    if [ ! -d "$dir" ]; then
        echo "  SKIP $inst ($impl): directory not found" | tee -a "$LOG"
        echo "    Tried: $dir" | tee -a "$LOG"
        return
    fi

    echo -n "  $inst ($impl_label) ... " | tee -a "$LOG"

    cd "$dir"

    # Workaround: 's' (small) mode uses gwots.c/gwotsx1.c but Makefile references gwots.c/gwotsx1.c
    for f in gwots.c gwotsx1.c; do
        base="${f#g}"
        [ ! -f "$f" ] && [ -f "$base" ] && ln -sf "$base" "$f"
    done

    # 清理旧对象文件，避免链接冲突
    make clean >/dev/null 2>&1 || true

    # 尝试构建 benchmark，并捕获详细错误
    BUILD_LOG="/tmp/phoenix_build_$$.log"
    if ! make -j4 benchmark > "$BUILD_LOG" 2>&1; then
        echo "BUILD FAIL" | tee -a "$LOG"
        echo "    Build error (last 5 lines):" | tee -a "$LOG"
        tail -5 "$BUILD_LOG" | sed 's/^/      /' | tee -a "$LOG"
        rm -f "$BUILD_LOG"
        return
    fi
    rm -f "$BUILD_LOG"

    # 检查 benchmark 可执行文件是否存在
    if [ ! -x ./benchmark ]; then
        echo "NO EXECUTABLE" | tee -a "$LOG"
        return
    fi

    # 运行 benchmark
    local bench_out
    bench_out=$(timeout 120 ./benchmark 2>&1) || {
        echo "TIMEOUT/CRASH" | tee -a "$LOG"
        return
    }

    # 如果输出为空，可能是 benchmark 没有输出
    if [ -z "$bench_out" ]; then
        echo "NO OUTPUT" | tee -a "$LOG"
        return
    fi

    local vals
    vals=$(parse_bench_output "$bench_out")

    # 检查是否成功解析到数据
    if [ "$vals" = "0,0,0,0,0,0" ]; then
        echo "PARSE FAIL (raw output sample:)" | tee -a "$LOG"
        echo "$bench_out" | head -10 | sed 's/^/      /' | tee -a "$LOG"
        return
    fi

    echo "${scheme},${impl_label},${level},${mode},${vals}" >> "$CSV"
    echo "OK" | tee -a "$LOG"
}

# 检查必要的工具
if ! command -v python3 &> /dev/null; then
    echo "WARNING: python3 not found, avg. cycles will be 0" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "=== Reference — f (fast) mode ===" | tee -a "$LOG"

for scheme in SHAKE SM3; do
    for level in 128 192 256 384 512; do
        run_one "$scheme" "$level" "f" "Ref"
    done
done

echo "" | tee -a "$LOG"
echo "=== Reference — s (small) mode ===" | tee -a "$LOG"
echo "(Note: s-mode benchmark requires GWOTS support — may fail if benchmark.c uses GWOTS calls)" | tee -a "$LOG"

for scheme in SHAKE SM3; do
    for level in 128 192 256 384 512; do
        run_one "$scheme" "$level" "s" "Ref"
    done
done

echo "" | tee -a "$LOG"
echo "=== Optimized AVX2 — f mode ===" | tee -a "$LOG"

for scheme in SHAKE SM3; do
    for level in 128 192 256 384 512; do
        run_one "$scheme" "$level" "f" "AVX2"
    done
done

echo "" | tee -a "$LOG"
echo "=== Optimized AVX2 — s mode ===" | tee -a "$LOG"

for scheme in SHAKE SM3; do
    for level in 128 192 256 384 512; do
        run_one "$scheme" "$level" "s" "AVX2"
    done
done

echo "" | tee -a "$LOG"
echo "=== Done ===" | tee -a "$LOG"
echo "CSV: $CSV" | tee -a "$LOG"
echo "Log: $LOG" | tee -a "$LOG"
wc -l "$CSV" | tee -a "$LOG"
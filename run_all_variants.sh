#!/bin/bash

# Configuration
LEVELS=("128" "192" "256" "512")
HASHES=("sha2" "shake")
VARIANTS=("f" "s")
MODES=("simple") # Usually "simple" is the default for these variants in recent SPHINCS+

# Output file
RESULT_FILE="benchmark_results.txt"
echo "Phoenix Comprehensive Benchmark Results - $(date)" > $RESULT_FILE
echo "===============================================================" >> $RESULT_FILE

# Temporary build log
BUILD_LOG="build_all.log"
rm -f $BUILD_LOG

echo "Starting benchmarks for all variants..."
echo "Results will be saved to $RESULT_FILE"

for hash in "${HASHES[@]}"; do
    for level in "${LEVELS[@]}"; do
        for var in "${VARIANTS[@]}"; do
            for mode in "${MODES[@]}"; do
                PARAM="phoenix-${hash}-${level}${var}"
                echo "---------------------------------------------------------------"
                echo "Processing: $PARAM ($mode)"
                
                # Build
                make clean > /dev/null 2>&1
                make tests benchmarks PARAMS=$PARAM THASH=$mode >> $BUILD_LOG 2>&1
                
                if [ $? -ne 0 ]; then
                    echo "[FAILED] Build error for $PARAM. See $BUILD_LOG"
                    echo "$PARAM ($mode): BUILD FAILED" >> $RESULT_FILE
                    continue
                fi
                
                # Run SPX test
                echo "  Running SPX test..."
                TEST_OUT=$(./test/spx 2>&1)
                SUCCESS_RATE=$(echo "$TEST_OUT" | grep "Success rate" | awk '{print $3}')
                
                # Run Benchmark
                echo "  Running Benchmark..."
                BENCH_OUT=$(./test/benchmark 2>&1)
                
                # Extract some key metrics from benchmark output
                # Using a more robust extraction that works even if errors are interspersed
                KEYGEN=$(echo "$BENCH_OUT" | grep "Generating keypair.." | grep "median" | sed 's/.*median[[:space:]]*\([0-9,]*\) cycles.*/\1/')
                # If KEYGEN is empty, it might be on the next line
                if [ -z "$KEYGEN" ]; then
                    KEYGEN=$(echo "$BENCH_OUT" | grep -A 5 "Generating keypair.." | grep "median" | head -n 1 | sed 's/.*median[[:space:]]*\([0-9,]*\) cycles.*/\1/')
                fi

                SIGN=$(echo "$BENCH_OUT" | grep "Signing.." | grep "median" | grep -v "WOTS" | sed 's/.*median[[:space:]]*\([0-9,]*\) cycles.*/\1/')
                if [ -z "$SIGN" ]; then
                    SIGN=$(echo "$BENCH_OUT" | grep -A 5 "Signing.." | grep "median" | grep -v "WOTS" | head -n 1 | sed 's/.*median[[:space:]]*\([0-9,]*\) cycles.*/\1/')
                fi

                VERIFY=$(echo "$BENCH_OUT" | grep "Verifying.." | grep "median" | sed 's/.*median[[:space:]]*\([0-9,]*\) cycles.*/\1/')
                if [ -z "$VERIFY" ]; then
                    VERIFY=$(echo "$BENCH_OUT" | grep -A 5 "Verifying.." | grep "median" | head -n 1 | sed 's/.*median[[:space:]]*\([0-9,]*\) cycles.*/\1/')
                fi

                SIG_SIZE=$(echo "$BENCH_OUT" | grep "Signature size:" | awk '{print $3}')
                
                # Log to result file
                {
                    echo "Variant: $PARAM ($mode)"
                    echo "Success Rate: $SUCCESS_RATE"
                    echo "KeyGen: $KEYGEN cycles"
                    echo "Sign:   $SIGN cycles"
                    echo "Verify: $VERIFY cycles"
                    echo "Signature Size: $SIG_SIZE bytes"
                    echo "---------------------------------------------------------------"
                } >> $RESULT_FILE
                
                echo "  [DONE] $PARAM: Success Rate $SUCCESS_RATE"
            done
        done
    done
done

echo ""
echo "All benchmarks finished. Summary saved in $RESULT_FILE"
echo "==============================================================="
cat $RESULT_FILE

#!/bin/bash

PARAMS_LIST=(
    "phoenix-sm3-128f"
    "phoenix-sm3-192f"
    "phoenix-sm3-256f"
    "phoenix-sm3-384f"
    "phoenix-sm3-512f"
    "phoenix-sm3-128s"
    "phoenix-sm3-192s"
    "phoenix-sm3-256s"
    "phoenix-sm3-384s"
    "phoenix-sm3-512s"
)

echo "=== SM3 参数完整 Benchmark 测试 (NTESTS=1, 每个参数运行10次) ==="
echo ""

for PARAMS in "${PARAMS_LIST[@]}"; do
    echo "测试参数: $PARAMS"
    
    thash_sum=0
    keygen_sum=0
    sign_sum=0
    verify_sum=0
    sigsize_sum=0
    
    for i in $(seq 1 10); do
        make clean > /dev/null 2>&1
        output=$(make PARAMS=$PARAMS benchmark 2>&1)
        
        thash=$(echo "$output" | grep "thash.*median" | grep -oP 'median\s+\K[\d,]+' | tr -d ',')
        keygen=$(echo "$output" | grep "Generating keypair..*median" | grep -oP 'median\s+\K[\d,]+' | tr -d ',')
        sign=$(echo "$output" | grep "Signing..*median" | grep -oP 'median\s+\K[\d,]+' | tr -d ',')
        verify=$(echo "$output" | grep "Verifying..*median" | grep -oP 'median\s+\K[\d,]+' | tr -d ',')
        sigsize=$(echo "$output" | grep "Signature size" | grep -oP '\d+')
        
        thash_sum=$((thash_sum + thash))
        keygen_sum=$((keygen_sum + keygen))
        sign_sum=$((sign_sum + sign))
        verify_sum=$((verify_sum + verify))
        sigsize_sum=$((sigsize_sum + sigsize))
    done
    
    thash_avg=$((thash_sum / 10))
    keygen_avg=$((keygen_sum / 10))
    sign_avg=$((sign_sum / 10))
    verify_avg=$((verify_sum / 10))
    sigsize_avg=$((sigsize_sum / 10))
    
    printf "  thash:       %'18d cycles\n" $thash_avg
    printf "  KeyGen:      %'18d cycles\n" $keygen_avg
    printf "  Sign:        %'18d cycles\n" $sign_avg
    printf "  Verify:      %'18d cycles\n" $verify_avg
    printf "  Signature:   %'18d bytes\n" $sigsize_avg
    echo ""
done

echo "=== 测试完成 ==="

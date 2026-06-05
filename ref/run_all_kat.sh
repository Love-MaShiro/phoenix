#!/bin/bash
# Build + run the signature KAT (keygen/sign/verify round-trip) for every
# parameter set and THASH mode, then summarise PASS/FAIL.
# haraka variants are intentionally excluded (to be deprecated; no arm64 AES-NI).
set -u

SSL=${SSL:-/opt/homebrew/opt/openssl@3}
EXTRA="-I$SSL/include -L$SSL/lib"

HASHES=(sha2 shake sm3)
LEVELS=(128 192 256 384 512)
VARS=(f)
MODES=(simple robust)

RESULT=kat_sweep_results.txt
: > "$RESULT"
PASS=0
FAIL=0

for h in "${HASHES[@]}"; do
  for l in "${LEVELS[@]}"; do
    for v in "${VARS[@]}"; do
      for m in "${MODES[@]}"; do
        P="phoenix-${h}-${l}${v}"
        printf "%-24s %-7s ... " "$P" "$m"
        make clean >/dev/null 2>&1
        if ! make PQCgenKAT_sign PARAMS="$P" THASH="$m" EXTRA_CFLAGS="$EXTRA" \
              >/tmp/kat_build.log 2>&1; then
          echo "BUILD-FAIL"
          echo "BUILD-FAIL   $P $m" >> "$RESULT"
          FAIL=$((FAIL+1))
          continue
        fi
        if ./PQCgenKAT_sign >/tmp/kat_run.log 2>&1; then
          sum=$(shasum -a 256 PQCsignKAT_*.rsp 2>/dev/null | awk '{print $1}')
          echo "PASS"
          echo "PASS         $P $m  rsp=$sum" >> "$RESULT"
          PASS=$((PASS+1))
        else
          rc=$?
          echo "KAT-FAIL(rc=$rc)"
          echo "KAT-FAIL($rc) $P $m" >> "$RESULT"
          FAIL=$((FAIL+1))
        fi
      done
    done
  done
done

echo "=== TOTAL PASS=$PASS FAIL=$FAIL ===" | tee -a "$RESULT"

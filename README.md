# Phoenix Signature Algorithm — Submission Package

## Algorithm Overview

Phoenix is a stateless hash-based digital signature scheme built on the
SPHINCS+ framework with GWOTS+ and FORS/TFORS one-time signature components.
It uses a hypertree of Merkle trees to combine many one-time key pairs into a
single long-term public key.

This submission supports two hash function families:

| Backend | Standard | XOF / Hash |
|---------|----------|------------|
| **Phoenix-SHAKE** | FIPS 202 | SHAKE-128 / SHAKE-256 |
| **Phoenix-SM3**   | GB/T 32905-2016 | SM3 / SM3-KDF (pseudoXOF) |

Each family provides 10 parameter sets across 5 security levels × 2 modes:

| Security Level | Classical Bits | `f` (fast) | `s` (small) |
|:---:|:---:|:---:|:---:|
| 128 | 128 | Phoenix-*-128f | Phoenix-*-128s |
| 192 | 192 | Phoenix-*-192f | Phoenix-*-192s |
| 256 | 256 | Phoenix-*-256f | Phoenix-*-256s |
| 384 | 384 | Phoenix-*-384f | Phoenix-*-384s |
| 512 | 512 | Phoenix-*-512f | Phoenix-*-512s |

- **`f` (fast)**: larger signatures, faster signing.
- **`s` (small)**: compact signatures, slower signing.

## Directory Structure

```text
.
├── README.md                          ← this file
├── Implementations/
│   ├── README.md                      ← detailed implementation guide
│   ├── Reference_Implementation/      ← 20 portable C reference instances
│   │   ├── Phoenix-SHAKE-128f/
│   │   ├── Phoenix-SHAKE-128s/
│   │   ├── ...
│   │   └── Phoenix-SM3-512s/
│   ├── Optimized_Implementation/
│   │   └── avx2/                      ← 20 AVX2-accelerated instances
│   │       ├── Phoenix-SHAKE-128f-avx2/
│   │       ├── ...
│   │       └── Phoenix-SM3-512s-avx2/
│   └── Additional_Implementation/    ← reserved
└── Test_Vectors/
    ├── KAT_SIG_Phoenix-SHAKE-128f.txt
    ├── ...
    └── KAT_SIG_Phoenix-SM3-512s.txt
```

## Quick Start

### Build & Run (Reference) 
Take Phoenix-SHAKE-128f as an example.

- **Build and run KAT_SIG**

```sh
cd Implementations/Reference_Implementation/Phoenix-SHAKE-128f
make KAT_SIG
./KAT_SIG
make clean
```

- **Build and run benchmark**

```sh
cd Implementations/Reference_Implementation/Phoenix-SHAKE-128f
make benchmark
./benchmark
make clean
```

Generated KAT output is placed in the `output/` subdirectory.

### Build & Run (Optimized, AVX2)
Take Phoenix-SHAKE-128f-avx2 as an example.


- **Build and run KAT_SIG**
```sh
cd Implementations/Optimized_Implementation/avx2/Phoenix-SHAKE-128f-avx2
make KAT_SIG
./KAT_SIG
make clean
```
- **Build and run benchmark**
```sh
cd Implementations/Optimized_Implementation/avx2/Phoenix-SHAKE-128f-avx2
make benchmark
./benchmark
make clean
```

### Verify KAT Output

Compare the generated output against the reference vectors:

```sh
diff output/KAT_SIG_Phoenix-SHAKE-128f.txt \
     ../../../Test_Vectors/KAT_SIG_Phoenix-SHAKE-128f.txt
```

All reference and optimized implementations must produce byte-identical KAT output.

## Build Requirements

| Component | Reference | Optimized (AVX2) |
|-----------|-----------|-------------------|
| Compiler | GCC ≥ 7 or Clang ≥ 10 | GCC ≥ 7 or Clang ≥ 10 |
| C Standard | C99 | C99 |
| CPU Features | — | AVX2, BMI2 |
| OS | Linux / macOS | Linux / macOS |
| Libraries | libm | libm |

## Algorithm Instances — Full List

```
Phoenix-SHAKE-128f      Phoenix-SM3-128f
Phoenix-SHAKE-128s      Phoenix-SM3-128s
Phoenix-SHAKE-192f      Phoenix-SM3-192f
Phoenix-SHAKE-192s      Phoenix-SM3-192s
Phoenix-SHAKE-256f      Phoenix-SM3-256f
Phoenix-SHAKE-256s      Phoenix-SM3-256s
Phoenix-SHAKE-384f      Phoenix-SM3-384f
Phoenix-SHAKE-384s      Phoenix-SM3-384s
Phoenix-SHAKE-512f      Phoenix-SM3-512f
Phoenix-SHAKE-512s      Phoenix-SM3-512s
```

## File Manifest

Each instance directory contains:

| File | Purpose |
|------|---------|
| `api.h` | Public API: `crypto_sign_keypair`, `crypto_sign`, `crypto_sign_open` |
| `sign.c` | Core signing and verification logic |
| `params.h` | Instance-specific security parameters |
| `SIG_AlgorithmInstance.{c,h}` | ICCS algorithm instance wrapper |
| `KAT_SIG.c` | Known Answer Test generator |
| `Makefile` | Build configuration |
| `drng.{c,h}` | Deterministic PRNG for reproducible KAT |
| `hash*.{c,h}` | Hash function abstraction layer |
| `gwots*.{c,h}` | GWOTS one-time signature |
| `tfors*.{c,h}` | TFORS few-time signature |
| `merkle.{c,h}` | Merkle tree operations |
| `address.{c,h}` | Hash address scheme |
| `utils*.{c,h}` | Utility functions |
| `fips202.{c,h}` | SHAKE-128/256 (FIPS 202) |
| `sm3*.{c,h}` | SM3 hash (for SM3 variants) |

## References

- SPHINCS+ — Submission to NIST PQC Standardization (Round 3)
- FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
- GB/T 32905-2016 — SM3 Cryptographic Hash Algorithm
- GB/T 32918.4-2016 — SM2 Elliptic Curve Public Key Cryptography (SM3-KDF)

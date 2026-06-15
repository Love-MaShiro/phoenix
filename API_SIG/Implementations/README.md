# Implementations Directory

This directory contains implementations of the Phoenix signature algorithm instances.

## Directory Structure

```
Implementations/
├── Additional_Implementation/     # Additional implementations (e.g., hardware-specific)
├── Optimized_Implementation/      # Optimized implementations for performance
│   └── avx2/                      # AVX2 optimized implementations
│       ├── Phoenix-SHAKE-128f-avx2/
│       ├── Phoenix-SHAKE-128s-avx2/
│       ├── Phoenix-SHAKE-192f-avx2/
│       ├── Phoenix-SHAKE-192s-avx2/
│       ├── Phoenix-SHAKE-256f-avx2/
│       ├── Phoenix-SHAKE-256s-avx2/
│       ├── Phoenix-SHAKE-384f-avx2/
│       ├── Phoenix-SHAKE-384s-avx2/
│       ├── Phoenix-SHAKE-512f-avx2/
│       ├── Phoenix-SHAKE-512s-avx2/
│       ├── Phoenix-SM3-128f-avx2/
│       ├── Phoenix-SM3-128s-avx2/
│       ├── Phoenix-SM3-192f-avx2/
│       ├── Phoenix-SM3-192s-avx2/
│       ├── Phoenix-SM3-256f-avx2/
│       ├── Phoenix-SM3-256s-avx2/
│       ├── Phoenix-SM3-384f-avx2/
│       ├── Phoenix-SM3-384s-avx2/
│       ├── Phoenix-SM3-512f-avx2/
│       └── Phoenix-SM3-512s-avx2/
└── Reference_Implementation/      # Reference implementations
    ├── Phoenix-SHAKE-128f/
    ├── Phoenix-SHAKE-128s/
    ├── Phoenix-SHAKE-192f/
    ├── Phoenix-SHAKE-192s/
    ├── Phoenix-SHAKE-256f/
    ├── Phoenix-SHAKE-256s/
    ├── Phoenix-SHAKE-384f/
    ├── Phoenix-SHAKE-384s/
    ├── Phoenix-SHAKE-512f/
    ├── Phoenix-SHAKE-512s/
    ├── Phoenix-SM3-128f/
    ├── Phoenix-SM3-128s/
    ├── Phoenix-SM3-192f/
    ├── Phoenix-SM3-192s/
    ├── Phoenix-SM3-256f/
    ├── Phoenix-SM3-256s/
    ├── Phoenix-SM3-384f/
    ├── Phoenix-SM3-384s/
    ├── Phoenix-SM3-512f/
    └── Phoenix-SM3-512s/
```

## Description

### Additional_Implementation/
Reserved for additional implementations such as hardware-specific optimizations,
alternative cryptographic primitives, or specialized deployments. This directory
currently contains only a placeholder file.

### Optimized_Implementation/
Contains performance-optimized implementations of Phoenix signature algorithm instances.

#### avx2/
AVX2 optimized implementations leveraging Intel AVX2 instruction set for parallel computation.
These implementations provide significant performance improvements through:
- 8-way parallel SM3 hash computation using AVX2 vectors
- Parallel tree hash operations (`thashx8`)
- Optimized utility functions (`utilsx8`)

### Reference_Implementation/
Contains reference implementations of Phoenix signature algorithm instances. These implementations
prioritize clarity and correctness over performance, serving as the authoritative specification
for each algorithm instance.

## Algorithm Instances

Each algorithm instance follows the naming convention:
`Phoenix-{HashFunction}-{SecurityLevel}{Mode}`

- **HashFunction**: SHAKE or SM3
- **SecurityLevel**: 128, 192, 256, 384, 512 (bits of security)
- **Mode**: 'f' (fast) or 's' (small)

### Security Parameters

| Instance | Security Level | Hash Function | Mode |
|----------|---------------|---------------|------|
| Phoenix-SHAKE-128f | 128 bits | SHAKE256 | Fast |
| Phoenix-SHAKE-128s | 128 bits | SHAKE256 | Small |
| Phoenix-SHAKE-192f | 192 bits | SHAKE256 | Fast |
| Phoenix-SHAKE-192s | 192 bits | SHAKE256 | Small |
| Phoenix-SHAKE-256f | 256 bits | SHAKE256 | Fast |
| Phoenix-SHAKE-256s | 256 bits | SHAKE256 | Small |
| Phoenix-SHAKE-384f | 384 bits | SHAKE256 | Fast |
| Phoenix-SHAKE-384s | 384 bits | SHAKE256 | Small |
| Phoenix-SHAKE-512f | 512 bits | SHAKE256 | Fast |
| Phoenix-SHAKE-512s | 512 bits | SHAKE256 | Small |
| Phoenix-SM3-128f | 128 bits | SM3 | Fast |
| Phoenix-SM3-128s | 128 bits | SM3 | Small |
| Phoenix-SM3-192f | 192 bits | SM3 | Fast |
| Phoenix-SM3-192s | 192 bits | SM3 | Small |
| Phoenix-SM3-256f | 256 bits | SM3 | Fast |
| Phoenix-SM3-256s | 256 bits | SM3 | Small |
| Phoenix-SM3-384f | 384 bits | SM3 | Fast |
| Phoenix-SM3-384s | 384 bits | SM3 | Small |
| Phoenix-SM3-512f | 512 bits | SM3 | Fast |
| Phoenix-SM3-512s | 512 bits | SM3 | Small |

## File Descriptions

Each algorithm instance directory contains the following files:

### Core Implementation Files
- **api.h** - Public API header with signature/verify function declarations
- **sign.c** - Signature generation implementation
- **SIG_AlgorithmInstance.c** - Algorithm instance-specific implementation
- **SIG_AlgorithmInstance.h** - Algorithm instance header

### Cryptographic Components
- **address.c/h** - Address management for tree nodes
- **auxfunc.c/h** - Auxiliary functions
- **hash.c/h** - Hash function wrappers
- **merkle.c/h** - Merkle tree operations
- **octopus.c/h** - Octopus transformation
- **tfors.c/h** - TFORS transformation
- **wots.c/h** - WOTS+ signature scheme
- **wotsx1.c/h** - Single-threaded WOTS+ operations

### Utility Functions
- **utils.c/h** - General utility functions
- **utilsx1.c/h** - Single-threaded utility functions

### Configuration
- **params.h** - Parameter definitions
- **params/params-phoenix-*.h** - Instance-specific parameters
- **Makefile** - Build configuration

### Testing
- **KAT_SIG.c** - Known Answer Test generation
- **KAT_SIG** - Pre-generated KAT vectors

### Documentation
- **README.md** - Instance-specific documentation
- **MODIFICATION_NOTES.md** - Implementation modification notes

### AVX2-Specific Files (Optimized Implementation)
- **sm3_avx2.c** - AVX2-optimized SM3 hash implementation
- **sm3_x8.c** - 8-way parallel SM3 interface
- **sm3_x4.c** - 4-way parallel SM3 interface (for NEON compatibility)
- **sm3_neon.c** - NEON-optimized SM3 hash implementation
- **sm3_scalar.c** - Scalar SM3 implementation (fallback)
- **hash_sm3x8.c** - 8-way parallel hash operations
- **thash_sm3_simplex8.c** - 8-way parallel tree hash operations
- **utilsx8.c/h** - 8-way parallel utility functions
- **hashx8.h** - 8-way parallel hash header
- **thashx8.h** - 8-way parallel tree hash header

## Building and Testing

Each algorithm instance directory contains its own Makefile. To build and generate KAT vectors:

```sh
cd Reference_Implementation/Phoenix-SHAKE-128f
make kat
```

For optimized implementations:

```sh
cd Optimized_Implementation/avx2/Phoenix-SHAKE-128f-avx2
make kat
```

## Test Vectors

Test vectors for all algorithm instances are located in the `../Test_Vectors/` directory.

## References

- Phoenix Signature Scheme Specification
- SHAKE256 (FIPS 202)
- SM3 (GB/T 32905-2016)
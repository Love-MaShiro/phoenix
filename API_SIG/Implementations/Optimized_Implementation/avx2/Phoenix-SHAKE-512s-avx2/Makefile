ALGORITHM_INSTANCE = Phoenix-SHAKE-128f-avx2
PARAMS = phoenix-shake-128f

CC ?= gcc
CFLAGS ?= -O3 -std=c99 -Wno-nullarity-completeness -Wno-nullarity-extension -Wno-newline-eof -Wno-sign-conversion
# AVX2 optimization flags
AVX2_CFLAGS = -mavx2
CFLAGS += $(AVX2_CFLAGS) -DPARAMS=$(PARAMS) -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -I. -DALLOW_DEEP_TREES -DSUBMISSION_DRNG -DAVX2_OPTIMIZED -DTHASH_VARIANT_simple

# Core sources (reference implementation)
CORE_SOURCES = \
	address.c \
	counter.c \
	fips202.c \
	hash_shake.c \
	merkle.c \
	octopus.c \
	randombytes.c \
	sign.c \
	tfors.c \
	thash_shake_simple.c \
	utils.c \
	utilsx1.c \
	wots.c \
	wotsx1.c

# AVX2 optimized sources (simple variant)
AVX2_SOURCES = \
	fips202x4.c \
	hash_shake256x4.c \
	thash_shake_simplex4.c \
	utilsx4.c \
	keccak4x/KeccakP-1600-times4-SIMD256.c

SUBMISSION_SOURCES = \
	SIG_AlgorithmInstance.c \
	drng.c \
	KAT_SIG.c

ALL_SOURCES = $(CORE_SOURCES) $(AVX2_SOURCES) $(SUBMISSION_SOURCES)

.PHONY: all clean kat

all: KAT_SIG

kat: KAT_SIG
	./KAT_SIG

KAT_SIG: $(ALL_SOURCES) SIG_AlgorithmInstance.h drng.h
	$(CC) $(CFLAGS) -o $@ $(ALL_SOURCES)

clean:
	$(RM) KAT_SIG
	$(RM) -r output
	$(RM) *.o

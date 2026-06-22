ALGORITHM_INSTANCE = Phoenix-SHAKE-128f-avx2
PARAMS = phoenix-shake-128f

CC ?= gcc
CFLAGS ?= -O3 -std=c99 -march=native
AVX2_CFLAGS ?= -mavx2
CFLAGS += $(AVX2_CFLAGS) -DPARAMS=$(PARAMS) -I. -DALLOW_DEEP_TREES -DSUBMISSION_DRNG -DAVX2_OPTIMIZED

CORE_SOURCES = \
	address.c \
	counter.c \
	fips202.c fips202x4.c \
	hash_shake.c hash_shake256x4.c \
	keccak4x/KeccakP-1600-times4-SIMD256.c \
	merkle.c \
	octopus.c \
	randombytes.c \
	sign.c \
	tfors.c \
	thash_shake_simple.c thash_shake_simplex4.c \
	utils.c utilsx1.c utilsx4.c \
	wots.c wotsx1.c wotsx4.c

SUBMISSION_SOURCES = \
	SIG_AlgorithmInstance.c \
	drng.c \
	KAT_SIG.c

HEADERS = \
	address.h counter.h fips202.h fips202x4.h \
	hash.h hashx4.h \
	merkle.h octopus.h randombytes.h shake_offsets.h \
	tfors.h thash.h thashx4.h \
	utils.h utilsx1.h utilsx4.h wots.h wotsx1.h \
	api.h params.h context.h drng.h \
	keccak4x/KeccakP-1600-times4-SnP.h \
	keccak4x/KeccakP-1600-unrolling.macros \
	keccak4x/SIMD256-config.h keccak4x/align.h keccak4x/brg_endian.h

.PHONY: all clean kat benchmark

all: KAT_SIG

kat: KAT_SIG
	./KAT_SIG

KAT_SIG: $(CORE_SOURCES) $(SUBMISSION_SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -o $@ $(CORE_SOURCES) $(SUBMISSION_SOURCES)

benchmark: $(CORE_SOURCES) test/benchmark.c test/cycles.c
	$(CC) $(CFLAGS) -U SUBMISSION_DRNG -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -o $@ $(CORE_SOURCES) test/benchmark.c test/cycles.c

clean:
	$(RM) KAT_SIG
	$(RM) benchmark
	$(RM) -r output

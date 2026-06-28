ALGORITHM_INSTANCE = Phoenix-SHAKE-512s-avx2
PARAMS = phoenix-shake-512s

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
	SIG_AlgorithmInstance.c \
	tfors.c \
	thash_shake_simple.c thash_shake_simplex4.c \
	utils.c utilsx1.c utilsx4.c \
	gwotsc.c gwotscx1.c gwotscx4.c

SUBMISSION_SOURCES = \
	drng.c \
	KAT_SIG.c

HEADERS = \
	address.h counter.h fips202.h fips202x4.h \
	hash.h hashx4.h \
	merkle.h octopus.h randombytes.h shake_offsets.h \
	tfors.h thash.h thashx4.h \
	utils.h utilsx1.h utilsx4.h gwotsc.h gwotscx1.h gwotscx4.h \
	api.h params.h context.h drng.h \
	keccak4x/KeccakP-1600-times4-SnP.h \
	keccak4x/KeccakP-1600-unrolling.macros \
	keccak4x/SIMD256-config.h keccak4x/align.h keccak4x/brg_endian.h

TESTS = test/spx \
		test/tfors \
		test/octopus

BENCHMARK = test/benchmark

.PHONY: all clean kat test tests benchmark benchmarks

all: KAT_SIG

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

kat: KAT_SIG
	./KAT_SIG

KAT_SIG: $(CORE_SOURCES) $(SUBMISSION_SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -o $@ $(CORE_SOURCES) $(SUBMISSION_SOURCES)

$(BENCHMARK): $(CORE_SOURCES) test/benchmark.c test/cycles.c
	$(CC) $(CFLAGS) -U SUBMISSION_DRNG -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -o $@ $(CORE_SOURCES) test/benchmark.c test/cycles.c

test/%: test/%.c $(CORE_SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -U SUBMISSION_DRNG -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -o $@ $(CORE_SOURCES) $<

test/%.exec: test/%
	@$<

clean:
	$(RM) KAT_SIG
	$(RM) $(BENCHMARK)
	$(RM) $(TESTS)
	$(RM) -r output

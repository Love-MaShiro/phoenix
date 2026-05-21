PARAMS ?= phoenix-shake-256s
THASH ?= simple

CC ?= /usr/bin/gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes
AVX2_CFLAGS ?= -mavx2
CFLAGS += $(AVX2_CFLAGS) -DPARAMS=$(PARAMS) -DPARAMNAME=\"$(PARAMS)\" -DTHASH_VARIANT_$(THASH) -I. -Itest -DALLOW_DEEP_TREES $(EXTRA_CFLAGS)

THASHX4_SOURCES = thash_shake_$(THASH)x4.c
THASHX4_HEADERS = thashx4.h
THASHX4_TESTS = test/thashx4
CONSISTENCY_TESTS = test/test_x4_consistency

SOURCES = address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c \
	utilsx4.c tfors.c sign.c octopus.c counter.c fips202.c fips202x4.c hash_shake.c \
	hash_shake256x4.c thash_shake_$(THASH).c $(THASHX4_SOURCES) \
	keccak4x/KeccakP-1600-times4-SIMD256.c
HEADERS = api.h params.h context.h address.h counter.h fips202.h hash.h \
	merkle.h octopus.h randombytes.h shake_offsets.h tfors.h thash.h \
	utils.h utilsx1.h utilsx4.h wots.h wotsx1.h rng.h fips202x4.h hashx4.h \
	$(THASHX4_HEADERS) \
	keccak4x/KeccakP-1600-times4-SnP.h keccak4x/KeccakP-1600-unrolling.macros \
	keccak4x/SIMD256-config.h keccak4x/align.h keccak4x/brg_endian.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/tfors \
	test/spx \
	test/octopus \
	test/gwots \
	test/hashx4 \
	test/utilsx4 \
	$(CONSISTENCY_TESTS) \
	$(THASHX4_TESTS)

BENCHMARKS = test/benchmark \
	test/x4_benchmark \
	test/gwots_benchmark \
	test/tfors_benchmark

.PHONY: default all tests test benchmarks benchmark clean

default: all

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARKS)

benchmark: $(BENCHMARKS:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/benchmark: test/benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $<

test/tfors_benchmark: test/tfors_benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $<

test/gwots_benchmark: test/gwots_benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $<

test/x4_benchmark: test/x4_benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $<

test/test_x4_consistency: test/test_x4_consistency.c test/test_x4_consistency_vectors.h $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $<

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARKS)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req

ALGORITHM_INSTANCE = Phoenix-SM3-192f-avx2
PARAMS = phoenix-sm3-192f

CC ?= gcc
CFLAGS ?= -O3 -std=c99 -march=native
CFLAGS += -DPARAMS=$(PARAMS) -I. -DALLOW_DEEP_TREES -DSUBMISSION_DRNG -DAVX2_OPTIMIZED

CORE_SOURCES = \
	address.c \
	auxfunc.c \
	counter.c \
	hash_sm3.c sm3_drng.c hash_sm3x8.c \
	merkle.c \
	octopus.c \
	randombytes.c \
	sign.c \
	tfors.c \
	thash_sm3_simple.c thash_sm3_simplex8.c \
	utils.c \
	utilsx1.c \
	wots.c \
	wotsx1.c

AVX2_SOURCES = \
	sm3_avx2.c \
	sm3_x4.c \
	sm3_x8.c

SUBMISSION_SOURCES = \
	SIG_AlgorithmInstance.c \
	drng.c \
	KAT_SIG.c

.PHONY: all clean kat benchmark

all: KAT_SIG

kat: KAT_SIG
	./KAT_SIG

KAT_SIG: $(CORE_SOURCES) $(AVX2_SOURCES) $(SUBMISSION_SOURCES) SIG_AlgorithmInstance.h drng.h
	$(CC) $(CFLAGS) -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -o $@ $(CORE_SOURCES) $(AVX2_SOURCES) $(SUBMISSION_SOURCES)

benchmark: $(CORE_SOURCES) $(AVX2_SOURCES) test/benchmark.c test/cycles.c
	$(CC) $(CFLAGS) -U SUBMISSION_DRNG -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -o $@ $(CORE_SOURCES) $(AVX2_SOURCES) test/benchmark.c test/cycles.c

clean:
	$(RM) KAT_SIG
	$(RM) benchmark
	$(RM) -r output
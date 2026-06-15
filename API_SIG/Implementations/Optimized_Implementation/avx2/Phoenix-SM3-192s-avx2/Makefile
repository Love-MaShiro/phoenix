ALGORITHM_INSTANCE = Phoenix-SM3-192s-avx2
PARAMS = phoenix-sm3-192s
AVX2_CFLAGS = -mavx2
CFLAGS ?= -O3 -std=c99 -Wno-nullability-completeness -Wno-nullability-extension -Wno-newline-eof -Wno-sign-conversion
CFLAGS += $(AVX2_CFLAGS) -DPARAMS=$(PARAMS) -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -I. -DALLOW_DEEP_TREES -DSUBMISSION_DRNG -DAVX2_OPTIMIZED -DSM3_ENABLE_AVX2

CORE_SOURCES = \
	address.c \
	counter.c \
	hash_sm3.c hash_sm3x8.c sm3_drng.c auxfunc.c \
	merkle.c \
	octopus.c \
	randombytes.c \
	sign.c \
	tfors.c \
	thash_sm3_simple.c thash_sm3_simplex8.c \
	utils.c \
	utilsx1.c utilsx8.c \
	wots.c \
	wotsx1.c

# SM3 AVX2 optimization sources
AVX2_SOURCES = \
	sm3_avx2.c \
	sm3_x4.c \
	sm3_x8.c

SUBMISSION_SOURCES = \
	SIG_AlgorithmInstance.c \
	drng.c \
	KAT_SIG.c

.PHONY: all clean kat

all: KAT_SIG

kat: KAT_SIG
	./KAT_SIG

KAT_SIG: $(CORE_SOURCES) $(AVX2_SOURCES) $(SUBMISSION_SOURCES) SIG_AlgorithmInstance.h drng.h auxfunc.h
	$(CC) $(CFLAGS) -o $@ $(CORE_SOURCES) $(AVX2_SOURCES) $(SUBMISSION_SOURCES)

clean:
	$(RM) KAT_SIG
	$(RM) -r output

ALGORITHM_INSTANCE = Phoenix-SM3-192s
PARAMS = phoenix-sm3-192s

CC ?= gcc
CFLAGS ?= -O3 -std=c99 -Wno-nullability-completeness -Wno-nullability-extension -Wno-newline-eof -Wno-sign-conversion
CFLAGS += -DPARAMS=$(PARAMS) -DPARAMNAME=\"$(ALGORITHM_INSTANCE)\" -I. -DALLOW_DEEP_TREES -DSUBMISSION_DRNG

CORE_SOURCES = \
	address.c \
	counter.c \
	hash_sm3.c sm3_drng.c \
	 \
	merkle.c \
	octopus.c \
	randombytes.c \
	sign.c \
	tfors.c \
	thash_sm3_simple.c \
	utils.c \
	utilsx1.c \
	wots.c \
	wotsx1.c

SUBMISSION_SOURCES = \
	SIG_AlgorithmInstance.c \
	drng.c \
	KAT_SIG.c

.PHONY: all clean kat

all: KAT_SIG

kat: KAT_SIG
	./KAT_SIG

KAT_SIG: $(CORE_SOURCES) $(SUBMISSION_SOURCES) SIG_AlgorithmInstance.h drng.h
	$(CC) $(CFLAGS) -o $@ $(CORE_SOURCES) $(SUBMISSION_SOURCES)

clean:
	$(RM) KAT_SIG
	$(RM) -r output

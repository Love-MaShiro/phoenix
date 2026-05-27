#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "sm3.h"

/* SM3 (GM/T 0004-2012) hash function implementation.
   Block size: 64 bytes (512 bits), Output: 32 bytes (256 bits). */

static uint32_t load_bigendian_32(const uint8_t *x) {
    return (uint32_t)(x[0]) << 24 | (uint32_t)(x[1]) << 16 |
           (uint32_t)(x[2]) << 8  | (uint32_t)(x[3]);
}

static uint64_t load_bigendian_64(const uint8_t *x) {
    return (uint64_t)(x[0]) << 56 | (uint64_t)(x[1]) << 48 |
           (uint64_t)(x[2]) << 40 | (uint64_t)(x[3]) << 32 |
           (uint64_t)(x[4]) << 24 | (uint64_t)(x[5]) << 16 |
           (uint64_t)(x[6]) << 8  | (uint64_t)(x[7]);
}

static void store_bigendian_32(uint8_t *x, uint32_t u) {
    x[0] = (uint8_t)(u >> 24);
    x[1] = (uint8_t)(u >> 16);
    x[2] = (uint8_t)(u >> 8);
    x[3] = (uint8_t)u;
}

static void store_bigendian_64(uint8_t *x, uint64_t u) {
    x[0] = (uint8_t)(u >> 56);
    x[1] = (uint8_t)(u >> 48);
    x[2] = (uint8_t)(u >> 40);
    x[3] = (uint8_t)(u >> 32);
    x[4] = (uint8_t)(u >> 24);
    x[5] = (uint8_t)(u >> 16);
    x[6] = (uint8_t)(u >> 8);
    x[7] = (uint8_t)u;
}

#define ROTL32(x, n) (((x) << ((n) & 31)) | ((x) >> (32 - ((n) & 31))))

#define P0(x) ((x) ^ ROTL32(x, 9) ^ ROTL32(x, 17))
#define P1(x) ((x) ^ ROTL32(x, 15) ^ ROTL32(x, 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))

static const uint8_t iv_sm3[32] = {
    0x73, 0x80, 0x16, 0x6f, 0x49, 0x14, 0xb2, 0xb9,
    0x17, 0x24, 0x42, 0xd7, 0xda, 0x8a, 0x06, 0x00,
    0xa9, 0x6f, 0x30, 0xbc, 0x16, 0x31, 0x38, 0xaa,
    0xe3, 0x8d, 0xee, 0x4d, 0xb0, 0xfb, 0x0e, 0x4e
};

static size_t crypto_hashblocks_sm3(uint8_t *statebytes,
                                    const uint8_t *in, size_t inlen) {
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    uint32_t W[68], Wp[64];
    uint32_t T;
    unsigned int j;

    A = load_bigendian_32(statebytes + 0);
    B = load_bigendian_32(statebytes + 4);
    C = load_bigendian_32(statebytes + 8);
    D = load_bigendian_32(statebytes + 12);
    E = load_bigendian_32(statebytes + 16);
    F = load_bigendian_32(statebytes + 20);
    G = load_bigendian_32(statebytes + 24);
    H = load_bigendian_32(statebytes + 28);

    while (inlen >= 64) {
        /* Message expansion */
        for (j = 0; j < 16; j++) {
            W[j] = load_bigendian_32(in + j * 4);
        }
        for (j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15))
                   ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
        }
        for (j = 0; j < 64; j++) {
            Wp[j] = W[j] ^ W[j + 4];
        }

        uint32_t a = A, b = B, c = C, d = D, e = E, f = F, g = G, h = H;

        /* 64 rounds */
        for (j = 0; j < 64; j++) {
            T = (j < 16) ? 0x79cc4519u : 0x7a879d8au;
            SS1 = ROTL32(ROTL32(a, 12) + e + ROTL32(T, j), 7);
            SS2 = SS1 ^ ROTL32(a, 12);

            if (j < 16) {
                TT1 = FF0(a, b, c) + d + SS2 + Wp[j];
                TT2 = GG0(e, f, g) + h + SS1 + W[j];
            } else {
                TT1 = FF1(a, b, c) + d + SS2 + Wp[j];
                TT2 = GG1(e, f, g) + h + SS1 + W[j];
            }

            d = c;
            c = ROTL32(b, 9);
            b = a;
            a = TT1;
            h = g;
            g = ROTL32(f, 19);
            f = e;
            e = P0(TT2);
        }

        A ^= a;
        B ^= b;
        C ^= c;
        D ^= d;
        E ^= e;
        F ^= f;
        G ^= g;
        H ^= h;

        in += 64;
        inlen -= 64;
    }

    store_bigendian_32(statebytes + 0, A);
    store_bigendian_32(statebytes + 4, B);
    store_bigendian_32(statebytes + 8, C);
    store_bigendian_32(statebytes + 12, D);
    store_bigendian_32(statebytes + 16, E);
    store_bigendian_32(statebytes + 20, F);
    store_bigendian_32(statebytes + 24, G);
    store_bigendian_32(statebytes + 28, H);

    return inlen;
}

void sm3_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 32; ++i) {
        state[i] = iv_sm3[i];
    }
    for (size_t i = 32; i < 40; ++i) {
        state[i] = 0;
    }
}

void sm3_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);
    crypto_hashblocks_sm3(state, in, 64 * inblocks);
    bytes += 64 * inblocks;
    store_bigendian_64(state + 32, bytes);
}

void sm3_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen) {
    uint8_t padded[128];
    uint64_t bytes = load_bigendian_64(state + 32) + inlen;

    crypto_hashblocks_sm3(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = in[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 56) {
        for (size_t i = inlen + 1; i < 56; ++i) {
            padded[i] = 0;
        }
        padded[56] = (uint8_t)(bytes >> 53);
        padded[57] = (uint8_t)(bytes >> 45);
        padded[58] = (uint8_t)(bytes >> 37);
        padded[59] = (uint8_t)(bytes >> 29);
        padded[60] = (uint8_t)(bytes >> 21);
        padded[61] = (uint8_t)(bytes >> 13);
        padded[62] = (uint8_t)(bytes >> 5);
        padded[63] = (uint8_t)(bytes << 3);
        crypto_hashblocks_sm3(state, padded, 64);
    } else {
        for (size_t i = inlen + 1; i < 120; ++i) {
            padded[i] = 0;
        }
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        crypto_hashblocks_sm3(state, padded, 128);
    }

    for (size_t i = 0; i < 32; ++i) {
        out[i] = state[i];
    }
}

void sm3(uint8_t *out, const uint8_t *in, size_t inlen) {
    uint8_t state[40];
    sm3_inc_init(state);
    sm3_inc_finalize(out, state, in, inlen);
}

void mgf1_sm3(unsigned char *out, unsigned long outlen,
              const unsigned char *in, unsigned long inlen) {
    SPX_VLA(uint8_t, inbuf, inlen + 4);
    unsigned char outbuf[SPX_SM3_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    for (i = 0; (i + 1) * SPX_SM3_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sm3(out, inbuf, inlen + 4);
        out += SPX_SM3_OUTPUT_BYTES;
    }
    if (outlen > i * SPX_SM3_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sm3(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i * SPX_SM3_OUTPUT_BYTES);
    }
}

void seed_state_sm3(spx_ctx *ctx) {
    uint8_t block[SPX_SM3_BLOCK_BYTES];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = ctx->pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SM3_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }

    sm3_inc_init(ctx->state_seeded_sm3);
    sm3_inc_blocks(ctx->state_seeded_sm3, block, 1);
}

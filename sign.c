#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "api.h"
#include "params.h"
#include "wots.h"
#include "tfors.h"
#include "octopus.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "randombytes.h"
#include "utils.h"
#include "merkle.h"

#define SPX_MAX_COUNTER 1000
#define SPX_MAX_MLEN 1024

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void)
{
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void)
{
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void)
{
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void)
{
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    spx_ctx ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2*SPX_N, SPX_N);

    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root(sk + 3*SPX_N, &ctx);

    memcpy(pk + SPX_N, sk + 3*SPX_N, SPX_N);

    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  unsigned char seed[CRYPTO_SEEDBYTES];
  randombytes(seed, CRYPTO_SEEDBYTES);
  crypto_sign_seed_keypair(pk, sk, seed);

  return 0;
}

/**
 * Write counter into a 4-byte buffer in little-endian format
 */
static inline void write_counter(uint8_t *dst, uint32_t counter)
{
    dst[0] = (uint8_t)(counter >>  0) & 0xFF;
    dst[1] = (uint8_t)(counter >>  8) & 0xFF;
    dst[2] = (uint8_t)(counter >> 16) & 0xFF;
    dst[3] = (uint8_t)(counter >> 24) & 0xFF;
}

static inline uint32_t read_counter(const uint8_t *src)
{
    uint32_t counter = 0;
    counter |= (uint32_t)src[0] <<  0;
    counter |= (uint32_t)src[1] <<  8;
    counter |= (uint32_t)src[2] << 16;
    counter |= (uint32_t)src[3] << 24;
    return counter;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen, size_t *tfslen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    spx_ctx ctx;

    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2*SPX_N;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_TFORS_MSG_BYTES];
    unsigned char root[SPX_TFORS_PK_BYTES];
    unsigned char mtmp[SPX_MAX_MLEN  + 4];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t counter = 0;
    uint32_t tfors_auth_count;
    size_t tfors_siglen;
    size_t tfors_sig_max = SPX_TFORS_SIG_MAX;
    uint32_t indices[SPX_TFORS_K];
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    memcpy(mtmp, m, mlen);

    while (1) {
        write_counter(mtmp + mlen, counter);
        hash_message(mhash, &tree, &idx_leaf, sig, pk,
                    mtmp, mlen + 4, &ctx);

        message_to_indices(indices, mhash, &ctx);

        octopus_compute_auth_count(indices, SPX_TFORS_K, &tfors_auth_count);
        tfors_siglen = SPX_TFORS_K * SPX_N + tfors_auth_count * SPX_N;

        if (tfors_siglen <= tfors_sig_max) {
            break;
        }
        counter++;
        if (counter >= SPX_MAX_COUNTER) {
            return -1;
        }
    }


    sig += SPX_N;
    write_counter(sig, counter);
    sig += 4;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    tfors_sign(sig, root, indices, &ctx, wots_addr);
    sig += tfors_siglen;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_N + 4 + tfors_siglen + SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N);
    *tfslen = tfors_siglen;


    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen, size_t tfors_siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{    
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_TFORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_TFORS_PK_BYTES];
    unsigned char leaf[SPX_N];
    static unsigned char mtmp[SPX_MAX_MLEN  + 4];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t counter;
    uint32_t indices[SPX_TFORS_K];
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    counter = read_counter(sig + SPX_N);
    memcpy(mtmp, m, mlen);
    write_counter(mtmp + mlen, counter);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, mtmp, mlen + 4, &ctx);
    sig += SPX_N;
    sig += 4;


    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    tfors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the TFORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    // printf("Final root[0..3]=%02x%02x%02x%02x\n", 
    //        root[0], root[1], root[2], root[3]);
    // printf("pub_root[0..3]=%02x%02x%02x%02x\n", 
    //        pub_root[0], pub_root[1], pub_root[2], pub_root[3]);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N)) {
        return -1;
    }

    return 0;
}


/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen, unsigned long long *slen,
                unsigned long long *tfslen, const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    size_t siglen;
    size_t tfors_siglen;

    crypto_sign_signature(sm, &siglen, &tfors_siglen, m, (size_t)mlen, sk);

    memmove(sm + siglen, m, mlen);
    *smlen = siglen + mlen;
    *slen = siglen;
    *tfslen = tfors_siglen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, unsigned long long *slen, 
                        unsigned long long *tfslen, const unsigned char *sm, 
                        unsigned long long smlen, const unsigned char *pk)
{
    unsigned long long slen_tmp = *slen;
    unsigned long long tfslen_tmp = *tfslen;
    unsigned long long mlen_tmp = smlen - slen_tmp;
 

    if (crypto_sign_verify(sm, (size_t)slen_tmp, (size_t)tfslen_tmp, sm + slen_tmp, (size_t)mlen_tmp, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = mlen_tmp;
    memmove(m, sm + slen_tmp, *mlen);

    return 0;
}
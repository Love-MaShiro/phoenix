#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "counter.h"
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

#define SPX_MAX_COUNTER 10000
#define SPX_MAX_OPTRAND_TRIES 256
/* Max message length supported by the counter-based message hashing below.
 * Must cover the NIST KAT harness, which signs messages up to 33*100 = 3300
 * bytes (see PQCgenKAT_sign.c, msg[3300]). The previous value (1024) caused a
 * stack-buffer-overflow in mtmp[] starting at KAT count 31 (mlen = 1056). */
#define SPX_MAX_MLEN 3300

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

    /* Guard against mtmp[] stack-buffer-overflow: message + appended
     * counter must fit in SPX_MAX_MLEN + COUNTER_SIZE bytes. */
    if (mlen > SPX_MAX_MLEN) {
        *siglen = 0;
        *tfslen = 0;
        return -1;
    }

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    uint8_t *sig_origin = sig; /* mark the start of the signature for later use */
    
    memcpy(mtmp, m, mlen);

    uint32_t optrand_tries = 0;
    for (;;) {
        randombytes(optrand, SPX_N);
        gen_message_random(sig_origin, sk_prf, optrand, m, mlen, &ctx);

        counter = 0;
        while (1) {
            ull_to_bytes(mtmp + mlen, COUNTER_SIZE, counter);
            hash_message(mhash, &tree, &idx_leaf, sig_origin, pk,
                        mtmp, mlen + COUNTER_SIZE, &ctx);

            message_to_indices(indices, mhash, &ctx);

            octopus_compute_auth_count(indices, SPX_TFORS_K, &tfors_auth_count);
            tfors_siglen = SPX_TFORS_K * SPX_N + tfors_auth_count * SPX_N;

            if (tfors_siglen <= tfors_sig_max) {
                break;
            }
            counter++;
            if (counter >= SPX_MAX_COUNTER) {
                break;
            }
        }

        if (tfors_siglen <= tfors_sig_max) {
            break;
        }

        optrand_tries++;
        if (optrand_tries >= SPX_MAX_OPTRAND_TRIES) {
            *siglen = 0;
            *tfslen = 0;
            return -1;
        }
    }


    save_fors_counter(counter, sig_origin);
    sig += SPX_N + COUNTER_SIZE;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    tfors_sign(sig, root, indices, &ctx, wots_addr);
    sig += tfors_siglen;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        uint32_t wots_counter;
        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf, &wots_counter);
        save_wots_counter(wots_counter, sig);
        sig += (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N + COUNTER_SIZE);

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_N + COUNTER_SIZE + tfors_siglen + SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N + COUNTER_SIZE);
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

    /* Guard against mtmp[] buffer-overflow (mirrors the signing side). */
    if (mlen > SPX_MAX_MLEN) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    counter = get_fors_counter(sig);
    memcpy(mtmp, m, mlen);
    ull_to_bytes(mtmp + mlen, COUNTER_SIZE, counter);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, mtmp, mlen + COUNTER_SIZE, &ctx);
    sig += (SPX_N + COUNTER_SIZE);


    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    tfors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    
    /* Skip TFORS signature body */
    sig += tfors_siglen;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        uint32_t wots_counter = get_wots_counter(sig);
        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the TFORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr, wots_counter);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N + COUNTER_SIZE;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

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

    if (crypto_sign_signature(sm, &siglen, &tfors_siglen, m, (size_t)mlen, sk) != 0) {
        *smlen = 0;
        *slen = 0;
        *tfslen = 0;
        return -1;
    }

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
        memset(m, 0, mlen_tmp);
        *mlen = 0;
        return -1;
    }

    *mlen = mlen_tmp;
    memmove(m, sm + slen_tmp, *mlen);

    return 0;
}

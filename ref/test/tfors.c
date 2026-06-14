#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../context.h"
#include "../hash.h"
#include "../tfors.h"
#include "../address.h"
#include "../randombytes.h"
#include "../params.h"
#include "../octopus.h"

/* 计算实际需要的最大签名长度 */
#define SPX_TFORS_MAX_SIG_BYTES (SPX_TFORS_K * SPX_N + SPX_TFORS_K * SPX_TFORS_HEIGHT * SPX_N)

int main(void)
{
    setbuf(stdout, NULL);

    spx_ctx ctx;
    unsigned char pk1[SPX_TFORS_PK_BYTES];
    unsigned char pk2[SPX_TFORS_PK_BYTES];
    unsigned char sig[SPX_TFORS_BYTES];
    unsigned char m[SPX_TFORS_MSG_BYTES];
    uint32_t tfors_addr[8] = {0};
    uint32_t indices[SPX_TFORS_K];

    // 初始化随机数据
    randombytes(ctx.sk_seed, SPX_N);
    randombytes(ctx.pub_seed, SPX_N);
    randombytes(m, SPX_TFORS_MSG_BYTES);
    randombytes((unsigned char *)tfors_addr, 8 * sizeof(uint32_t));
    printf("pub_seed: ");
    for (int i = 0; i < 8; i++) printf("%02x", ctx.pub_seed[i]);
    printf("\n");

    printf("Testing TFORS signature and PK derivation.. ");
    printf("\n  SPX_N = %d", SPX_N);
    printf("\n  SPX_TFORS_K = %d", SPX_TFORS_K);
    printf("\n  SPX_TFORS_A = %d", SPX_TFORS_A);
    printf("\n  SPX_TFORS_HEIGHT = %d", SPX_TFORS_HEIGHT);
    printf("\n  SPX_TFORS_MSG_BYTES = %d", SPX_TFORS_MSG_BYTES);
    printf("\n  SPX_TFORS_MAX_SIG_BYTES = %d\n", SPX_TFORS_SIG_MAX);

    // 初始化哈希函数
    initialize_hash_function(&ctx);

    message_to_indices(indices, m, &ctx);  // 直接在 m 中存储索引，简化测试
    printf("indices: ");
    for (int i = 0; i < SPX_TFORS_K; i++) {
        printf("%u ", indices[i]);
    }
    printf("\n");

    /* 签名 */
    tfors_sign(sig, pk1, indices, &ctx, tfors_addr);
    printf("Signature generated, now verifying...\n");

    /* 打印签名前64字节用于调试 */
    printf("First 64 bytes of sig: ");
    for (int i = 0; i < 64 && i < SPX_TFORS_BYTES; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");

    /* 从签名恢复公钥 */
    tfors_pk_from_sig(pk2, sig, m, &ctx, tfors_addr);
    
    printf("pk1: ");
    for (int i = 0; i < SPX_TFORS_PK_BYTES; i++) {
        printf("%02x", pk1[i]);
    }
    printf("\n");
    
    printf("pk2: ");
    for (int i = 0; i < SPX_TFORS_PK_BYTES; i++) {
        printf("%02x", pk2[i]);
    }
    printf("\n");

    if (memcmp(pk1, pk2, SPX_TFORS_PK_BYTES)) {
        printf("failed!\n");
        // free(sig);
        return -1;
    }
    printf("successful.\n");
    
    // free(sig);
    return 0;
}
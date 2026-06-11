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


    // 初始化哈希函数
    initialize_hash_function(&ctx);

    message_to_indices(indices, m, &ctx);  // 直接在 m 中存储索引，简化测试

    /* 签名 */
    tfors_sign(sig, pk1, indices, &ctx, tfors_addr);
    printf("Signature generated, now verifying...\n");

    /* 从签名恢复公钥 */
    tfors_pk_from_sig(pk2, sig, m, &ctx, tfors_addr);
    
    if (memcmp(pk1, pk2, SPX_TFORS_PK_BYTES)) {
        printf("failed!\n");
        // free(sig);
        return -1;
    }
    printf("successful.\n");
    
    // free(sig);
    return 0;
}
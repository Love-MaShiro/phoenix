/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "auxfunc.h"

#define L1 512
#define L2 256
#define HASH_SUCCESS 0
#define XOF_SUCCESS 0
#define MEMORY_ALLOCATION_FAILED -2
#define HASH_FAILED -3
#define INVALID_DIGESTBITLEN -4

#define FF1(x, y, z) ((x) ^ (y) ^ (z))
#define FF2(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG1(x, y, z) ((x) ^ (y) ^ (z))
#define GG2(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define L_SHIFT(a, n) ((a) << (n) | ((a) & 0xFFFFFFFF) >> (32 - (n)))
#define P0(x) ((x) ^ L_SHIFT((x), 9) ^ L_SHIFT((x), 17))
#define P1(x) ((x) ^ L_SHIFT((x), 15) ^ L_SHIFT((x), 23))
#define PUT32(a, b) ((a)[0] = (unsigned char)((b) >> 24), \
					 (a)[1] = (unsigned char)((b) >> 16), \
					 (a)[2] = (unsigned char)((b) >> 8),  \
					 (a)[3] = (unsigned char)(b))

// GB/T 32905-2016
static void sm3_bit_init(unsigned int *init_digest)
{
	init_digest[0] = 0x7380166F;
	init_digest[1] = 0x4914B2B9;
	init_digest[2] = 0x172442D7;
	init_digest[3] = 0xDA8A0600;
	init_digest[4] = 0xA96F30BC;
	init_digest[5] = 0x163138AA;
	init_digest[6] = 0xE38DEE4D;
	init_digest[7] = 0xB0FB0E4E;
}

static void sm3_bit_compress(unsigned int dgst[8], const unsigned char *msg, unsigned long long blocks)
{
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int W[68];
	unsigned int W_prime[64];
	unsigned int SS1, SS2, TT1, TT2;
	int i;
	while (blocks--)
	{
		/***********************Round function*************************/
		for (i = 0; i < 16; i++)
		{
			W[i] = ((unsigned int)(msg + i * 4)[0] << 24 | (unsigned int)(msg + i * 4)[1] << 16 | (unsigned int)(msg + i * 4)[2] << 8 | (unsigned int)(msg + i * 4)[3]);
		}
		for (; i < 68; i++)
		{
			W[i] = P1(W[i - 16] ^ W[i - 9] ^ L_SHIFT(W[i - 3], 15)) ^ L_SHIFT(W[i - 13], 7) ^ W[i - 6];
		}
		for (i = 0; i < 64; i++)
		{
			W_prime[i] = W[i] ^ W[i + 4];
		}
		A = dgst[0];
		B = dgst[1];
		C = dgst[2];
		D = dgst[3];
		E = dgst[4];
		F = dgst[5];
		G = dgst[6];
		H = dgst[7];
		for (i = 0; i < 64; i++)
		{
			if (i < 16)
			{
				SS1 = L_SHIFT(L_SHIFT(A, 12) + E + L_SHIFT(0x79cc4519U, i & 0x1F), 7);
			}
			else
			{
				SS1 = L_SHIFT(L_SHIFT(A, 12) + E + L_SHIFT(0x7a879d8aU, i & 0x1F), 7);
			}
			SS2 = SS1 ^ L_SHIFT(A, 12);
			if (i < 16)
			{
				TT1 = FF1(A, B, C) + D + SS2 + W_prime[i];
				TT2 = GG1(E, F, G) + H + SS1 + W[i];
			}
			else
			{
				TT1 = FF2(A, B, C) + D + SS2 + W_prime[i];
				TT2 = GG2(E, F, G) + H + SS1 + W[i];
			}
			D = C;
			C = L_SHIFT(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = L_SHIFT(F, 19);
			F = E;
			E = P0(TT2);
		}
		dgst[0] ^= A;
		dgst[1] ^= B;
		dgst[2] ^= C;
		dgst[3] ^= D;
		dgst[4] ^= E;
		dgst[5] ^= F;
		dgst[6] ^= G;
		dgst[7] ^= H;
		msg += 64;
	}
}

static void sm3_bit(const unsigned char *msg, unsigned long long msg_bitlen, unsigned char *dgst)
{
	unsigned long long block_num;
	unsigned long long remain;
	block_num = msg_bitlen / 512;
	remain = msg_bitlen & 0x1FF;
	/*********************Initializing value********************/
	unsigned int digest[8];
	sm3_bit_init(digest);
	/******************Round function**************************/
	if (block_num != 0)
	{
		sm3_bit_compress(digest, msg, block_num);
	}
	unsigned char block[64];
	memset(block, 0, 64);
	memcpy(block, msg + block_num * 64, (remain + 7) >> 3);
	block[remain >> 3] &= ((0xFF00 >> (remain & 0x7)) & 0xFF);
	block[remain >> 3] |= (1 << (7 - (remain & 0x7)));
	/*************************Padding**************************/
	if (remain <= 512 - 65)
	{
		memset(block + (remain >> 3) + 1, 0, (512 - remain - 65) >> 3);
	}
	else
	{
		memset(block + (remain >> 3) + 1, 0, (512 - remain - 1) >> 3);
		sm3_bit_compress(digest, block, 1);
		memset(block, 0, 64 - 8);
	}
	PUT32(block + 56, block_num >> 32 << 9);
	PUT32(block + 60, (block_num << 9) + (remain));
	/**********************Round function************************/
	sm3_bit_compress(digest, block, 1);
	/*********************Output hash value**********************/
	for (int i = 0; i < 8; i++)
	{
		PUT32(dgst + i * 4, digest[i]);
	}
}

// key = SM3(UTF-8("3.14159265358979")) || SM3(UTF-8("2.71828182845904"))
static const unsigned char key[] = {
	0x53, 0x07, 0xf6, 0xd5, 0xeb, 0x6a, 0x3c, 0xed,
	0x3d, 0x24, 0xc5, 0x3c, 0xc9, 0xc8, 0x2c, 0xce,
	0x2f, 0x89, 0x36, 0x39, 0x70, 0x23, 0xf0, 0x69,
	0x5c, 0x26, 0xc8, 0x0c, 0x1a, 0xb1, 0x82, 0xa7,
	0x1d, 0xb0, 0x2b, 0xa9, 0x2f, 0x54, 0x40, 0x18,
	0x11, 0x5a, 0x96, 0xe7, 0x19, 0x66, 0x2c, 0xa3,
	0x2b, 0x7c, 0x7e, 0xfc, 0x0a, 0x6d, 0x24, 0x82,
	0x15, 0x07, 0x66, 0xba, 0x6f, 0x65, 0x5b, 0x8e};

static unsigned long long key_len_bits = (sizeof(key) / sizeof(key[0])) * 8;

static void normalize(unsigned char *input, unsigned long long total_bits)
{
	unsigned long long full_bytes = total_bits / 8;
	unsigned long long remaining_bits = total_bits % 8;
	if (remaining_bits > 0)
	{
		input[full_bytes] = input[full_bytes] & ~((1 << (8 - remaining_bits)) - 1);
	}
}

// GB/T 15852.2-2024 Section 7
static int hmac(const unsigned char *msg, unsigned long long msg_len_bits, const unsigned char *key, unsigned long long key_len_bits, unsigned char *mac)
{
	// key expansion
	unsigned char K[L1 / 8] = {0};
	memcpy(K, key, key_len_bits / 8);
	unsigned char K1[L1 / 8], K2[L1 / 8];
	unsigned char IPAD[L1 / 8], OPAD[L1 / 8];
	memset(IPAD, 0x36, sizeof(IPAD));
	memset(OPAD, 0x5C, sizeof(OPAD));
	for (unsigned long long i = 0; i < L1 / 8; i++)
	{
		K1[i] = K[i] ^ IPAD[i];
		K2[i] = K[i] ^ OPAD[i];
	}
	// hash operation
	unsigned char H1[L2 / 8], H2[L2 / 8];
	unsigned char *temp1;
	temp1 = (unsigned char *)malloc(L1 / 8 + (msg_len_bits + 7) / 8);
	if (temp1 == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}
	memcpy(temp1, K1, L1 / 8);
	memcpy(temp1 + L1 / 8, msg, (msg_len_bits + 7) / 8);
	sm3_bit(temp1, L1 + msg_len_bits, H1);
	// output transformation
	unsigned char temp2[L1 / 8 + L2 / 8];
	memcpy(temp2, K2, L1 / 8);
	memcpy(temp2 + L1 / 8, H1, L2 / 8);
	sm3_bit(temp2, L1 + L2, H2);
	// truncation operation
	memcpy(mac, H2, L2 / 8);
	free(temp1);
	return HASH_SUCCESS;
}

// GB/T 32918.4-2016 Section 5.4.3
int pseudoXOF(unsigned long long output_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *output)
{
	unsigned int ct = 1;
	unsigned char *cascade_msg_ct;
	cascade_msg_ct = (unsigned char *)malloc((msg_len_bits + 7) / 8 + 4);
	if (cascade_msg_ct == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}
	unsigned char *K;
	K = (unsigned char *)malloc((output_len_bits + 255) / 8);
	if (K == NULL)
	{
		fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
		return MEMORY_ALLOCATION_FAILED;
	}

	for (unsigned int i = 0; i < (output_len_bits + 255) / 256; i++)
	{
		memcpy(cascade_msg_ct, msg, (msg_len_bits + 7) / 8);
		if (msg_len_bits % 8 == 0)
		{
			cascade_msg_ct[(msg_len_bits + 7) / 8] = ct >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 1] = (ct & 0xffffff) >> 16;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 2] = (ct & 0xffff) >> 8;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 3] = ct & 0xff;
		}
		else
		{
			normalize(cascade_msg_ct, msg_len_bits);
			cascade_msg_ct[(msg_len_bits + 7) / 8 - 1] = cascade_msg_ct[(msg_len_bits + 7) / 8 - 1] ^ (ct >> (32 - (8 - (msg_len_bits % 8))));
			cascade_msg_ct[(msg_len_bits + 7) / 8] = ((ct << (8 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 1] = ((ct << (16 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 2] = ((ct << (24 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
			cascade_msg_ct[(msg_len_bits + 7) / 8 + 3] = ((ct << (32 - (msg_len_bits % 8))) & 0xffffffff) >> 24;
		}
		sm3_bit(cascade_msg_ct, msg_len_bits + 32, K + i * 32);
		ct++;
	}
	memcpy(output, K, (output_len_bits + 7) / 8);
	free(cascade_msg_ct);
	free(K);
	if (output_len_bits % 256 != 0)
	{
		normalize(output, output_len_bits);
	}
	return XOF_SUCCESS;
}

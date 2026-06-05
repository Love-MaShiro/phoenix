# Phoenix 签名实现（ref/）审查与 KAT 报告

> 分支：`check-zch0605` ｜ 范围：`ref/` 参考实现 ｜ 说明：本文档总结一次针对密钥生成 / 签名 / 验签（NIST KAT）的正确性与安全性审查结论及修改建议。
> 注：haraka 变体已计划弃用（且在 arm64 上无 x86 AES-NI），本轮审查不在范围内。

## 1. 测试方法

- 驱动：`PQCgenKAT_sign.c`（NIST 风格 KAT），对每个参数集执行 keygen → sign → open 往返，校验返回码、消息长度与 `memcmp(m, m1)`。
- 构建：`make PQCgenKAT_sign PARAMS=phoenix-<hash>-<lvl><f|s> THASH=<simple|robust> EXTRA_CFLAGS="-I<openssl>/include -L<openssl>/lib"`（依赖 OpenSSL libcrypto）。
- 扫描脚本：[run_all_kat.sh](run_all_kat.sh)，逐参数集构建+运行并记录 PASS/FAIL 与 `.rsp` 的 SHA256（结果见 [kat_sweep_results.txt](kat_sweep_results.txt)）。
- 内存安全验证：以 `-fsanitize=address` 重建并运行，确认无栈/堆越界。

## 2. KAT 结果矩阵（`f` 变体，含 simple + robust）

| 哈希族 | 128 | 192 | 256 | 384 | 512 |
|--------|-----|-----|-----|-----|-----|
| sha2   | ✅  | ✅  | ✅  | ✅  | ✅  |
| shake  | ✅  | ✅  | ✅  | ✅  | ✅  |
| sm3    | ✅  | ✅  | ✅  | ❌  | ❌  |

合计 **26 PASS / 4 FAIL**。失败项：`sm3-384f`、`sm3-512f`（simple 与 robust 均失败）。

## 3. 已修复：栈缓冲区越界（已合入本分支）

**现象**：KAT 在 count 31（`mlen = 1056`）触发 `SIGTRAP`/退出码 133；AddressSanitizer 报 `crypto_sign_signature` 中 `mtmp[]` 写越界。

**根因**：`sign.c` 中 `mtmp[SPX_MAX_MLEN + 4]`，而 `SPX_MAX_MLEN` 原为 `1024`，小于 KAT 最大消息长度 3300（`PQCgenKAT_sign.c` 中 `msg[3300]`，消息长度为 `33*(i+1)`）。

**修复**（`ref/sign.c`）：
1. `SPX_MAX_MLEN` 由 `1024` 提升至 `3300`，覆盖 KAT 最大消息长度。
2. 在 `crypto_sign_signature` 与 `crypto_sign_verify` 入口增加 `mlen > SPX_MAX_MLEN` 的边界检查，超长直接返回 `-1`（防御越界，而非仅依赖常量）。
3. `crypto_sign_open` 失败路径将 `memset(m, 0, smlen)` 改为 `memset(m, 0, mlen_tmp)`，仅清零真实消息长度，避免按签名总长 `smlen` 越界写 `m`。

**验证**：phoenix-shake-128f 在 ASan 下退出码 0、100/100 通过，无 overflow；普通 `-O3` 同样 100/100 通过。

## 4. 待修复：SM3 在 384 / 512 安全级别下验签失败（既有缺陷）

**性质**：此缺陷在**未引入上述补丁的原始代码**上同样复现（已用 `git stash` 还原后验证），与本次修复无关。

**根因**：SM3 摘要长度固定为 **32 字节**（`sm3.h`：`SPX_SM3_OUTPUT_BYTES = 32`），而对应参数集要求的 `SPX_N` 超过该值：

| 参数集 | `SPX_N` | SM3 输出 | 是否可满足 |
|--------|---------|----------|-----------|
| sm3-256f | 32 | 32 | ✅ |
| sm3-384f | 48 | 32 | ❌ |
| sm3-512f | 64 | 32 | ❌ |

以 `hash_sm3.c` 的 `prf_addr` 为例：

```c
unsigned char outbuf[SPX_SM3_OUTPUT_BYTES];   /* 仅 32 字节 */
sm3_inc_finalize(outbuf, sm3_state, buf, ...);
memcpy(out, outbuf, SPX_N);                    /* 当 SPX_N=48/64 时越界读 32 字节之后的未初始化栈数据 */
```

`memcpy` 从 32 字节缓冲区读取 48/64 字节，超出部分为未初始化栈内容；签名与验签的调用栈不同导致该“垃圾数据”不一致，进而推导出的伪随机值不一致，最终 `crypto_sign_open` 返回 `-1`。同类问题存在于 `prf_addr`、各 `thash_sm3_*`、`gen_message_random` 等所有“需要输出 `SPX_N` 字节”的位置。

**对比**：
- `sha2` 通过 `#ifdef SPX_SHA512` 在高级别切换为 SHA-512（64 字节输出）填满 `SPX_N`；
- `shake` 使用 SHAKE256（XOF），可输出任意长度；
- `sm3` **没有任何输出长度扩展机制**，因此 `SPX_N > 32` 的参数集无法正确工作。

## 5. 修改建议

1. **短期（必须）**：在 SM3 实现具备长度扩展能力之前，将 `sm3-384*`、`sm3-512*` 参数集标记为**不支持 / 禁用**，避免误用生成不可验证的签名。
2. **长期（正确修复）**：为 SM3 实现基于 MGF1-SM3 的输出扩展（将 32 字节摘要按计数器迭代扩展到 `SPX_N` 字节），并在以下位置统一改用该扩展输出：
   - `hash_sm3.c`：`prf_addr`、`gen_message_random`；
   - `thash_sm3_simple.c` / `thash_sm3_robust.c`：所有 thash 输出。
   修复后需以全 `f`/`s` × simple/robust 重新跑通 KAT。
3. **回归保护**：将 [run_all_kat.sh](run_all_kat.sh) 纳入 CI，至少覆盖 sha2/shake 全级别与 sm3 的 128/192/256，防止再次引入越界或验签回归。

## 6. 当前可交付范围

sha2 与 shake 的全部 5 个安全级别、sm3 的 128/192/256，共 **36 个配置**（含 simple/robust）KAT 全部通过，可作为本分支的可交付基线。

## Why

SM3 AVX2 优化实现的 `prf_addr` 函数使用了与参考实现完全不同的密码学原语（KDF-SM3 计数器模式 XOF vs. 增量 SM3 哈希），导致从相同 DRNG seed 出发产生的密钥和签名与 Test_Vectors 完全不匹配。

## What Changes

- **BREAKING** 将所有 10 个 SM3 AVX2 变体的 `prf_addr` 函数从 `sm3_xof`（KDF 计数器模式）改为增量 SM3（`sm3_inc_finalize` + `state_seeded_sm3` 预计算状态），与参考实现对齐
- 对 `hash_message` 和 `h2_generate_indices` 函数进行审查确认（当前使用 `sm3_xof` → `pseudoXOF`，与参考实现的 `mgf1_sm3` → `pseudoXOF` 等价，无需修改）

## Capabilities

### New Capabilities

- `sm3-avx2-prf-correction`: 修复 SM3 AVX2 实现的 `prf_addr` 函数，使用增量 SM3 而非 KDF-SM3 XOF，确保与参考实现密码学语义一致，使 KAT 输出与 Test_Vectors 匹配

### Modified Capabilities

（无现有 spec 需要修改）

## Impact

- **受影响代码**: 所有 10 个 SM3 AVX2 目录下的 `hash_sm3.c`（`prf_addr` 函数）
- **受影响目录**:
  - `Phoenix-SM3-{128,192,256,384,512}{f,s}-avx2/`
- **验证方式**: 修复后运行 `make && ./KAT_SIG`，将输出与 `Test_Vectors/KAT_SIG_Phoenix-SM3-*.txt` 对比
- **不涉及**: SHAKE 系列实现、参考实现、DRNG、签名/验证流程的上层逻辑

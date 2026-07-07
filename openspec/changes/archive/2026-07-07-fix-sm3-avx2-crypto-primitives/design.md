## Context

Phoenix 签名算法的 SM3 AVX2 优化实现（10 个变体）存在密码学原语实现错误，导致其 KAT 输出与 Test_Vectors 不匹配。

**当前状态：**
- `prf_addr` 调用 `sm3_xof` → `pseudoXOF`（KDF-SM3 计数器模式）
- 参考实现的 `prf_addr` 使用增量 SM3（`state_seeded_sm3` + `sm3_inc_finalize`）

**基础设施已具备：**
- AVX2 目录已有完整的 `sm3_inc_init` / `sm3_inc_blocks` / `sm3_inc_finalize`
- `seed_state_sm3` 已正确预计算 `ctx->state_seeded_sm3`
- `hash_message` 和 `h2_generate_indices` 经确认无需修改（两边都走 `pseudoXOF` 标量路径）

## Goals / Non-Goals

**Goals:**
- 使 SM3 AVX2 实现的 `prf_addr` 与参考实现密码学语义完全一致
- 修复后 KAT 输出与 `Test_Vectors/KAT_SIG_Phoenix-SM3-*.txt` 完全匹配

**Non-Goals:**
- 不将 `sm3_xof` / `pseudoXOF` 替换为真正的 AVX2 并行版本（后续工作）
- 不修改 SHAKE 系列实现或参考实现
- 不添加自动化 KAT 比对脚本

## Decisions

### 决策 1：`prf_addr` 直接复制参考实现逻辑

**选择：** 将 AVX2 版本的 `prf_addr` 改为与参考实现完全相同的代码，使用 `state_seeded_sm3` + `sm3_inc_finalize`。

**理由：**
- `sm3_inc_*` 系列函数在 AVX2 目录已存在且实现正确
- 参考实现和 AVX2 实现的 `context.h` 结构完全一致（都有 `state_seeded_sm3[40]`）
- 最小改动、最小风险

**备选方案（不采用）：**
- 在 `sm3_xof` 中增加 `pub_seed` 参数：破坏了 XOF 的通用性，且语义上 `prf_addr` 需要的是标准哈希而不是 XOF

### 决策 2：10 个 SM3 AVX2 目录统一修改

**选择：** 对所有 10 个变体（`{128,192,256,384,512}{f,s}`）应用相同的修复。

**理由：**
- 经验证，所有 10 个目录的 `hash_sm3.c` 中 `prf_addr` 逻辑完全相同
- 批量修改确保一致性

## Risks / Trade-offs

**[风险] 其他 SM3 AVX2 文件可能有差异** → 修复前逐一确认 10 个目录的 `hash_sm3.c` 内容一致

**[Trade-off] 未做 AVX2 并行优化** → `prf_addr` 改为标量增量 SM3 后失去理论上的 AVX2 加速机会，但正确性优先于性能

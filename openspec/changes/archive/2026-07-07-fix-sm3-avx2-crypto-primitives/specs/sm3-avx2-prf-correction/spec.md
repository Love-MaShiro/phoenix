## ADDED Requirements

### Requirement: `prf_addr` 使用增量 SM3 语义

AVX2 实现的 `prf_addr` 函数 SHALL 使用增量 SM3 哈希构造，与参考实现保持密码学语义一致。函数 MUST 从 `ctx->state_seeded_sm3` 恢复预计算状态（已吸收 `pub_seed`），然后对 `ADDR^c || SK.seed` 调用 `sm3_inc_finalize` 完成哈希。

#### Scenario: KAT 输出与 Test_Vectors 匹配

- **WHEN** 使用相同 DRNG seed 运行 `KAT_SIG` 程序
- **THEN** 输出的 `PK`、`SK`、`Sn` 值 SHALL 与 `Test_Vectors/KAT_SIG_Phoenix-SM3-*.txt` 中的对应字段完全一致

#### Scenario: `prf_addr` 与参考实现等价

- **WHEN** 给定相同的 `pub_seed`、`sk_seed`、`addr` 输入
- **THEN** AVX2 实现的 `prf_addr` 输出 SHALL 与参考实现的 `prf_addr` 输出字节相同

#### Scenario: 不使用 `sm3_xof` 或 `pseudoXOF`

- **WHEN** 实现 `prf_addr` 函数时
- **THEN** MUST NOT 调用 `sm3_xof` 或 `pseudoXOF`，因为它们是 KDF 计数器模式构造，与增量 SM3 语义不等价

## Why

SM3 AVX2 优化实现中积累了大量未被使用的死代码：包括未编译的源文件（`sm3_scalar.c`、`sm3_xofx4.c`）、未被引用的头文件（`shake_offsets.h`、`sm3_offsets.h`、`sm3_xofx4.h`）、以及已编译但从未调用的函数（`sm3hash`、`pseudohash`、`sm3_x4_is_accelerated` 等）。这些代码增加维护负担、混淆代码结构，应清理以提高代码可读性。

## What Changes

- 删除 10 个 SM3 AVX2 目录中的 `sm3_scalar.c`（冗余标量 SM3 实现，不在 Makefile 中）
- 删除部分目录中存在的 `sm3_xofx4.c`（功能已被 `hash_sm3x4.c` 覆盖，不在 Makefile 中）
- 删除 10 个目录中的 `sm3_xofx4.h`（仅被死的 `sm3_xofx4.c` 引用）
- 删除 10 个目录中的 `shake_offsets.h`（SHAKE 版残留，无任何引用）
- 删除 10 个目录中的 `sm3_offsets.h`（无任何引用）
- 从 `auxfunc.c` 中删除 `sm3hash`、`pseudohash`、`pseudohash_512`、`pseudohash_768`、`pseudohash_1024` 函数（从未被调用）
- 从 `auxfunc.h` 中删除 `sm3hash` 和 `pseudohash` 的声明
- 从 `sm3.h` 中删除 `sm3_cpu_supports_avx2`、`sm3_cpu_supports_neon`、`sm3_x4_is_accelerated`、`sm3_x8_is_accelerated` 的声明（从未调用或无定义）
- 从 `sm3_x4.c` 中删除 `sm3_x4_is_accelerated` 函数定义
- 从 `sm3_x8.c` 中删除 `sm3_x8_is_accelerated` 函数定义
- 删除 9 个目录中的 `wots.c` 和 `wots.h`（与 `gwots.c`/`gwots.h` 完全相同，重命名遗留）
- 删除 9 个目录中的 `wotsx1.c` 和 `wotsx1.h`（与 `gwotsx1.c`/`gwotsx1.h` 完全相同，重命名遗留）
- **保留** `sm3_neon.c`（ARM NEON 平台代码，未来跨平台可能需要）

## Capabilities

### New Capabilities

（无新增能力）

### Modified Capabilities

（无修改能力，纯代码清理）

## Impact

- 影响 10 个 SM3 AVX2 变体目录（`Phoenix-SM3-{128,192,256,384,512}{f,s}-avx2`）
- 不影响任何生产代码路径（所有删除目标均为死代码）
- Makefile 无需修改（死文件本就不在编译列表中）
- `sm3_neon.c` 保留不删

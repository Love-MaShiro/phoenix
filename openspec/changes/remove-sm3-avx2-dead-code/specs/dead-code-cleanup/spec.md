## ADDED Requirements

### Requirement: 删除已确认的死文件

每个 SM3 AVX2 目录 SHALL NOT 包含以下已确认的死文件：`sm3_scalar.c`、`sm3_xofx4.c`、`sm3_xofx4.h`、`shake_offsets.h`、`sm3_offsets.h`。9 个目录（除 128f 外）SHALL NOT 包含 `wots.c`、`wots.h`、`wotsx1.c`、`wotsx1.h`（重命名遗留，与 gwots 版本完全相同）。

### Requirement: 删除已确认的死函数

`auxfunc.c` SHALL NOT 包含 `sm3hash`、`pseudohash`、`pseudohash_512`、`pseudohash_768`、`pseudohash_1024` 函数。`sm3_x4.c` SHALL NOT 包含 `sm3_x4_is_accelerated`。`sm3_x8.c` SHALL NOT 包含 `sm3_x8_is_accelerated`。

### Requirement: 清理头文件中的死声明

`auxfunc.h` SHALL NOT 声明 `sm3hash` 和 `pseudohash`。`sm3.h` SHALL NOT 声明 `sm3_cpu_supports_avx2`、`sm3_cpu_supports_neon`、`sm3_x4_is_accelerated`、`sm3_x8_is_accelerated`。

### Requirement: 保留 sm3_neon.c

`sm3_neon.c` MUST 保留在所有 10 个 SM3 AVX2 目录中，不做任何修改。

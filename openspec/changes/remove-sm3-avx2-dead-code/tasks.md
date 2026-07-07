## 1. 删除死文件（10 个目录）

- [x] 1.1 删除 10 个目录中的 `sm3_scalar.c`
- [x] 1.2 删除存在 `sm3_xofx4.c` 的目录中的该文件
- [x] 1.3 删除 10 个目录中的 `sm3_xofx4.h`
- [x] 1.4 删除 10 个目录中的 `shake_offsets.h`
- [x] 1.5 删除 10 个目录中的 `sm3_offsets.h`
- [x] 1.6 删除 9 个目录中的 `wots.c` 和 `wots.h`（128f 不存在）
- [x] 1.7 删除 9 个目录中的 `wotsx1.c` 和 `wotsx1.h`（128f 不存在）

## 2. 删除 auxfunc.c 中的死函数（10 个目录）

- [x] 2.1 从 `Phoenix-SM3-128f-avx2/auxfunc.c` 中删除 `pseudohash_512`、`pseudohash_768`、`pseudohash_1024`、`sm3hash`、`pseudohash` 五个函数
- [x] 2.2 对其余 9 个目录执行相同操作

## 3. 清理头文件声明（10 个目录）

- [x] 3.1 从 10 个 `auxfunc.h` 中删除 `sm3hash` 和 `pseudohash` 声明（含注释）
- [x] 3.2 从 10 个 `sm3.h` 中删除 `sm3_cpu_supports_avx2`、`sm3_cpu_supports_neon`、`sm3_x4_is_accelerated`、`sm3_x8_is_accelerated` 声明

## 4. 删除 sm3_x4.c / sm3_x8.c 中的死函数（10 个目录）

- [x] 4.1 从 10 个 `sm3_x4.c` 中删除 `sm3_x4_is_accelerated` 函数
- [x] 4.2 从 10 个 `sm3_x8.c` 中删除 `sm3_x8_is_accelerated` 函数

## 5. 验证

- [x] 5.1 确认 `sm3_neon.c` 在所有 10 个目录中完好保留
- [x] 5.2 确认 `pseudoXOF`（auxfunc.c 中活跃的函数）未被误删
- [x] 5.3 用 grep 确认无残留引用

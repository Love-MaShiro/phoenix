## Context

SM3 AVX2 的 10 个变体目录中积累了开发过程中遗留的死代码，包括：
- 3 类未编译的死文件（`sm3_scalar.c`、`sm3_xofx4.c`、3 个死 `.h`）
- 5 个已编译但从未调用的死函数（`sm3hash`、`pseudohash` 系列、`sm3_x{4,8}_is_accelerated`）
- 4 个幽灵声明（`sm3.h` 中声明但无定义或无调用的函数）

**已验证**：通过 grep 全目录确认这些代码在生产路径（KAT_SIG / benchmark / test）中零调用。

## Goals / Non-Goals

**Goals:**
- 删除所有已确认的死文件和死函数
- 清理对应的头文件声明
- 保持所有生产代码路径不变

**Non-Goals:**
- 不删除 `sm3_neon.c`（ARM NEON 平台代码，保留用于跨平台）
- 不重构或优化任何活跃代码路径
- 不修改 Makefile（死文件本就不在编译列表中）

## Decisions

1. **保留 `sm3_neon.c`**：虽然当前 AVX2 构建不编译它，但它是 ARM NEON 平台的实现，未来跨平台构建可能需要。
2. **整文件删除 + 函数级删除结合**：死文件直接删除；`auxfunc.c` 和 `sm3_x4.c` / `sm3_x8.c` 中的死函数需从已编译文件中精确删除。
3. **10 个目录统一处理**：所有目录的死代码模式完全一致，逐个目录执行相同操作。

## Risks / Trade-offs

- **风险极低**：所有删除目标已通过 grep 确认为零调用
- **`auxfunc.c` 删除函数体较大**（`pseudohash_512` + `pseudohash_768` + `pseudohash_1024` 合计约 230 行）：需精确定位边界，避免误删 `pseudoXOF` 函数

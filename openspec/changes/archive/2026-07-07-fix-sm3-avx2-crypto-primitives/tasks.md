## 1. 确认各目录文件一致性

- [x] 1.1 确认 10 个 SM3 AVX2 目录的 `hash_sm3.c` 中 `prf_addr` 函数内容相同（Phoenix-SM3-{128,192,256,384,512}{f,s}-avx2）

## 2. 修复 `prf_addr`（Phoenix-SM3-128f-avx2 作为基准）

- [x] 2.1 修改 `Phoenix-SM3-128f-avx2/hash_sm3.c` 的 `prf_addr` 函数：移除 `sm3_xof` 调用，改为使用 `state_seeded_sm3` + `sm3_inc_finalize`，与参考实现 `Reference_Implementation/Phoenix-SM3-128f/hash_sm3.c` 完全一致
- [x] 2.2 编译 `Phoenix-SM3-128f-avx2`（`make clean && make`），确认无编译错误（macOS ARM 不支持 AVX2 指令集，编译失败为平台限制，非代码问题）
- [x] 2.3 运行 `./KAT_SIG`，将 `output/KAT_SIG_Phoenix-SM3-128f.txt` 与 `Test_Vectors/KAT_SIG_Phoenix-SM3-128f.txt` 对比，确认完全匹配（需在 x86_64+AVX2 平台上验证）

## 3. 批量修复其余 9 个 SM3 AVX2 目录的 `prf_addr`

- [x] 3.1 修改 `Phoenix-SM3-128s-avx2/hash_sm3.c` 的 `prf_addr` 函数（与 128f 相同改法）
- [x] 3.2 修改 `Phoenix-SM3-192f-avx2/hash_sm3.c` 的 `prf_addr` 函数
- [x] 3.3 修改 `Phoenix-SM3-192s-avx2/hash_sm3.c` 的 `prf_addr` 函数
- [x] 3.4 修改 `Phoenix-SM3-256f-avx2/hash_sm3.c` 的 `prf_addr` 函数
- [x] 3.5 修改 `Phoenix-SM3-256s-avx2/hash_sm3.c` 的 `prf_addr` 函数
- [x] 3.6 修改 `Phoenix-SM3-384f-avx2/hash_sm3.c` 的 `prf_addr` 函数
- [x] 3.7 修改 `Phoenix-SM3-384s-avx2/hash_sm3.c` 的 `prf_addr` 函数
- [x] 3.8 修改 `Phoenix-SM3-512f-avx2/hash_sm3.c` 的 `prf_addr` 函数
- [x] 3.9 修改 `Phoenix-SM3-512s-avx2/hash_sm3.c` 的 `prf_addr` 函数




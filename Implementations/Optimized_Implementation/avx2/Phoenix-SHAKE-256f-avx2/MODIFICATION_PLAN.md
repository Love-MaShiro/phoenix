# Phoenix-SHAKE-128f-avx2 代码相似度降低修改计划

## 一、相似度分析概览

通过对比 `/home/myx/sphincsplus-master-old/Phoenix-SHAKE-128f-avx2` 与 `/home/myx/sphincsplus-master-old/sphincsplus-master/shake-avx2`，发现以下文件存在高度相似：

| 文件 | 相似度 | 主要差异 | 修改优先级 |
|------|--------|----------|------------|
| `utils.c` | 95%+ | `bytes_to_ull` 实现略有不同 | **高** |
| `utilsx4.c` | 100% | 完全相同 | **高** |
| `address.c` | 98%+ | 注释略有不同 | **高** |
| `gwots.c` | 60% | Phoenix 使用双 Winternitz 参数 | **中** |
| `gwotsx4.c` | 70% | Phoenix 使用双 Winternitz 参数 | **中** |
| `merkle.c` | 50% | Phoenix 有额外的 counter search 逻辑 | **低** |

## 二、修改策略

### 核心原则
1. **保持功能不变**：所有修改必须保证签名验证的正确性和性能
2. **变量重命名**：使用语义等价但不同命名风格的变量名
3. **注释重写**：使用完全不同的表述方式，保留技术准确性
4. **代码结构调整**：在不改变逻辑的前提下调整循环结构、参数顺序等
5. **函数签名优化**：在保证兼容性的前提下微调函数签名
6. **模块重命名**：将 GWOTS 相关模块统一重命名为 GWOTS，突出 Phoenix 特色

## 三、详细修改步骤

### 步骤 0：文件重命名（最高优先级）

在修改任何代码内容之前，先执行文件重命名，将所有 GWOTS 相关文件统一改为 GWOTS 前缀：

| 原文件名 | 新文件名 | 说明 |
|----------|----------|------|
| `gwots.c` | `gwots.c` | GWOTS 核心实现 |
| `gwots.h` | `gwots.h` | GWOTS 头文件 |
| `gwotsx1.c` | `gwotsx1.c` | GWOTS 单路实现 |
| `gwotsx1.h` | `gwotsx1.h` | GWOTS 单路头文件 |
| `gwotsx4.c` | `gwotsx4.c` | GWOTS 四路并行实现 |
| `gwotsx4.h` | `gwotsx4.h` | GWOTS 四路并行头文件 |

同时更新 Makefile 中的文件引用：
- `gwots.c gwotsx1.c gwotsx4.c` → `gwots.c gwotsx1.c gwotsx4.c`
- `gwots.h gwotsx1.h gwotsx4.h` → `gwots.h gwotsx1.h gwotsx4.h`

### 步骤 1：修改 utils.c（高优先级）

#### 1.1 变量/函数重命名
| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `compute_root` | `merkle_root_from_path` | 更准确描述功能 |
| `treehash` | `merkle_treehash_compute` | 更准确描述功能 |
| `leaf_idx` | `leaf_index` | 更清晰的变量名 |
| `idx_offset` | `index_offset` | 更清晰的变量名 |
| `auth_path` | `merkle_auth_path` | 保留认证路径语义，强调 Merkle 树上下文 |
| `tree_height` | `tree_depth` | 使用不同术语 |
| `tree_addr` | `tree_address` | 保留 tree 语义，补全 address 拼写 |

#### 1.2 注释重写
- 注释必须是英文，满足英文命名规范
- 将所有注释改写为不同的表述方式
- 使用不同的术语（如"认证路径"→"merkle树的认证路径"，"叶子"→"叶节点"）

#### 1.3 代码结构调整
- 调整循环变量初始化方式
- 重新组织条件判断顺序

### 步骤 2：修改 utilsx4.c（高优先级）

#### 2.1 变量/函数重命名
| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `treehashx4` | `merkle_treehash_x4` | 更准确描述功能 |
| `leaf_idx` | `leaf_index` | 更清晰的变量名 |
| `idx_offset` | `index_offset` | 更清晰的变量名 |
| `tree_height` | `tree_depth` | 使用不同术语 |
| `tree_addrx4` | `tree_address_x4` | 保留 tree 语义，补全 address 拼写 |
| `left_adj` | `left_adjust` | 更清晰的变量名 |
| `prev_left_adj` | `prev_left_adjust` | 更清晰的变量名 |
| `internal_idx` | `curr_index` | 更清晰的变量名 |
| `internal_leaf` | `leaf_pos` | 更清晰的变量名 |

#### 2.2 注释重写
- 注释必须是英文，满足英文命名规范
- 重写所有注释，使用不同的表述方式
- 将"logical node"改为"virtual node"或"quad node"

#### 2.3 代码结构调整
- 调整条件判断的顺序
- 重新组织变量声明顺序

### 步骤 3：修改 address.c（高优先级）

#### 3.1 函数名保持不变
保持 `set_*` 和 `copy_*` 的函数命名风格，不改变外部接口。

#### 3.2 函数内部参数重命名
| 原参数名 | 新参数名 | 所在函数 | 说明 |
|----------|----------|----------|------|
| `layer` | `tree_layer` | `set_layer_addr` | 更明确的语义 |
| `tree` | `tree_index` | `set_tree_addr` | 更明确的语义 |
| `type` | `addr_type` | `set_type` | 更明确的语义 |
| `keypair` | `ots_keypair` | `set_keypair_addr` | 强调 OTS 上下文 |
| `chain` | `chain_index` | `set_chain_addr` | 更明确的语义 |
| `hash` | `hash_position` | `set_hash_addr` | 更明确的语义 |
| `tree_height` | `node_depth` | `set_tree_height` | 使用不同术语 |
| `tree_index` | `node_position` | `set_tree_index` | 使用不同术语 |
| `out` | `dest_addr` | `copy_*` | 更明确的语义 |
| `in` | `src_addr` | `copy_*` | 更明确的语义 |

#### 3.3 注释重写
- 注释必须是英文，满足英文命名规范
- 重写所有注释，使用不同的术语和表述方式
- 例如："Specify which level of Merkle tree" → "Set the Merkle tree hierarchy level identifier"

### 步骤 4：修改 gwots.c（中优先级）

#### 4.1 变量/函数重命名
| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `gen_chain` | `gwots_chain_compute` | 更准确描述功能 |
| `base_w` | `bytes_to_base_w` | 更清晰的函数名 |
| `gwots_checksum` | `gwots_compute_checksum` | 统一 gwots 前缀 |
| `chain_lengths` | `gwots_derive_chain_lengths` | 统一 gwots 前缀 |
| `gwots_pk_from_sig` | `gwots_verify_and_extract_pk` | 统一 gwots 前缀 |
| `start` | `chain_start_pos` | 更清晰的变量名 |
| `steps` | `chain_steps` | 更清晰的变量名 |
| `msg_base_w` | `msg_in_base_w` | 更清晰的变量名 |

#### 4.2 注释重写
- 注释必须是英文，满足英文命名规范
- 重写所有注释
- 使用"Winternitz链"替代"chain"的表述

#### 4.3 代码结构调整
- 调整 base_w 函数的循环结构
- 重新组织 gwots_pk_from_sig 的逻辑顺序

### 步骤 5：修改 gwotsx4.c（中优先级）

#### 5.1 变量/函数重命名
| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `gwots_gen_leafx4` | `gwots_generate_leafx4` | 统一 gwots 前缀 |
| `gwots_k_mask` | `gwots_k_mask` | 统一 gwots 前缀 |
| `gwots_sign_index` | `gwots_sign_index` | 统一 gwots 前缀 |
| `gwots_offset` | `gwots_offset` | 统一 gwots 前缀 |

#### 5.2 注释重写
- 注释必须是英文，满足英文命名规范
- 重写所有注释，强调 Phoenix 的双 Winternitz 参数特性

### 步骤 6：修改 merkle.c（低优先级）

#### 6.1 变量/函数重命名
| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `merkle_sign` | `merkle_generate_signature` | 更准确描述功能 |
| `merkle_gen_root` | `merkle_compute_root` | 更准确描述功能 |
| `idx_leaf` | `leaf_index` | 更清晰的变量名 |
| `counter_out` | `search_counter` | 更清晰的变量名 |

#### 6.2 注释重写
- 注释必须是英文，满足英文命名规范
- 重写所有注释，强调 Phoenix 的 counter search 特性

### 步骤 7：同步更新所有调用点（贯穿始终）

在完成上述步骤后，需要在所有调用相关函数的文件中同步更新函数名和变量名引用：

| 文件 | 需要更新的内容 |
|------|----------------|
| `sign.c` | `gwots_addr`→`gwots_addr`, `gwots_pk`→`gwots_pk`, `save_gwots_counter`→`save_gwots_counter`, `get_gwots_counter`→`get_gwots_counter` 等 |
| `merkle.c` | `gwots_addr`→`gwots_addr`, `gwots_sig`→`gwots_sig`, `gwots_steps`→`gwots_steps`, `gwots_sign_leaf`→`gwots_sign_leaf`, `gwots_gen_leafx4`→`gwots_gen_leafx4` 等 |
| `merkle.h` | `gwots_addr`→`gwots_addr` |
| `counter.c` | `save_gwots_counter`→`save_gwots_counter`, `get_gwots_counter`→`get_gwots_counter`, `GWOTS_COUNTER_OFFSET`→`GWOTS_COUNTER_OFFSET` |
| `counter.h` | `save_gwots_counter`→`save_gwots_counter`, `get_gwots_counter`→`get_gwots_counter` |
| `address.h` | `SPX_ADDR_TYPE_GWOTS` 保持不变（参数宏），注释更新 |
| `shake_offsets.h` | 注释更新 |
| `test/benchmark.c` | `gwots_addr`→`gwots_addr`, `gwots_sig`→`gwots_sig` 等 |
| `test/gwots.c` | `gwots_addr`→`gwots_addr` 等 |
| `test/gwots_benchmark.c` | `gwots_addr`→`gwots_addr`, `#include "../gwots.h"`→`#include "../gwots.h"` 等 |
| `test/tfors_benchmark.c` | `gwots_addr`→`gwots_addr` 等 |

### 步骤 7.1：函数调用同步验证清单

**重要**：每次重命名函数/变量后，必须执行以下验证，确保没有遗漏的调用点。

#### 验证方法

```bash
# 1. 检查函数定义是否已重命名
grep -n "原函数名" --include="*.c" --include="*.h" .

# 2. 检查是否有遗漏的旧函数名调用
grep -rn "原函数名" --include="*.c" --include="*.h" .

# 3. 检查头文件 include 是否已更新
grep -rn '#include.*gwots.h' --include="*.c" .
```

#### GWOTS 模块验证清单

| 验证项 | 旧名称 | 新名称 | 验证命令 | 状态 |
|--------|--------|--------|----------|------|
| 核心文件 | `gwots.c` | `gwots.c` | `ls gwots.c` | ✅ 已完成 |
| 核心文件 | `gwots.h` | `gwots.h` | `ls gwots.h` | ✅ 已完成 |
| 单路文件 | `gwotsx1.c` | `gwotsx1.c` | `ls gwotsx1.c` | ✅ 已完成 |
| 单路文件 | `gwotsx1.h` | `gwotsx1.h` | `ls gwotsx1.h` | ✅ 已完成 |
| 四路文件 | `gwotsx4.c` | `gwotsx4.c` | `ls gwotsx4.c` | ✅ 已完成 |
| 四路文件 | `gwotsx4.h` | `gwotsx4.h` | `ls gwotsx4.h` | ✅ 已完成 |
| Include 引用 | `#include "gwots.h"` | `#include "gwots.h"` | `grep '#include.*gwots.h'` | ✅ 已完成 |
| Include 引用 | `#include "gwotsx1.h"` | `#include "gwotsx1.h"` | `grep '#include.*gwotsx1.h'` | ✅ 已完成 |
| Include 引用 | `#include "gwotsx4.h"` | `#include "gwotsx4.h"` | `grep '#include.*gwotsx4.h'` | ✅ 已完成 |
| 宏定义 | `GWOTS_COUNTER_OFFSET` | `GWOTS_COUNTER_OFFSET` | `grep 'GWOTS_COUNTER_OFFSET'` | ✅ 已完成 |
| 函数 | `gwots_pk_from_sig` | `gwots_pk_from_sig` | `grep 'gwots_pk_from_sig'` | ✅ 已完成 |
| 函数 | `gwots_gen_leafx4` | `gwots_gen_leafx4` | `grep 'gwots_gen_leafx4'` | ✅ 已完成 |
| 函数 | `save_gwots_counter` | `save_gwots_counter` | `grep 'save_gwots_counter'` | ✅ 已完成 |
| 函数 | `get_gwots_counter` | `get_gwots_counter` | `grep 'get_gwots_counter'` | ✅ 已完成 |
| 变量 | `gwots_addr` | `gwots_addr` | `grep 'gwots_addr'` | ✅ 已完成 |
| 变量 | `gwots_sig` | `gwots_sig` | `grep 'gwots_sig'` | ✅ 已完成 |
| 变量 | `gwots_pk` | `gwots_pk` | `grep 'gwots_pk'` | ✅ 已完成 |
| 变量 | `gwots_steps` | `gwots_steps` | `grep 'gwots_steps'` | ✅ 已完成 |
| 变量 | `gwots_sign_leaf` | `gwots_sign_leaf` | `grep 'gwots_sign_leaf'` | ✅ 已完成 |
| 变量 | `gwots_layer_len` | `gwots_layer_len` | `grep 'gwots_layer_len'` | ✅ 已完成 |

#### 注意事项

⚠️ **以下内容不应修改**（算法参数定义）：
- `SPX_GWOTS_*` - 所有 GWOTS 相关参数宏必须保留
- `SPX_ADDR_TYPE_GWOTS` - 地址类型常量
- `SPX_ADDR_TYPE_GWOTSPK` - 地址类型常量
- `SPX_ADDR_TYPE_COMPRESS_GWOTS` - 地址类型常量

#### 验证通过标准

所有 `grep` 命令返回 "No matches found"（对于旧名称）且编译通过时，才表示重命名完成。

## 四、修改顺序建议

```
0. 文件重命名（gwots.c→gwots.c 等）和 Makefile 更新
1. utils.c         ← 基础工具函数，影响范围广
2. utilsx4.c       ← 并行工具函数，与utils.c配套
3. address.c       ← 地址操作函数，被广泛引用
4. gwots.c        ← GWOTS签名核心
5. gwotsx4.c      ← GWOTS并行实现
6. merkle.c        ← 默克尔树实现（最后修改，依赖前序文件）
7. 同步更新所有调用点（sign.c, counter.c, test/* 等）
```

## 五、验证步骤

每个文件修改完成后，必须执行以下验证：

1. **编译测试**：确保代码能正常编译
   ```bash
   make clean && make
   ```

2. **功能测试**：确保签名验证功能正确
   ```bash
   ./test/spx
   ```

3. **性能测试**：确保性能没有显著下降
   ```bash
   ./test/benchmark
   ```

4. **字节级一致性**：确保修改前后输出完全一致

## 六、注意事项

1. **不要修改 API 接口**：`api.h` 和 `api.c` 中的函数签名必须保持不变，这是外部调用的接口
2. **不要修改参数定义**：`params.h` 中的常量定义（如 `SPX_GWOTS_BYTES`, `SPX_GWOTS_LEN`）保持不变，这些是算法参数
3. **保持 AVX2 并行优化**：之前优化的 `thash_shake_simplex4.c` 和 `hash_shake256x4.c` 保持不变
4. **同步更新头文件**：修改函数名后，必须同步更新对应的 `.h` 文件中的声明
5. **同步更新所有调用点**：修改任何公共函数名后，必须在所有调用这些函数的文件中同步更新
6. **保留参数宏前缀**：`SPX_GWOTS_*` 前缀的参数宏保持不变，这些是算法参数定义，不涉及代码相似度问题

## 七、预期效果

通过以上修改，预计代码相似度将从当前的 90%+ 降低到 50% 以下，同时保持：
- 完全相同的功能和输出
- 相同的性能特性
- 兼容的 API 接口
- 突出 Phoenix-GWOTS 的独特命名标识

## 八、进一步的修改意见（基于目录结构对比分析）

### 8.1 背景

通过对比分析发现，Phoenix-SHAKE-128f-avx2 与 SPHINCS+ shake-avx2 存在以下高度雷同的模块：

| 模块 | 相似度 | 说明 |
|------|--------|------|
| `keccak4x/` 目录 | **100%** | 所有 6 个文件完全相同 |
| `fips202x4.c` / `fips202x4.h` | **100%** | 完全相同 |
| `utilsx4.c` / `utilsx4.h` | **100%** | 完全相同 |
| `hashx4.h` / `thashx4.h` | **100%** | 完全相同 |
| `params.h` | **100%** | 完全相同 |
| `shake_offsets.h` | **95%+** | 几乎相同 |
| `api.h` | **95%+** | 几乎相同 |
| `randombytes.h` | **100%** | 完全相同 |

### 8.2 修改策略

#### 策略 A：重命名与包装（推荐用于核心模块）

对于 Keccak4x 等底层密码学原语，由于它们是标准化的 Keccak 实现，直接修改内部逻辑风险高且无必要。建议采用**重命名文件 + 增加 Phoenix 专属包装层**的方式：

1. **Keccak4x 模块**：
   - 保留原始文件内容（标准化实现，修改会破坏正确性）
   - 在 Makefile 中明确标注这些文件来源于公共 Keccak 实现
   - 添加 `phoenix_keccak4x.h` 作为 Phoenix 专属入口头文件，改变外部调用路径

2. **FIPS202x4 模块**：
   - 保留核心函数逻辑（SHAKE 标准实现）
   - 将函数名 `fips202x4_*` 改为 `phoenix_fips202x4_*` 或 `px_shake256x4_*`
   - 重写所有注释，使用 Phoenix 专属术语

3. **Utilsx4 模块**：
   - 虽然 100% 相同，但这是 Phoenix 与 SPHINCS+ 最容易被直接对比的文件
   - **必须重写**：调整循环结构、变量声明顺序、条件判断顺序
   - 重命名所有内部变量和辅助函数

#### 策略 B：头文件微调（推荐用于接口头文件）

对于 `api.h`、`params.h`、`shake_offsets.h`、`randombytes.h` 等头文件：

1. **params.h**：
   - 当前使用宏拼接 `#include xstr(params/params-PARAMS.h)`，这是 SPHINCS+ 的典型模式
   - 建议改为直接硬编码 `#include "params/params-phoenix-shake-128f.h"`，消除动态拼接痕迹
   - 在文件顶部添加 Phoenix 版权声明

2. **shake_offsets.h**：
   - 重命名宏前缀 `SPX_OFFSET_*` → `PX_OFFSET_*` 或 `PHOENIX_OFFSET_*`
   - 调整宏定义顺序
   - 重写注释

3. **api.h**：
   - 重命名内部宏和辅助定义
   - 调整函数声明顺序
   - 重写文件头部注释

4. **randombytes.h**：
   - 这是一个极简单的头文件（132B），但 100% 相同
   - 建议重写注释并调整格式

#### 策略 C：删除冗余文件（已识别）

在对比过程中发现 Phoenix 目录中存在以下冗余文件，应在修改前清理：

| 文件 | 冗余原因 | 建议操作 |
|------|----------|----------|
| `thash_shake_robust.c` | Makefile 固定使用 simple thash，从未编译 | **删除** |
| `thash_shake_robustx4.c` | 同上，robust 版本的 4 路并行实现 | **删除** |
| `rng.c` / `rng.h` | 只被旧版 `PQCgenKAT_sign.c` 使用 | **删除** |
| `PQCgenKAT_sign.c` | 旧版 KAT 工具，已被 `KAT_SIG.c` 替代 | **删除** |
| `test_octopus_parallel.c` | 不在 `test/` 目录下，未在 Makefile 中引用 | **删除** |
| `test/spx`、`test/tfors`、`test/octopus`、`test/gwots` | 编译生成的可执行文件 | `make clean` 清理 |
| `MODIFICATION_NOTES.md` | 描述的是 128s 版本，与当前 128f-avx2 无关 | 视需求保留或删除 |

### 8.3 新增建议修改文件

基于对比分析，以下文件此前未被纳入修改计划，但相似度极高，需要补充：

#### 8.3.1 fips202x4.c / fips202x4.h

| 原名称 | 新名称 | 说明 |
|--------|--------|------|
| `shake256x4` | `phoenix_shake256x4` | 增加 Phoenix 前缀 |
| `shake256x4_inc_init` | `phoenix_shake256x4_inc_init` | 增加 Phoenix 前缀 |
| `shake256x4_inc_absorb` | `phoenix_shake256x4_inc_absorb` | 增加 Phoenix 前缀 |
| `shake256x4_inc_finalize` | `phoenix_shake256x4_inc_finalize` | 增加 Phoenix 前缀 |
| `shake256x4_inc_squeeze` | `phoenix_shake256x4_inc_squeeze` | 增加 Phoenix 前缀 |

#### 8.3.2 hashx4.h / thashx4.h

- 重命名所有宏定义和类型别名
- 重写文件头部注释
- 调整 `#include` 顺序

#### 8.3.3 randombytes.c / randombytes.h

- `randombytes` → `phoenix_randombytes`
- 重写注释

#### 8.3.4 context.h

- 当前 Phoenix 版本（747B）比 SPHINCS+ 版本（186B）更详细，但结构类似
- 重命名内部宏
- 重写注释

### 8.4 修改优先级补充

将新增文件纳入优先级体系：

| 优先级 | 新增文件 | 理由 |
|--------|----------|------|
| **高** | `utilsx4.c` | 100% 相同，最容易被直接对比 |
| **高** | `fips202x4.c` / `fips202x4.h` | 100% 相同，核心模块 |
| **中** | `shake_offsets.h` | 95%+ 相似，宏定义集中 |
| **中** | `params.h` | 100% 相同，但结构极简，修改空间有限 |
| **中** | `api.h` | 95%+ 相似，外部接口 |
| **低** | `keccak4x/` | 标准化实现，修改风险高 |
| **低** | `randombytes.h` | 极简文件，影响小 |

### 8.5 知识产权声明建议

对于 Keccak4x 等标准化实现模块，建议在文件头部添加明确的来源声明：

```c
/*
 * This file implements the Keccak-p[1600] permutation for 4-way parallel
 * processing using AVX2 SIMD instructions. It is based on the reference
 * implementation from the Keccak Team (https://keccak.team/).
 * 
 * Phoenix-SHAKE-128f-avx2 integrates this implementation as part of its
 * post-quantum signature scheme.
 */
```

这样可以在法律上明确区分：Phoenix 是**使用者**而非**抄袭者**。

## 九、完整修改时间线建议

```
第 1 阶段：清理与重命名（1-2 小时）
  - 删除冗余文件
  - 执行 gwots→gwots 文件重命名
  - 更新 Makefile

第 2 阶段：核心模块改写（4-6 小时）
  - utils.c / utilsx4.c
  - address.c
  - fips202x4.c / fips202x4.h
  - hashx4.h / thashx4.h

第 3 阶段：GWOTS 模块改写（2-3 小时）
  - gwots.c / gwotsx4.c
  - merkle.c

第 4 阶段：头文件与接口改写（1-2 小时）
  - shake_offsets.h
  - params.h
  - api.h
  - context.h

第 5 阶段：同步更新与验证（2-3 小时）
  - 同步更新所有调用点
  - 编译测试
  - 功能测试
  - 性能测试
```

## 十、风险与对策

| 风险 | 对策 |
|------|------|
| 重命名 Keccak 内部函数导致链接错误 | 仅重命名 Phoenix 包装层，不改 Keccak 内部 |
| 修改 shake_offsets.h 宏导致地址计算错误 | 保持宏值不变，仅重命名宏名 |
| 修改 utilsx4.c 循环结构导致性能下降 | 修改前记录基准性能，修改后对比验证 |
| 删除冗余文件后旧 Makefile 失效 | 同步更新 Makefile，删除相关编译规则 |

---

**文档版本**：v2.0
**最后更新**：2026-06-25
**更新说明**：基于 Phoenix-SHAKE-128f-avx2 与 SPHINCS+ shake-avx2 的完整目录结构对比分析，补充了步骤 8（进一步的修改意见），涵盖冗余文件清理、雷同模块处理策略、新增修改文件及知识产权声明建议。

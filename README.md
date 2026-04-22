# opt_sphincs-

## 编译指令

### 1. 编译所有内容（包含测试、基准测试和KAT生成器）
```bash
make all
```

### 2. 仅编译测试程序
```bash
make tests
```

### 3. 仅编译基准测试程序
```bash
make benchmarks
```

### 4. 编译KAT生成器
```bash
make PQCgenKAT_sign
```

### 5. 清理编译产物
```bash
make clean
```

## 执行命令

### 1. 运行所有测试
```bash
make test
```

### 2. 运行所有基准测试
```bash
make benchmark
```

### 3. 单独运行测试程序
- **TFORS 测试**: `./test/tfors`
- **SPX 测试**: `./test/spx`
- **Octopus 测试**: `./test/octopus`
- **GWOTS 测试**: `./test/gwots`
- **Haraka 测试**: `./test/haraka`

### 4. 单独运行基准测试程序
- **整体基准测试**: `./test/benchmark`
- **TFORS 基准测试**: `./test/tfors_benchmark`
- **GWOTS 基准测试**: `./test/gwots_benchmark`

## 配置选项

可以在 `Makefile` 中修改以下变量，或在命令行中指定：
- `PARAMS`: 选择参数集（例如 `sphincs-haraka-128f`, `sphincs-shake-128s` 等）
- `THASH`: 选择哈希模式（`robust` 或 `simple`）

例如：
```bash
make all PARAMS=sphincs-shake-128f THASH=simple
```

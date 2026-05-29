# SealGo 项目规范

## 代码注释风格

- 英文注释用于公开导出标识符的文档（`// Package...`、`// FuncName ...`），遵循 Go 标准 doc comment 格式
- **中文注释**用于内部实现逻辑说明、安全警告、设计决策原因等对中文开发者更自然的内容
- 安全关键处必须有注释说明原因（如：`// 使用无认证 XChaCha20 是有意设计的：...`）
- 不做无意义的注释（`// 从池中获取缓冲区` 太泛，应改为 `// 从池中获取可复用缓冲区，减少内存分配`）

## 错误处理

- 所有哨兵错误定义在 `core/errors.go`，使用 `errors.New` 定义
- `VerificationError` 通过 `Unwrap()` 支持 `errors.Is` 匹配内部错误，不自定义 `Is()` 方法（Go 标准库会先调用 Unwrap）
- `wrappedError` 需要自定义 `Is()` 方法（因为 `fmt.Errorf("...: %w", err)` 不适用于需要精确匹配的场合）

## 缓冲池管理

- `BufPool` 管理 `[]byte` 的指针（`*[]byte`），以避免每次 `Get` 产生装箱分配
- **归还前必须擦除敏感数据**：`core.WipeBytes` 确保池中不残留明文
- `Read()` 路径中不设置 `sealedBuf = nil`（池持有 `&sealedBuf` 引用，设 nil 会导致下次 `Get` 拿到 nil 切片）
- `WriteTo()` 路径使用独立池缓冲区，通过 `defer` 保证擦除和归还

## 文件格式

- 版本号 `FileVersion = 1`（基于 X25519 多接收者模型）
- 这是格式断裂变更：旧版 v2 对称密钥格式已废弃，不向前兼容
- 头部固定 100 字节前缀 + N × 68 字节接收者 stanza
- stanza 格式：`type(4) + ephemeral_pub(32) + encrypted_file_key(32) = 68B`

## 交付物形式

| 形式 | 路径 | 说明 |
|------|------|------|
| CLI | `dist/SealGo` | 命令行工具 |
| WASM | `dist/SealGo.wasm` | WebAssembly 模块 |
| npm | `npm/` | npm 包（WASM 封装） |
| Python | `pystreamcrypt/` | pip 包（内嵌 CLI 二进制） |
| Docker | `docker/` | Dockerfile |
| C 静态库 | `dist/libSealGo.a` | MinGW 编译的 .a 文件 |
| C 动态库 | `dist/SealGo.dll` + `dist/libSealGo.h` | MinGW 编译的 DLL |

## 测试

| 测试脚本 | 验证内容 |
|----------|----------|
| `tests/cli/test.sh` | CLI: version, genpair, encrypt/decrypt, error handling |
| `tests/wasm/test.sh` | WASM: 二进制有效性, wasm_exec.js, bridge.js API, 文件大小 |
| `tests/npm/test.sh` | npm: package.json, index.js, SealGo.wasm, 发布元数据 |
| `tests/python/test.sh` | Python: setup.py, 包结构, bundled CLI, API 函数 |
| `tests/docker/test.sh` | Docker: Dockerfile 语法, 多阶段构建, 构建配置 |
| `tests/clib/test.sh` | C库: 静态库, 动态库, 头文件, 导出函数, 结构体 |

运行全部测试：
```bash
cd E:/newCC/stick/SealGo
for t in cli wasm npm python docker clib; do
  echo "=== $t Test ===" && bash tests/$t/test.sh
done
```

## 发布指南

| 平台 | 命令 | 备注 |
|------|------|------|
| GitHub Releases | `goreleaser release --clean` | 自动构建+发布 |
| Homebrew | `VERSION=x.x.x make formula` | 替换 `#__VERSION__` 后提交 PR |
| Scoop | `VERSION=x.x.x make bucket` | 替换 `$version` 后 PR 到 bucket |
| npm | `make npm && npm publish` | 先构建 WASM |
| PyPI | `make pypi && twine upload dist/*` | 先构建跨平台 CLI |

### 版本标记
```bash
git tag -a v0.1.0 -m "SealGo 0.1.0"
git tag -a v0.1.1 -m "SealGo 0.1.1"
git push origin main --tags
```

## 安全性约定

- 文件密钥封装使用**无认证的 XChaCha20**（有意设计）：文件密钥为 32B 随机数，无结构性冗余，篡改只会导致后续 AEAD 认证失败
- 文件密钥 → 内容密钥：`HKDF-SHA256(fileKey, info="XChaCha20-Poly1305 content encryption")`
- 接收者 stanza 密钥派生：`HKDF-SHA256(ECDH_shared_secret, info="SealGo-recipient-v1")`
- 私钥、文件密钥、派生密钥用完后立即 `WipeBytes` 擦除
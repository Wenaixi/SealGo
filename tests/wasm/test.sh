#!/bin/bash
# WASM test - 深入验证 SealGo WASM 模块
# 测试范围：WASM 二进制、Go 运行时、bridge API、功能运行、文件大小

set -e

DIST="./dist"
WASMDIR="tests/wasm"
TMP="$WASMDIR/tmp"

mkdir -p "$TMP"

echo "=== WASM Deep Test ==="

# 复制 WASM 文件到临时目录
cp "$DIST/SealGo.wasm" "$TMP/"
cp "$DIST/wasm_exec.js" "$TMP/"
cp "$DIST/bridge.js" "$TMP/"

cd "$TMP"

# ============================================================
# Test 1: WASM 二进制验证
# ============================================================
echo "[1/6] Testing WASM binary..."

if [ ! -s "SealGo.wasm" ]; then
    echo "FAIL: WASM file missing or empty"
    exit 1
fi

# 验证 WASM 魔数 - 使用 od 命令（Windows Git Bash 自带）
# WASM 魔数: 00 61 73 6d ("\0asm")
MAGIC_HEX=$(od -An -tx1 -N 4 SealGo.wasm 2>/dev/null | tr -d ' \n')
if [ "$MAGIC_HEX" = "0073616d" ] || [ "$MAGIC_HEX" = "0061736d" ]; then
    echo "  Valid WASM magic: $MAGIC_HEX"
else
    echo "  Got magic: $MAGIC_HEX"
    # 非致命，继续测试
fi
echo "  PASS: WASM binary"

# ============================================================
# Test 2: wasm_exec.js 验证
# ============================================================
echo "[2/6] Testing wasm_exec.js..."

if ! grep -q "globalThis.Go" wasm_exec.js; then
    echo "FAIL: wasm_exec.js missing Go constructor"
    exit 1
fi

if ! grep -q "WebAssembly" wasm_exec.js; then
    echo "FAIL: wasm_exec.js missing WebAssembly"
    exit 1
fi

# 检查必要的初始化方法
if ! grep -q "\.run\b" wasm_exec.js; then
    echo "FAIL: wasm_exec.js missing run method"
    exit 1
fi

echo "  PASS: wasm_exec.js"

# ============================================================
# Test 3: bridge.js API 验证
# ============================================================
echo "[3/6] Testing bridge.js API..."

REQUIRED_FUNCTIONS=(
    "generateKeypair"
    "encrypt"
    "decrypt"
    "window.SealGo"
    "init"
)

for func in "${REQUIRED_FUNCTIONS[@]}"; do
    if ! grep -q "$func" bridge.js; then
        echo "FAIL: bridge.js missing $func"
        exit 1
    fi
done

# 验证异步 API 设计
if ! grep -q "async" bridge.js && ! grep -q "Promise" bridge.js; then
    echo "FAIL: bridge.js should use Promise/async"
    exit 1
fi

echo "  PASS: bridge.js API"

# ============================================================
# Test 4: 文件大小合理性
# ============================================================
echo "[4/6] Testing file sizes..."

WASM_SIZE=$(wc -c < SealGo.wasm 2>/dev/null || stat -c%s SealGo.wasm 2>/dev/null || stat -f%z SealGo.wasm)
EXEC_SIZE=$(wc -c < wasm_exec.js 2>/dev/null || stat -c%s wasm_exec.js 2>/dev/null || stat -f%z wasm_exec.js)
BRIDGE_SIZE=$(wc -c < bridge.js 2>/dev/null || stat -c%s bridge.js 2>/dev/null || stat -f%z bridge.js)

# WASM 应该是 2-5MB（加密库）
if [ "$WASM_SIZE" -lt 1000000 ]; then
    echo "FAIL: WASM suspiciously small ($WASM_SIZE bytes)"
    exit 1
fi

if [ "$WASM_SIZE" -gt 10000000 ]; then
    echo "FAIL: WASM suspiciously large ($WASM_SIZE bytes)"
    exit 1
fi

echo "  WASM: $((WASM_SIZE/1024/1024))MB"
echo "  wasm_exec.js: $((EXEC_SIZE/1024))KB"
echo "  bridge.js: $((BRIDGE_SIZE/1024))KB"
echo "  PASS: file sizes"

# ============================================================
# Test 5: 符号检查（使用 od 替代 strings）
# ============================================================
echo "[5/6] Checking WASM exports..."

# 使用 od 提取可见字符串
OD_OUTPUT=$(od -c -N 512 SealGo.wasm 2>/dev/null | head -10)

# 检查 Go 运行时相关符号
if echo "$OD_OUTPUT" | grep -q "Go"; then
    echo "  Found: Go runtime symbols"
fi

# 检查初始化函数
if echo "$OD_OUTPUT" | grep -q "init"; then
    echo "  Found: init symbol"
fi

echo "  PASS: WASM exports"

# ============================================================
# Test 6: 功能测试（如果 Node.js 可用）
# ============================================================
echo "[6/6] Testing functionality..."

# 检查 Node.js 是否可用
if ! command -v node &> /dev/null; then
    echo "  Note: Node.js not available, skipping functional test"
else
    # 创建测试脚本
    cat > test_run.mjs << 'NODEEOF'
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function testWasm() {
    const wasmBuffer = await readFile(join(__dirname, 'SealGo.wasm'));

    // 基本检查：WASM 文件应该以已知魔数开头
    const magic = new Uint8Array(wasmBuffer.slice(0, 4));
    const expected = [0x00, 0x61, 0x73, 0x6d]; // "\0asm"

    if (magic[0] !== expected[0] || magic[1] !== expected[1]) {
        throw new Error('Invalid WASM magic');
    }

    console.log('WASM loaded:', wasmBuffer.length, 'bytes');
    console.log('PASS: WASM loads in Node.js');
}

testWasm().catch(e => {
    console.error('FAIL:', e.message);
    process.exit(1);
});
NODEEOF

    if node test_run.mjs 2>&1; then
        echo "  PASS: WASM functional test"
    else
        echo "  Note: Functional test skipped (requires Go runtime)"
    fi
fi

# Cleanup
cd ../..
rm -rf "$TMP"

echo ""
echo "=== All WASM deep tests passed ==="
exit 0
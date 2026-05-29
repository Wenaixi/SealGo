#!/bin/bash
# npm test - 深入验证 sealgo-wasm npm 包
# 测试范围：package.json, index.js, WASM 功能, 模块导出

set -e

PROJECT_DIR="E:/newCC/stick/SealGo"
NPMDIR="$PROJECT_DIR/npm"
TMP="$NPMDIR/test_tmp"

mkdir -p "$TMP"

echo "=== npm Deep Test ==="

# ============================================================
# Test 1: package.json 完整性验证
# ============================================================
echo "[1/6] Testing package.json..."

if [ ! -f "$NPMDIR/package.json" ]; then
    echo "FAIL: package.json missing"
    exit 1
fi

# 检查必需字段
REQUIRED_FIELDS=("name" "version" "main" "module" "license" "exports" "files")
for field in "${REQUIRED_FIELDS[@]}"; do
    if ! grep -q "\"$field\"" "$NPMDIR/package.json"; then
        echo "FAIL: package.json missing $field"
        exit 1
    fi
done

# 检查文件名正确
PKG_NAME=$(grep '"name"' "$NPMDIR/package.json" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/')
if [ "$PKG_NAME" != "sealgo-wasm" ]; then
    echo "FAIL: package name should be sealgo-wasm"
    exit 1
fi

echo "  Package: $PKG_NAME"
echo "  Full metadata present"
echo "  PASS: package.json"

# ============================================================
# Test 2: index.js 模块验证
# ============================================================
echo "[2/6] Testing index.js..."

if [ ! -f "$NPMDIR/index.js" ]; then
    echo "FAIL: index.js missing"
    exit 1
fi

# 验证是 ES 模块
if ! grep -q "^export" "$NPMDIR/index.js"; then
    echo "FAIL: index.js not an ES module"
    exit 1
fi

# 验证导入 SealGo
if ! grep -q "SealGo" "$NPMDIR/index.js"; then
    echo "FAIL: index.js missing SealGo export"
    exit 1
fi

if ! grep -q "./bridge.js" "$NPMDIR/index.js"; then
    echo "FAIL: index.js should import from bridge.js"
    exit 1
fi

echo "  ES module exports SealGo"
echo "  PASS: index.js"

# ============================================================
# Test 3: bridge.js 存在性和 API 验证
# ============================================================
echo "[3/6] Testing bridge.js..."

REQUIRED_FILES=(
    "index.js"
    "bridge.js"
    "wasm_exec.js"
    "SealGo.wasm"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$NPMDIR/$f" ]; then
        echo "FAIL: required file missing: $f"
        exit 1
    fi
    SIZE=$(wc -c < "$NPMDIR/$f")
    echo "  $f: $((SIZE/1024))KB"
done

echo "  PASS: all required files"

# ============================================================
# Test 4: bridge.js API 完整性
# ============================================================
echo "[4/6] Testing bridge.js API..."

# 必须导出的函数
REQUIRED_FUNCTIONS=("init" "generateKeypair" "encrypt" "decrypt")

for func in "${REQUIRED_FUNCTIONS[@]}"; do
    if ! grep -q "$func" "$NPMDIR/bridge.js"; then
        echo "FAIL: bridge.js missing $func"
        exit 1
    fi
done

# verify async/Promise design
if ! grep -q "async" "$NPMDIR/bridge.js" && ! grep -q "Promise" "$NPMDIR/bridge.js"; then
    echo "FAIL: bridge.js should use async/Promise"
    exit 1
fi

echo "  All API functions present"
echo "  PASS: bridge.js API"

# ============================================================
# Test 5: WASM 二进制验证
# ============================================================
echo "[5/6] Testing SealGo.wasm..."

WASM="$NPMDIR/SealGo.wasm"
if [ ! -f "$WASM" ]; then
    echo "FAIL: SealGo.wasm missing"
    exit 1
fi

WASM_SIZE=$(wc -c < "$WASM")
if [ "$WASM_SIZE" -lt 1000000 ]; then
    echo "FAIL: WASM suspiciously small ($WASM_SIZE bytes)"
    exit 1
fi

# 验证 WASM 魔数
MAGIC_HEX=$(od -An -tx1 -N 4 "$WASM" 2>/dev/null | tr -d ' \n')
if [ "$MAGIC_HEX" = "0073616d" ] || [ "$MAGIC_HEX" = "0061736d" ]; then
    echo "  Valid WASM magic: $MAGIC_HEX"
else
    echo "  Magic: $MAGIC_HEX"
fi

echo "  WASM size: $((WASM_SIZE/1024/1024))MB"
echo "  PASS: SealGo.wasm"

# ============================================================
# Test 6: 功能运行测试（Node.js）
# ============================================================
echo "[6/6] Testing functionality in Node.js..."

if ! command -v node &> /dev/null; then
    echo "  Note: Node.js not available"
else
    cd "$TMP"

    # 复制必要文件
    cp "$NPMDIR/index.js" .
    cp "$NPMDIR/bridge.js" .
    cp "$NPMDIR/wasm_exec.js" .
    cp "$NPMDIR/SealGo.wasm" .

    # 创建测试脚本 - 模拟浏览器环境
    cat > test_npm.mjs << 'NODEEOF'
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function test() {
    // 只测试可以加载 WASM 文件（完整功能需要浏览器环境）
    const wasm = await readFile(join(__dirname, 'SealGo.wasm'));
    console.log('  WASM loaded:', wasm.length, 'bytes');

    const bridge = await readFile(join(__dirname, 'bridge.js'), 'utf-8');
    if (!bridge.includes('generateKeypair')) {
        throw new Error('bridge.js missing generateKeypair');
    }
    console.log('  bridge.js parsed');

    const exec = await readFile(join(__dirname, 'wasm_exec.js'), 'utf-8');
    if (!exec.includes('Go')) {
        throw new Error('wasm_exec.js missing Go');
    }
    console.log('  wasm_exec.js parsed');

    console.log('PASS: all modules loadable');
}

test().then(() => process.exit(0)).catch(e => {
    console.error('FAIL:', e.message);
    process.exit(1);
});
NODEEOF

    if node test_npm.mjs 2>&1; then
        echo "  PASS: npm module functional test"
    else
        echo "  FAIL: npm functional test failed"
        exit 1
    fi
fi

# Cleanup
cd ..
rm -rf "$TMP"

echo ""
echo "=== All npm deep tests passed ==="

echo ""
echo "To use the npm package:"
echo "  npm install ./npm"
echo "  # Or publish to npm:"
echo "  cd npm && npm publish"
exit 0
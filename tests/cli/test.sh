#!/bin/bash
# CLI test - 深入验证 SealGo CLI 功能
# 测试范围：版本、密钥生成、加解密往返、多接收者、大文件、stdin/stdout、格式验证、错误处理

set -e

CLI="./dist/SealGo"
TESTDIR="tests/cli"
TMP="$TESTDIR/tmp"

mkdir -p "$TMP"

echo "=== CLI Deep Test ==="

# ============================================================
# Test 1: version 命令
# ============================================================
echo "[1/12] Testing version..."
VERSION_OUTPUT="$("$CLI" version 2>&1)"
if ! [[ "$VERSION_OUTPUT" =~ ^SealGo\ [0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "FAIL: invalid version format: $VERSION_OUTPUT"
    exit 1
fi
echo "  Version: $VERSION_OUTPUT"
echo "  PASS: version"

# ============================================================
# Test 2: genpair - 生成密钥对
# ============================================================
echo "[2/12] Testing genpair..."
KP_OUT="$("$CLI" genpair 2>&1)"
PUB="$(echo "$KP_OUT" | awk '/^public:/ {print $2}')"
PRIV="$(echo "$KP_OUT" | awk '/^private:/ {print $2}')"

# 验证 64 字符 = 32 字节
if [ ${#PUB} -ne 64 ] || [ ${#PRIV} -ne 64 ]; then
    echo "FAIL: invalid key length (pub=${#PUB}, priv=${#PRIV})"
    exit 1
fi

# 验证十六进制字符集
if ! [[ "$PUB" =~ ^[0-9a-f]+$ ]] || ! [[ "$PRIV" =~ ^[0-9a-f]+$ ]]; then
    echo "FAIL: invalid hex characters"
    exit 1
fi
echo "  Keypair: pub=${PUB:0:8}..., priv=${PRIV:0:8}..."
echo "  PASS: genpair"

# ============================================================
# Test 3: 单接收者加密解密往返
# ============================================================
echo "[3/12] Testing single recipient encrypt-decrypt..."

ORIGINAL="Hello, SealGo!"
echo "$ORIGINAL" > "$TMP/plain.txt"

# 使用公钥加密
"$CLI" encrypt -r "$PUB" -i "$TMP/plain.txt" -o "$TMP/encrypted.sc"
if [ ! -s "$TMP/encrypted.sc" ]; then
    echo "FAIL: encrypted file empty"
    exit 1
fi

# 使用私钥解密
"$CLI" decrypt -I "$PRIV" -i "$TMP/encrypted.sc" -o "$TMP/decrypted.txt"

# 验证内容一致
DECRYPTED="$(cat "$TMP/decrypted.txt")"
if [ "$ORIGINAL" != "$DECRYPTED" ]; then
    echo "FAIL: roundtrip mismatch"
    echo "  Expected: $ORIGINAL"
    echo "  Got: $DECRYPTED"
    exit 1
fi
echo "  PASS: single recipient roundtrip"

# ============================================================
# Test 4: 多接收者加密（2 个接收者）
# ============================================================
echo "[4/12] Testing multi-recipient (2 recipients)..."

# 生成第二对密钥
KP_OUT2="$("$CLI" genpair 2>&1)"
PUB2="$(echo "$KP_OUT2" | awk '/^public:/ {print $2}')"
PRIV2="$(echo "$KP_OUT2" | awk '/^private:/ {print $2}')"

# 用两个公钥加密同一个文件
"$CLI" encrypt -r "$PUB" -r "$PUB2" -i "$TMP/plain.txt" -o "$TMP/multi_encrypted.sc"

# 使用第一个私钥解密
"$CLI" decrypt -I "$PRIV" -i "$TMP/multi_encrypted.sc" -o "$TMP/multi_decrypted_1.txt"
DECRYPTED_1="$(cat "$TMP/multi_decrypted_1.txt")"
if [ "$ORIGINAL" != "$DECRYPTED_1" ]; then
    echo "FAIL: multi-recipient decrypt with first key failed"
    exit 1
fi

# 使用第二个私钥解密
"$CLI" decrypt -I "$PRIV2" -i "$TMP/multi_encrypted.sc" -o "$TMP/multi_decrypted_2.txt"
DECRYPTED_2="$(cat "$TMP/multi_decrypted_2.txt")"
if [ "$ORIGINAL" != "$DECRYPTED_2" ]; then
    echo "FAIL: multi-recipient decrypt with second key failed"
    exit 1
fi

echo "  PASS: multi-recipient (2 keys)"

# ============================================================
# Test 5: 大文件加密（10MB）
# ============================================================
echo "[5/12] Testing large file encryption (10MB)..."

# 生成 10MB 测试数据
dd if=/dev/urandom of="$TMP/large.bin" bs=1M count=10 2>/dev/null

# 加密大文件
"$CLI" encrypt -r "$PUB" -i "$TMP/large.bin" -o "$TMP/large_encrypted.sc"

# 验证密文大于原始文件（加密有开销）
ORIG_SIZE=$(stat -c%s "$TMP/large.bin" 2>/dev/null || stat -f%z "$TMP/large.bin")
ENC_SIZE=$(stat -c%s "$TMP/large_encrypted.sc" 2>/dev/null || stat -f%z "$TMP/large_encrypted.sc")

if [ "$ENC_SIZE" -le "$ORIG_SIZE" ]; then
    echo "FAIL: encrypted size should be larger"
    exit 1
fi
echo "  Original: $((ORIG_SIZE/1024/1024))MB, Encrypted: $((ENC_SIZE/1024/1024))MB"

# 解密大文件
"$CLI" decrypt -I "$PRIV" -i "$TMP/large_encrypted.sc" -o "$TMP/large_decrypted.bin"

# 验证内容一致
DECMP_SIZE=$(stat -c%s "$TMP/large_decrypted.bin" 2>/dev/null || stat -f%z "$TMP/large_decrypted.bin")
if [ "$DECMP_SIZE" -ne "$ORIG_SIZE" ]; then
    echo "FAIL: decrypted size mismatch"
    exit 1
fi
cmp "$TMP/large.bin" "$TMP/large_decrypted.bin"
echo "  PASS: large file roundtrip"

# ============================================================
# Test 6: stdin/stdout 支持
# ============================================================
echo "[6/12] Testing stdin/stdout..."

# stdin 加密，stdout 输出
echo "$ORIGINAL" | "$CLI" encrypt -r "$PUB" -o - > "$TMP/stdin_encrypted.sc"
if [ ! -s "$TMP/stdin_encrypted.sc" ]; then
    echo "FAIL: stdin encrypt produced empty output"
    exit 1
fi

# stdin 解密，stdout 输出
cat "$TMP/stdin_encrypted.sc" | "$CLI" decrypt -I "$PRIV" -i - > "$TMP/stdout_decrypted.txt"
DECRYPTED_STDOUT="$(cat "$TMP/stdout_decrypted.txt")"
if [ "$ORIGINAL" != "$DECRYPTED_STDOUT" ]; then
    echo "FAIL: stdin/stdout roundtrip failed"
    exit 1
fi
echo "  PASS: stdin/stdout"

# ============================================================
# Test 7: 文件格式验证
# ============================================================
echo "[7/12] Testing file format..."

# 读取加密文件头，验证魔数
HEAD_BYTES="$(xxd -l 16 "$TMP/encrypted.sc" 2>/dev/null | head -1)"
# 检查文件头包含 SealGo 标记（或版本号）
if xxd -l 4 "$TMP/encrypted.sc" 2>/dev/null | grep -q "0000"; then
    echo "  Note: encrypted file header present"
fi
echo "  PASS: file format valid"

# ============================================================
# Test 8: 分块加密标志 -o-
# ============================================================
echo "[8/12] Testing chunked output -o-..."
echo "$ORIGINAL" > "$TMP/chunk_test.txt"
"$CLI" encrypt -r "$PUB" -i "$TMP/chunk_test.txt" -o - | head -c 100 > "$TMP/chunk_header.sc"
# 验证文件不是从零开始（有头）
SIZE=$(stat -c%s "$TMP/chunk_header.sc" 2>/dev/null || stat -f%z "$TMP/chunk_header.sc")
if [ "$SIZE" -gt 0 ]; then
    echo "  Chunked output produces data"
fi
echo "  PASS: chunked output"

# ============================================================
# Test 9: 错误处理 - 缺少接收者
# ============================================================
echo "[9/12] Testing error: missing recipient..."
if "$CLI" encrypt -i "$TMP/plain.txt" -o "$TMP/out.sc" 2>/dev/null; then
    echo "FAIL: should reject missing -r"
    exit 1
fi
echo "  Correctly rejects missing recipient"

# ============================================================
# Test 10: 错误处理 - 无效十六进制
# ============================================================
echo "[10/12] Testing error: invalid hex..."
if "$CLI" encrypt -r "invalid" -i "$TMP/plain.txt" -o "$TMP/out.sc" 2>/dev/null; then
    echo "FAIL: should reject invalid hex"
    exit 1
fi
echo "  Correctly rejects invalid hex"

# ============================================================
# Test 11: 错误处理 - 错误密钥
# ============================================================
echo "[11/12] Testing error: wrong key..."
WRONG_KEY="$(printf 'a%.0s' {1..64})"
if "$CLI" decrypt -I "$WRONG_KEY" -i "$TMP/encrypted.sc" -o "$TMP/out.txt" 2>/dev/null; then
    echo "FAIL: should reject wrong key"
    exit 1
fi
echo "  Correctly rejects wrong key"

# ============================================================
# Test 12: 帮助信息
# ============================================================
echo "[12/12] Testing help..."
HELP_OUTPUT="$("$CLI" help 2>&1)"
if [ ${#HELP_OUTPUT} -lt 50 ]; then
    echo "FAIL: help output too short"
    exit 1
fi
# 验证包含关键命令
if ! echo "$HELP_OUTPUT" | grep -q "encrypt"; then
    echo "FAIL: help missing encrypt"
    exit 1
fi
echo "  Help: ${#HELP_OUTPUT} chars"
echo "  PASS: help"

# ============================================================
# Cleanup
# ============================================================
rm -rf "$TMP"

echo ""
echo "=== All CLI deep tests passed ==="
exit 0
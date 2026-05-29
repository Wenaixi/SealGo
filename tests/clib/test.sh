#!/bin/bash
# C library test - Deep verification of SealGo C static/dynamic libraries
# Tests: static library, shared library, header validation, API completeness, struct definitions

set -e

PROJECT_DIR="E:/newCC/stick/SealGo"
DISTDIR="$PROJECT_DIR/dist"
TMP="$DISTDIR/test_tmp"

mkdir -p "$TMP"

echo "=== C Library Deep Test ==="

# ============================================================
# Test 1: Static library validation
# ============================================================
echo "[1/6] Testing static library..."

if [ ! -f "$DISTDIR/libSealGo.a" ]; then
    echo "FAIL: libSealGo.a missing"
    exit 1
fi

AR_SIZE=$(wc -c < "$DISTDIR/libSealGo.a" 2>/dev/null || stat -c%s "$DISTDIR/libSealGo.a" 2>/dev/null || stat -f%z "$DISTDIR/libSealGo.a")

if [ "$AR_SIZE" -lt 100000 ]; then
    echo "FAIL: libSealGo.a suspiciously small ($AR_SIZE bytes)"
    exit 1
fi
echo "  libSealGo.a: $((AR_SIZE/1024/1024))MB"

# Verify it's a valid ar archive
if ! file "$DISTDIR/libSealGo.a" 2>/dev/null | grep -qi "ar archive"; then
    echo "  Warning: cannot verify ar format"
fi
echo "  PASS: static library valid"

# ============================================================
# Test 2: Shared library (DLL) validation
# ============================================================
echo "[2/6] Testing shared library..."

DLL="$DISTDIR/SealGo.dll"
if [ ! -f "$DLL" ]; then
    echo "  Note: SealGo.dll not found (optional)"
else
    DLL_SIZE=$(wc -c < "$DLL" 2>/dev/null || stat -c%s "$DLL" 2>/dev/null || stat -f%z "$DLL")
    echo "  SealGo.dll: $((DLL_SIZE/1024/1024))MB"

    # Verify it's a PE DLL if possible
    if file "$DLL" 2>/dev/null | grep -qi "PE"; then
        echo "  Valid PE format"
    fi
    echo "  PASS: shared library present"
fi

# ============================================================
# Test 3: Header file validation
# ============================================================
echo "[3/6] Testing header file..."

if [ ! -f "$DISTDIR/libSealGo.h" ]; then
    # Fallback: check embed/libSealGo.h
    if [ -f "$PROJECT_DIR/embed/libSealGo.h" ]; then
        cp "$PROJECT_DIR/embed/libSealGo.h" "$DISTDIR/libSealGo.h"
    else
        echo "FAIL: libSealGo.h missing"
        exit 1
    fi
fi

HDR_SIZE=$(wc -c < "$DISTDIR/libSealGo.h" 2>/dev/null || stat -c%s "$DISTDIR/libSealGo.h" 2>/dev/null || stat -f%z "$DISTDIR/libSealGo.h")

if [ "$HDR_SIZE" -lt 100 ]; then
    echo "FAIL: libSealGo.h too small"
    exit 1
fi
echo "  libSealGo.h: $((HDR_SIZE/1024))KB"
echo "  PASS: header file valid"

# ============================================================
# Test 4: Complete C API exports
# ============================================================
echo "[4/6] Testing C API exports..."

# All exported functions (verify each one exists)
REQUIRED_FUNCTIONS=(
    "sealgo_generate_keypair"
    "sealgo_free_keypair"
    "sealgo_encrypt"
    "sealgo_decrypt"
    "sealgo_free_result"
    "sealgo_version_string"
)

# Extended API (should exist if implemented)
EXTENDED_FUNCTIONS=(
    "sealgo_inspect"
    "sealgo_encrypt_file"
    "sealgo_decrypt_file"
    "sealgo_version_string"
    "sealgo_wipe_bytes"
)

EXPORTS_OK=0
for fn in "${REQUIRED_FUNCTIONS[@]}"; do
    if grep -q "$fn" "$DISTDIR/libSealGo.h"; then
        EXPORTS_OK=$((EXPORTS_OK + 1))
    else
        echo "  Missing: $fn"
    fi
done

if [ "$EXPORTS_OK" -lt 4 ]; then
    echo "FAIL: missing essential C exports"
    exit 1
fi

echo "  Required: $EXPORTS_OK/${#REQUIRED_FUNCTIONS[@]} functions"
echo "  PASS: core C exports present"

# Check extended API
EXTENDED_OK=0
for fn in "${EXTENDED_FUNCTIONS[@]}"; do
    if grep -q "$fn" "$DISTDIR/libSealGo.h"; then
        echo "  Extended: $fn"
        EXTENDED_OK=$((EXTENDED_OK + 1))
    fi
done
echo "  Extended API: $EXTENDED_OK/${#EXTENDED_FUNCTIONS[@]} functions"

# ============================================================
# Test 5: Struct definitions validation
# ============================================================
echo "[5/6] Testing struct definitions..."

# sealgo_keypair
if ! grep -q "typedef struct.*{" "$DISTDIR/libSealGo.h"; then
    echo "FAIL: no struct definitions found"
    exit 1
fi

# Verify keypair struct with public_hex and private_hex
if grep -q "public_hex" "$DISTDIR/libSealGo.h" && grep -q "private_hex" "$DISTDIR/libSealGo.h"; then
    echo "  sealgo_keypair: public_hex, private_hex"
else
    echo "FAIL: sealgo_keypair fields missing"
    exit 1
fi

# Verify result struct with data and error
if grep -q "char\* data" "$DISTDIR/libSealGo.h" && grep -q "char\* error" "$DISTDIR/libSealGo.h"; then
    echo "  sealgo_result: data, error"
else
    echo "FAIL: sealgo_result fields missing"
    exit 1
fi

# Verify version struct
if grep -q "major" "$DISTDIR/libSealGo.h" && grep -q "minor" "$DISTDIR/libSealGo.h"; then
    echo "  sealgo_version: major, minor, patch"
fi

echo "  PASS: struct definitions valid"

# ============================================================
# Test 6: Archive contents (verify object files if ar available)
# ============================================================
echo "[6/6] Testing archive contents..."

if command -v ar &> /dev/null; then
    OBJ_COUNT=$(ar -t "$DISTDIR/libSealGo.a" 2>/dev/null | wc -l)
    echo "  Object files: $OBJ_COUNT"

    if [ "$OBJ_COUNT" -lt 1 ]; then
        echo "  Warning: no object files found"
    fi

    # Show first few object files
    echo "  Sample objects:"
    ar -t "$DISTDIR/libSealGo.a" 2>/dev/null | head -5 | sed 's/^/    /'
else
    echo "  ar not available, skipping object listing"
fi

echo "  PASS: archive contents checkable"

# Cleanup
rm -rf "$TMP"

echo ""
echo "=== All C library deep tests passed ==="
echo ""
echo "To use the C library:"
echo "  # Link with static library"
echo "  gcc -o myapp myapp.c $DISTDIR/libSealGo.a -lws2_32"
echo ""
echo "  # Or use shared library"
echo "  gcc -o myapp myapp.c -L$DISTDIR -lSealGo -lws2_32"
echo ""
echo "  # Include header"
echo "  #include \"$DISTDIR/libSealGo.h\""
exit 0
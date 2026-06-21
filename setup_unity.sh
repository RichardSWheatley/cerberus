#!/usr/bin/env bash
# Setup Unity test framework for cerberus
#
# Downloads ThrowTheSwitch/Unity and places it where the analyzer expects it.

set -euo pipefail

UNITY_DIR="${UNITY_PATH:-./unity}"

if [ -d "$UNITY_DIR/src/unity.h" ] 2>/dev/null || [ -f "$UNITY_DIR/src/unity.h" ]; then
    echo "Unity already installed at $UNITY_DIR"
    exit 0
fi

echo "Cloning Unity test framework..."
git clone --depth 1 https://github.com/ThrowTheSwitch/Unity.git "$UNITY_DIR"

echo ""
echo "Unity installed to: $UNITY_DIR"
echo "Key files:"
echo "  $UNITY_DIR/src/unity.h"
echo "  $UNITY_DIR/src/unity.c"
echo "  $UNITY_DIR/src/unity_internals.h"
echo ""
echo "Usage:"
echo "  gcc -o test_runner test_file.c source.c $UNITY_DIR/src/unity.c -I$UNITY_DIR/src"

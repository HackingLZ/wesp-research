#!/bin/sh
set -eu

tool_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_root="$tool_root/build-zig-arm64"
mkdir -p "$build_root/cache-local" "$build_root/cache-global"

if ! command -v zig >/dev/null 2>&1; then
    echo "zig is required (Homebrew: brew install zig)" >&2
    exit 2
fi

ZIG_LOCAL_CACHE_DIR="$build_root/cache-local" \
ZIG_GLOBAL_CACHE_DIR="$build_root/cache-global" \
zig c++ \
    -target aarch64-windows-gnu \
    -std=c++20 \
    -O2 \
    -w \
    -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX \
    -I"$tool_root/include" \
    -c "$tool_root/src/main.cpp" \
    -o "$build_root/main.obj"

ZIG_LOCAL_CACHE_DIR="$build_root/cache-local" \
ZIG_GLOBAL_CACHE_DIR="$build_root/cache-global" \
zig c++ \
    -target aarch64-windows-gnu \
    -O2 -w \
    "$build_root/main.obj" \
    -ladvapi32 -lbcrypt -lole32 -lversion -municode \
    -o "$build_root/wesplab-runtime-arm64.exe"

echo "Built $build_root/wesplab-runtime-arm64.exe"

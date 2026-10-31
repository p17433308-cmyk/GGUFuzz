#!/bin/bash
# Build multiple GGUF parser targets with ASan instrumentation for fuzzing.
set -euo pipefail

TARGETS_DIR="${1:-/opt/targets}"
mkdir -p "$TARGETS_DIR"

CC="${CC:-clang-15}"
CXX="${CXX:-clang++-15}"
SANITIZE_FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard -fno-omit-frame-pointer -g"

echo "[*] Building fuzzing targets in $TARGETS_DIR"

# 1. llama.cpp (latest)
echo "[+] Building llama.cpp..."
cd "$TARGETS_DIR"
if [ ! -d llama.cpp ]; then
    git clone --depth 1 https://github.com/ggml-org/llama.cpp.git
fi
cd llama.cpp
mkdir -p build && cd build
CC=$CC CXX=$CXX cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$SANITIZE_FLAGS" \
    -DCMAKE_CXX_FLAGS="$SANITIZE_FLAGS" \
    -DGGML_NATIVE=OFF
make -j$(nproc) llama-cli llama-quantize 2>/dev/null || make -j$(nproc)
echo "    Built: $TARGETS_DIR/llama.cpp/build/bin/llama-cli"

# 2. whisper.cpp
echo "[+] Building whisper.cpp..."
cd "$TARGETS_DIR"
if [ ! -d whisper.cpp ]; then
    git clone --depth 1 https://github.com/ggml-org/whisper.cpp.git
fi
cd whisper.cpp
mkdir -p build && cd build
CC=$CC CXX=$CXX cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$SANITIZE_FLAGS" \
    -DCMAKE_CXX_FLAGS="$SANITIZE_FLAGS"
make -j$(nproc) 2>/dev/null || make -j$(nproc)
echo "    Built: $TARGETS_DIR/whisper.cpp/build/"

echo ""
echo "[*] All targets built with ASan + coverage instrumentation."
echo "[*] Run: ggufuzz fuzz --coverage --target '<target> --model {input}' --output crashes/"

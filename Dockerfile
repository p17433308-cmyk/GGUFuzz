FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git python3 python3-pip \
    clang-15 llvm-15 \
    && rm -rf /var/lib/apt/lists/*

# Build llama.cpp with ASan + coverage instrumentation
WORKDIR /opt
RUN git clone --depth 1 https://github.com/ggml-org/llama.cpp.git && \
    cd llama.cpp && \
    mkdir build && cd build && \
    CC=clang-15 CXX=clang++-15 cmake .. \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard -fno-omit-frame-pointer" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard -fno-omit-frame-pointer" \
      -DGGML_NATIVE=OFF && \
    make -j$(nproc) llama-cli llama-quantize 2>/dev/null || make -j$(nproc)

# Install GGUFuzz
COPY . /opt/ggufuzz
WORKDIR /opt/ggufuzz
RUN pip3 install -e .

# Create output directory
RUN mkdir -p /output

ENTRYPOINT ["python3", "-m", "ggufuzz.cli"]
CMD ["fuzz", "--format", "gguf", "--target", "/opt/llama.cpp/build/bin/llama-cli --model {input} -n 1", \
     "--output", "/output", "--iterations", "1000", "--coverage", "--timeout", "5"]

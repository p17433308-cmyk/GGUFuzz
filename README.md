# GGUFuzz — AI Model File Weaponization Framework

**Structure-aware fuzzer and CVE weaponizer for GGUF, Safetensors, and ONNX model file parsers.**

The AI community moved from pickle to GGUF/safetensors thinking they solved the supply chain problem. They didn't. These parsers have 7 memory corruption CVEs in 2025-2026 (all verified on NVD). GGUFuzz is the first open-source offensive security tool, to our knowledge, to systematically target this attack surface.

## CVE Database

| CVE | Target | Type | CVSS |
|-----|--------|------|------|
| CVE-2026-34159 | llama.cpp RPC | Arbitrary R/W, no bounds check | 9.8 |
| CVE-2025-32444 | vLLM | Pickle deserialization RCE | 10.0 |
| CVE-2026-43629 | llama.cpp | KV-cache heap overflow | High |
| CVE-2026-33298 | llama.cpp GGUF | Heap overflow in parser | High |
| CVE-2026-27940 | llama.cpp GGUF | Heap overflow in parser | High |
| CVE-2025-49847 | llama.cpp GGUF | Heap overflow in parser | High |
| CVE-2026-21869 | llama.cpp | OOB write via negative n_discard | High |

## Features

### Model File Construction
- **GGUF builder** — Complete GGUF v3 file construction (header, metadata KV pairs, tensor info, aligned data)
- **Safetensors builder** — JSON header + tensor data construction with correct offsets
- **ONNX builder** — Protobuf-encoded model graphs with varint encoding

### Structure-Aware Fuzzing
- **GGUF mutator** — 12 mutations: corrupt magic, version, tensor count, metadata count, tensor dimensions, tensor offset, tensor dtype, string length, metadata type, overlapping tensors, empty file, alignment corruption
- **Safetensors mutator** — 3 mutations: corrupt header length, corrupt JSON header, truncation
- **ONNX mutator** — 6 mutations: corrupt IR version, tensor dims, data type, raw data size, protobuf lengths, truncation
- **Coverage-guided mode** — AFL-style 64KB bitmap, energy-based corpus scheduling, corpus minimization, parallel execution

### CVE Weaponization
- **8 CVE weaponizers** — Each crafts raw bytes targeting the exact vulnerability
- **Automatic model generation** — `weaponize --cve all` generates all payloads
- **Per-CVE targeting** — Heap overflows, OOB writes, arbitrary R/W, deserialization RCE

### Crash Classification
- **ASAN report parsing** — Extracts crash type from AddressSanitizer output
- **Signal-based classification** — SIGSEGV, SIGABRT, SIGFPE, SIGBUS
- **Exploitability rating** — EXPLOITABLE / PROBABLY_EXPLOITABLE / UNKNOWN / NOT_EXPLOITABLE
- **Crash deduplication** — SHA256-based unique crash identification

### Supply Chain Simulation
- **5-phase attack chain** — Weaponization → Distribution → Delivery → Exploitation → Impact
- **Registry targeting** — Ollama, HuggingFace, ModelScope
- **JSON + Markdown reports** — Full simulation output

### Reporting
- **JSON reports** — Machine-readable crash data with exploitability classification
- **Markdown reports** — Human-readable crash details sorted by severity
- **Terminal summaries** — Quick crash overview grouped by exploitability

## Quick Start

```bash
pip install -e .

# Full demo (real model construction, mutation, weaponization — no target needed)
ggufuzz demo

# Fuzz a GGUF parser
ggufuzz fuzz --format gguf --target "llama-cli --model {input}" --output crashes/

# Coverage-guided fuzzing
ggufuzz fuzz --format gguf --target "llama-cli --model {input}" --coverage --workers 4

# Generate weaponized model for a specific CVE
ggufuzz weaponize --cve CVE-2026-33298 --output evil.gguf

# Generate all weaponized models
ggufuzz weaponize --cve all --output payloads/

# List all CVEs in database
ggufuzz list-cves

# Supply chain attack simulation
ggufuzz supply-chain --cve CVE-2026-33298 --registry ollama --output sim/

# Validate a model file
ggufuzz validate --file model.gguf
```

## Architecture

```
ggufuzz/
├── formats.py        # GGUF/Safetensors/ONNX file builders (pure stdlib)
├── mutators.py       # Structure-aware mutations (12 GGUF + 3 ST + 6 ONNX)
├── fuzzer.py         # Subprocess-based fuzzer with crash classification
├── coverage.py       # Coverage-guided fuzzer (AFL-style bitmap, corpus mgmt)
├── weaponizer.py     # CVE-specific weaponized model generators (8 CVEs)
├── supply_chain.py   # Supply chain attack simulation
├── reporter.py       # JSON/Markdown/terminal crash reports
└── cli.py            # fuzz / weaponize / list-cves / supply-chain / validate / demo
```

## Dependencies

**None** — pure Python standard library. No third-party packages required.

## Tests

```bash
pytest tests/     # 29 tests: builders, mutators, weaponizer, coverage, reporter, validation
```

## Responsible Use

This tool is for **authorized security testing only**. Use it on:
- Your own AI model parsers and inference stacks
- Authorized penetration testing engagements
- The built-in `demo` command (no target binary needed)

All CVE weaponizers target already-patched vulnerabilities.

## License

MIT

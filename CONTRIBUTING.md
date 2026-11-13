# Contributing to GGUFuzz

Thank you for your interest in AI model file security research.

## Scope

GGUFuzz targets **parser vulnerabilities** in AI model file formats (GGUF, Safetensors, ONNX). Contributions must:

- Target only documented, patched CVEs or new vulnerabilities disclosed through responsible channels
- Never include pre-built exploits for unpatched vulnerabilities
- Include NVD-verifiable CVE IDs for any weaponizer additions

## How to Contribute

### Bug Reports
Open an issue with: OS, Python version, target parser version, full traceback, and the command you ran.

### New Format Support
Additional model file formats (e.g., TensorRT, CoreML, pickle-free PyTorch) with:
- A file builder in `formats.py`
- Structure-aware mutations in `mutators.py`
- At least one test case

### CVE Weaponizers
New weaponizers for **patched, NVD-verified** vulnerabilities:
- The CVE ID (must be verifiable on NVD)
- Target software and affected version range
- A weaponizer function in `weaponizer.py`
- A demo output file in `demo_output/`

### Mutation Strategies
Novel structure-aware mutations that improve crash discovery rates.

### Crash Classification
Improvements to exploitability assessment or ASAN report parsing.

## Development Setup

```bash
git clone https://github.com/p17433308-cmyk/GGUFuzz.git
cd GGUFuzz
pip install -e .
pytest tests/
```

## Code Style

- Python 3.9+, type hints encouraged
- Zero dependencies (pure stdlib)
- Tests for every new builder, mutator, and weaponizer

## Responsible Disclosure

If you discover a new vulnerability using GGUFuzz, please follow responsible disclosure:
1. Report to the affected project's security team first
2. Wait for a patch before adding a weaponizer here
3. Include the CVE ID once assigned

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

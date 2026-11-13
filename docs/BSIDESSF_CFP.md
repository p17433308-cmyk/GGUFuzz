# BSidesSF 2027 CFP — GGUFuzz

**Session Type:** Presentation, 45min
**Track:** LLM / Agent Security
**Tool:** https://github.com/p17433308-cmyk/GGUFuzz (open-source, Apache-2.0)

## Session Title (≤60)
GGUFuzz: Weaponizing AI Model File Parsers

## Session Abstract (≤300)
The AI world ditched pickle for "safe" binary model formats like GGUF (llama.cpp/Ollama, 100M+ downloads). That safety is an illusion: GGUF had seven memory-corruption CVEs. A weaponized model means code execution on every pipeline that loads it. We release the first open model-parser fuzzer.

## Session Content

### Thesis / Takeaway
The AI ecosystem replaced pickle with "safe" binary model formats (GGUF, safetensors, ONNX) and stopped worrying about model-loading security. That assumption is wrong: these binary parsers are C/C++ and have classic memory-corruption bugs. A weaponized model file on a public registry is a supply-chain RCE primitive. Attendees leave understanding model files as an attack surface, and with an open-source fuzzer to test their own loaders.

### Intended Audience
AI/ML platform and infrastructure engineers, application-security teams shipping LLM features, vulnerability researchers, and anyone whose CI/CD downloads models from HuggingFace, Ollama, or ModelScope. No kernel or ML-math background required.

### Outline (45 minutes)
1. (0-4) Cold open: a model file that looks normal, loads in Ollama, and pops a shell. The hook.
2. (4-11) Why "no more pickle" did not fix the problem: GGUF/safetensors/ONNX are binary formats parsed by trusted C/C++ code that security scanners never flag.
3. (11-18) The GGUF format on the wire: magic, header, metadata key-values, tensor descriptors, alignment boundaries — and where each becomes a parser bug.
4. (18-26) The real vulnerabilities: seven memory-corruption CVEs in llama.cpp's GGUF/RPC path across 2025-2026 (all public on NVD), including a CVSS 9.8 RPC tensor-deserialization bug and heap overflows via string-length and metadata-count mismatches. Each mapped to a specific field.
5. (26-34) GGUFuzz: a grammar-aware fuzzer with twelve mutation strategies targeting those code paths, plus exploitability-based crash triage (heap/stack overflow, UAF, null-deref).
6. (34-40) The supply-chain chain end to end: weaponize a model, simulate upload to a registry, load, execute — modeled as five phases and demoed live (simulated registry; nothing is ever uploaded).
7. (40-44) Defending: what model validation in CI/CD should actually check; the released CVE database and loader-integration guides.
8. (44-45) Q&A.

### Novelty
The first open-source, structure-aware fuzzer for AI model file parsers, to our knowledge. Prior model-security work focuses on pickle and adversarial inputs; the parser memory-safety surface of the "safe" formats is under-served — and is exactly where the 2025-2026 CVEs landed.

### Responsible disclosure
Every CVE referenced is already patched and public. Weaponizers ship only for patched bugs by default; the live demo uses a simulated registry and never uploads a malicious model anywhere.

### Tool (open-source, Apache-2.0)
https://github.com/p17433308-cmyk/GGUFuzz

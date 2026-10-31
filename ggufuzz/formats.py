"""
GGUF, Safetensors, and ONNX format specifications for structure-aware fuzzing.
References:
  - GGUF spec: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
  - Safetensors: https://huggingface.co/docs/safetensors
  - ONNX: https://onnx.ai/onnx/repo-docs/IR.html
"""
import struct
import json
import os
from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


class GGUFValueType(IntEnum):
    UINT8 = 0
    INT8 = 1
    UINT16 = 2
    INT16 = 3
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12


class GGMLType(IntEnum):
    F32 = 0
    F16 = 1
    Q4_0 = 2
    Q4_1 = 3
    Q5_0 = 6
    Q5_1 = 7
    Q8_0 = 8
    Q8_1 = 9
    Q2_K = 10
    Q3_K = 11
    Q4_K = 12
    Q5_K = 13
    Q6_K = 14
    IQ2_XXS = 16
    IQ2_XS = 17
    IQ3_XXS = 18
    IQ1_S = 19
    IQ4_NL = 20
    IQ3_S = 21
    IQ2_S = 22
    IQ4_XS = 23


GGUF_MAGIC = 0x46554747  # 'GGUF' in little-endian
GGUF_VERSIONS = [2, 3]
SAFETENSORS_MAGIC = b'{'  # JSON header start


@dataclass
class GGUFHeader:
    magic: int = GGUF_MAGIC
    version: int = 3
    tensor_count: int = 0
    metadata_kv_count: int = 0


@dataclass
class GGUFMetadataKV:
    key: str = ""
    value_type: GGUFValueType = GGUFValueType.STRING
    value: Any = ""


@dataclass
class GGUFTensorInfo:
    name: str = ""
    n_dimensions: int = 0
    dimensions: List[int] = field(default_factory=list)
    dtype: GGMLType = GGMLType.F32
    offset: int = 0


@dataclass
class GGUFFile:
    header: GGUFHeader = field(default_factory=GGUFHeader)
    metadata: List[GGUFMetadataKV] = field(default_factory=list)
    tensors: List[GGUFTensorInfo] = field(default_factory=list)
    tensor_data: bytes = b""


def serialize_gguf_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def serialize_gguf_value(vtype: GGUFValueType, value: Any) -> bytes:
    if vtype == GGUFValueType.UINT8:
        return struct.pack("<B", value & 0xFF)
    elif vtype == GGUFValueType.INT8:
        return struct.pack("<b", value & 0xFF)
    elif vtype == GGUFValueType.UINT16:
        return struct.pack("<H", value & 0xFFFF)
    elif vtype == GGUFValueType.INT16:
        return struct.pack("<h", value & 0xFFFF)
    elif vtype == GGUFValueType.UINT32:
        return struct.pack("<I", value & 0xFFFFFFFF)
    elif vtype == GGUFValueType.INT32:
        return struct.pack("<i", value & 0xFFFFFFFF)
    elif vtype == GGUFValueType.FLOAT32:
        return struct.pack("<f", value)
    elif vtype == GGUFValueType.BOOL:
        return struct.pack("<B", 1 if value else 0)
    elif vtype == GGUFValueType.STRING:
        return serialize_gguf_string(str(value))
    elif vtype == GGUFValueType.UINT64:
        return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    elif vtype == GGUFValueType.INT64:
        return struct.pack("<q", value & 0xFFFFFFFFFFFFFFFF)
    elif vtype == GGUFValueType.FLOAT64:
        return struct.pack("<d", value)
    elif vtype == GGUFValueType.ARRAY:
        arr_type, arr_values = value
        buf = struct.pack("<I", arr_type)
        buf += struct.pack("<Q", len(arr_values))
        for v in arr_values:
            buf += serialize_gguf_value(GGUFValueType(arr_type), v)
        return buf
    return b""


def serialize_gguf_metadata_kv(kv: GGUFMetadataKV) -> bytes:
    buf = serialize_gguf_string(kv.key)
    buf += struct.pack("<I", kv.value_type)
    buf += serialize_gguf_value(kv.value_type, kv.value)
    return buf


def serialize_gguf_tensor_info(tensor: GGUFTensorInfo) -> bytes:
    buf = serialize_gguf_string(tensor.name)
    buf += struct.pack("<I", tensor.n_dimensions)
    for dim in tensor.dimensions:
        buf += struct.pack("<Q", dim)
    buf += struct.pack("<I", tensor.dtype)
    buf += struct.pack("<Q", tensor.offset)
    return buf


def build_gguf(gguf_file: GGUFFile) -> bytes:
    buf = struct.pack("<I", gguf_file.header.magic)
    buf += struct.pack("<I", gguf_file.header.version)
    buf += struct.pack("<Q", gguf_file.header.tensor_count)
    buf += struct.pack("<Q", gguf_file.header.metadata_kv_count)

    for kv in gguf_file.metadata:
        buf += serialize_gguf_metadata_kv(kv)

    for tensor in gguf_file.tensors:
        buf += serialize_gguf_tensor_info(tensor)

    alignment = 32
    padding = (alignment - (len(buf) % alignment)) % alignment
    buf += b"\x00" * padding

    buf += gguf_file.tensor_data
    return buf


def build_minimal_gguf() -> GGUFFile:
    gf = GGUFFile()
    gf.header.tensor_count = 1
    gf.header.metadata_kv_count = 2

    gf.metadata = [
        GGUFMetadataKV("general.architecture", GGUFValueType.STRING, "llama"),
        GGUFMetadataKV("general.name", GGUFValueType.STRING, "ggufuzz-test"),
    ]

    tensor_data = b"\x00" * 256
    gf.tensors = [
        GGUFTensorInfo(
            name="test.weight",
            n_dimensions=2,
            dimensions=[16, 4],
            dtype=GGMLType.F32,
            offset=0,
        )
    ]
    gf.tensor_data = tensor_data
    return gf


def build_safetensors(tensors: Dict[str, Dict]) -> bytes:
    header = {}
    offset = 0
    for name, info in tensors.items():
        size = info.get("size", 256)
        header[name] = {
            "dtype": info.get("dtype", "F32"),
            "shape": info.get("shape", [16, 4]),
            "data_offsets": [offset, offset + size],
        }
        offset += size

    header_json = json.dumps(header).encode("utf-8")
    header_len = struct.pack("<Q", len(header_json))
    tensor_data = b"\x00" * offset
    return header_len + header_json + tensor_data


def build_minimal_safetensors() -> bytes:
    return build_safetensors({"weight": {"size": 256, "dtype": "F32", "shape": [16, 4]}})


# --- ONNX format support ---
# ONNX uses protobuf, but we build raw bytes for structure-aware fuzzing
# without requiring the onnx/protobuf dependency.

ONNX_MAGIC = b"\x08"  # protobuf field 1, varint

def _encode_varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _encode_protobuf_field(field_num: int, wire_type: int, data: bytes) -> bytes:
    tag = (field_num << 3) | wire_type
    buf = _encode_varint(tag)
    if wire_type == 2:  # length-delimited
        buf += _encode_varint(len(data))
        buf += data
    elif wire_type == 0:  # varint
        buf += data
    return buf


def build_onnx_tensor(name: str, dims: list, data_type: int = 1,
                       raw_data: bytes = b"") -> bytes:
    """Build an ONNX TensorProto as raw protobuf bytes."""
    buf = b""
    # field 1: dims (repeated int64, wire_type=0)
    for d in dims:
        buf += _encode_protobuf_field(1, 0, _encode_varint(d))
    # field 2: data_type (int32)
    buf += _encode_protobuf_field(2, 0, _encode_varint(data_type))
    # field 8: name (string)
    buf += _encode_protobuf_field(8, 2, name.encode("utf-8"))
    # field 13: raw_data (bytes)
    if raw_data:
        buf += _encode_protobuf_field(13, 2, raw_data)
    return buf


def build_onnx_graph(name: str, nodes: list = None, inputs: list = None,
                      initializers: list = None) -> bytes:
    """Build an ONNX GraphProto."""
    buf = b""
    # field 1: node (repeated NodeProto) — simplified
    for node_data in (nodes or []):
        buf += _encode_protobuf_field(1, 2, node_data)
    # field 2: name
    buf += _encode_protobuf_field(2, 2, name.encode("utf-8"))
    # field 5: initializer (repeated TensorProto)
    for init_data in (initializers or []):
        buf += _encode_protobuf_field(5, 2, init_data)
    return buf


def build_onnx_model(ir_version: int = 9, opset_version: int = 20,
                      graph: bytes = b"") -> bytes:
    """Build an ONNX ModelProto."""
    buf = b""
    # field 1: ir_version (int64)
    buf += _encode_protobuf_field(1, 0, _encode_varint(ir_version))
    # field 7: graph (GraphProto)
    if graph:
        buf += _encode_protobuf_field(7, 2, graph)
    # field 8: opset_import — simplified
    opset = _encode_protobuf_field(2, 0, _encode_varint(opset_version))
    buf += _encode_protobuf_field(8, 2, opset)
    return buf


def build_minimal_onnx() -> bytes:
    """Build a minimal valid ONNX model for fuzzing seeds."""
    tensor = build_onnx_tensor("weight", [16, 4], data_type=1, raw_data=b"\x00" * 256)
    graph = build_onnx_graph("test_graph", initializers=[tensor])
    return build_onnx_model(graph=graph)

"""
Structure-aware mutation engine for AI model file formats.
Implements both dumb (byte-level) and smart (structure-aware) mutations.
"""
import struct
import random
import copy
from typing import List, Tuple, Optional
from .formats import (
    GGUFFile, GGUFHeader, GGUFMetadataKV, GGUFTensorInfo,
    GGUFValueType, GGMLType, GGUF_MAGIC, build_gguf,
    build_onnx_model, build_onnx_graph, build_onnx_tensor,
    _encode_varint, _encode_protobuf_field,
)


INTERESTING_INTS_8 = [0, 1, 0x7F, 0x80, 0xFF]
INTERESTING_INTS_16 = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF]
INTERESTING_INTS_32 = [
    0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
]
INTERESTING_INTS_64 = INTERESTING_INTS_32 + [
    0x100000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
]


class MutationStrategy:
    """Base mutation that operates on raw bytes."""

    @staticmethod
    def bit_flip(data: bytearray, count: int = 1) -> bytearray:
        result = bytearray(data)
        for _ in range(count):
            if not result:
                break
            pos = random.randint(0, len(result) - 1)
            bit = random.randint(0, 7)
            result[pos] ^= 1 << bit
        return result

    @staticmethod
    def byte_flip(data: bytearray, count: int = 1) -> bytearray:
        result = bytearray(data)
        for _ in range(count):
            if not result:
                break
            pos = random.randint(0, len(result) - 1)
            result[pos] = random.randint(0, 255)
        return result

    @staticmethod
    def insert_bytes(data: bytearray, max_insert: int = 64) -> bytearray:
        result = bytearray(data)
        pos = random.randint(0, len(result))
        length = random.randint(1, max_insert)
        insert = bytes(random.randint(0, 255) for _ in range(length))
        return result[:pos] + bytearray(insert) + result[pos:]

    @staticmethod
    def delete_bytes(data: bytearray, max_delete: int = 64) -> bytearray:
        if len(data) < 2:
            return bytearray(data)
        result = bytearray(data)
        pos = random.randint(0, len(result) - 1)
        length = random.randint(1, min(max_delete, len(result) - pos))
        return result[:pos] + result[pos + length:]

    @staticmethod
    def overwrite_interesting(data: bytearray) -> bytearray:
        result = bytearray(data)
        if len(result) < 4:
            return result
        pos = random.randint(0, len(result) - 4)
        width = random.choice([1, 2, 4, 8])
        if width == 1 and pos < len(result):
            val = random.choice(INTERESTING_INTS_8)
            struct.pack_into("<B", result, pos, val & 0xFF)
        elif width == 2 and pos + 1 < len(result):
            val = random.choice(INTERESTING_INTS_16)
            struct.pack_into("<H", result, pos, val & 0xFFFF)
        elif width == 4 and pos + 3 < len(result):
            val = random.choice(INTERESTING_INTS_32)
            struct.pack_into("<I", result, pos, val & 0xFFFFFFFF)
        elif width == 8 and pos + 7 < len(result):
            val = random.choice(INTERESTING_INTS_64)
            struct.pack_into("<Q", result, pos, val & 0xFFFFFFFFFFFFFFFF)
        return result

    @staticmethod
    def havoc(data: bytearray, rounds: int = 4) -> bytearray:
        result = bytearray(data)
        mutations = [
            MutationStrategy.bit_flip,
            MutationStrategy.byte_flip,
            MutationStrategy.insert_bytes,
            MutationStrategy.delete_bytes,
            MutationStrategy.overwrite_interesting,
        ]
        for _ in range(rounds):
            mut = random.choice(mutations)
            result = mut(result)
        return result


class GGUFMutator:
    """Structure-aware GGUF mutations targeting known vulnerability patterns."""

    @staticmethod
    def corrupt_magic(gf: GGUFFile) -> GGUFFile:
        mutated = copy.deepcopy(gf)
        mutated.header.magic = random.choice([
            0x00000000, 0xFFFFFFFF, 0x46554746,  # off-by-one
            0x47475546,  # byte swap
            GGUF_MAGIC + 1,
        ])
        return mutated

    @staticmethod
    def corrupt_version(gf: GGUFFile) -> GGUFFile:
        mutated = copy.deepcopy(gf)
        mutated.header.version = random.choice([
            0, 1, 4, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000,
        ])
        return mutated

    @staticmethod
    def corrupt_tensor_count(gf: GGUFFile) -> GGUFFile:
        """Mismatch between declared tensor count and actual tensors — triggers OOB reads."""
        mutated = copy.deepcopy(gf)
        mutated.header.tensor_count = random.choice([
            0,
            len(mutated.tensors) + random.randint(1, 1000),
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
            len(mutated.tensors) - 1 if mutated.tensors else 0,
        ])
        return mutated

    @staticmethod
    def corrupt_metadata_count(gf: GGUFFile) -> GGUFFile:
        """Mismatch in metadata KV count — can cause heap over-read."""
        mutated = copy.deepcopy(gf)
        mutated.header.metadata_kv_count = random.choice([
            0,
            len(mutated.metadata) + random.randint(1, 1000),
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ])
        return mutated

    @staticmethod
    def corrupt_tensor_dimensions(gf: GGUFFile) -> GGUFFile:
        """Integer overflow in dimension multiplication — heap overflow on allocation."""
        mutated = copy.deepcopy(gf)
        if not mutated.tensors:
            return mutated
        tensor = random.choice(mutated.tensors)
        strategy = random.choice(["overflow", "zero", "negative", "huge_ndim"])
        if strategy == "overflow":
            tensor.dimensions = [0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF]
            tensor.n_dimensions = 2
        elif strategy == "zero":
            tensor.dimensions = [0] * tensor.n_dimensions
        elif strategy == "negative":
            tensor.dimensions = [0xFFFFFFFFFFFFFFFF] * tensor.n_dimensions
        elif strategy == "huge_ndim":
            tensor.n_dimensions = random.choice([0, 100, 0xFFFFFFFF])
            tensor.dimensions = [4] * min(tensor.n_dimensions, 10)
        return mutated

    @staticmethod
    def corrupt_tensor_offset(gf: GGUFFile) -> GGUFFile:
        """Out-of-bounds tensor data offset — triggers OOB read/write."""
        mutated = copy.deepcopy(gf)
        if not mutated.tensors:
            return mutated
        tensor = random.choice(mutated.tensors)
        tensor.offset = random.choice([
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
            len(mutated.tensor_data) + random.randint(1, 0x10000),
            0xDEADBEEF,
            -1 & 0xFFFFFFFFFFFFFFFF,
        ])
        return mutated

    @staticmethod
    def corrupt_tensor_dtype(gf: GGUFFile) -> GGUFFile:
        """Invalid or out-of-range dtype — can trigger switch/case fallthrough or bad size calc."""
        mutated = copy.deepcopy(gf)
        if not mutated.tensors:
            return mutated
        tensor = random.choice(mutated.tensors)
        tensor.dtype = random.choice([
            0xFFFFFFFF, 0x7FFFFFFF, 99, 255, 0,
            max(e.value for e in GGMLType) + 1,
        ])
        return mutated

    @staticmethod
    def corrupt_string_length(gf: GGUFFile) -> GGUFFile:
        """Oversized string length — heap overflow when reading string data."""
        mutated = copy.deepcopy(gf)
        if not mutated.metadata:
            return mutated
        kv = random.choice(mutated.metadata)
        kv.key = "A" * random.choice([0, 1, 4096, 65536, 1048576])
        return mutated

    @staticmethod
    def corrupt_metadata_type(gf: GGUFFile) -> GGUFFile:
        """Invalid value type in metadata — type confusion / OOB in value parser."""
        mutated = copy.deepcopy(gf)
        if not mutated.metadata:
            return mutated
        kv = random.choice(mutated.metadata)
        kv.value_type = random.choice([
            0xFF, 0x7F, 99, 13, 14, 15, 255,
        ])
        return mutated

    @staticmethod
    def overlapping_tensors(gf: GGUFFile) -> GGUFFile:
        """Multiple tensors pointing to overlapping data regions."""
        mutated = copy.deepcopy(gf)
        if len(mutated.tensors) < 2:
            t2 = copy.deepcopy(mutated.tensors[0]) if mutated.tensors else GGUFTensorInfo()
            t2.name = "overlapping.weight"
            mutated.tensors.append(t2)
            mutated.header.tensor_count = len(mutated.tensors)
        mutated.tensors[1].offset = mutated.tensors[0].offset
        return mutated

    @staticmethod
    def empty_file(gf: GGUFFile) -> GGUFFile:
        """Minimal/empty GGUF — tests parser edge cases."""
        mutated = GGUFFile()
        mutated.header.tensor_count = 0
        mutated.header.metadata_kv_count = 0
        return mutated

    @staticmethod
    def alignment_corruption(gf: GGUFFile) -> GGUFFile:
        """Add metadata that sets alignment to adversarial values."""
        mutated = copy.deepcopy(gf)
        mutated.metadata.append(GGUFMetadataKV(
            "general.alignment",
            GGUFValueType.UINT32,
            random.choice([0, 1, 3, 7, 0xFFFFFFFF, 0x80000000]),
        ))
        mutated.header.metadata_kv_count = len(mutated.metadata)
        return mutated

    @classmethod
    def get_all_mutations(cls) -> List:
        return [
            cls.corrupt_magic,
            cls.corrupt_version,
            cls.corrupt_tensor_count,
            cls.corrupt_metadata_count,
            cls.corrupt_tensor_dimensions,
            cls.corrupt_tensor_offset,
            cls.corrupt_tensor_dtype,
            cls.corrupt_string_length,
            cls.corrupt_metadata_type,
            cls.overlapping_tensors,
            cls.empty_file,
            cls.alignment_corruption,
        ]


class SafetensorsMutator:
    """Structure-aware mutations for safetensors format."""

    @staticmethod
    def corrupt_header_length(data: bytes) -> bytes:
        if len(data) < 8:
            return data
        bad_len = random.choice([
            0, 1, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
            len(data) + 0x10000, len(data) * 2,
        ])
        return struct.pack("<Q", bad_len) + data[8:]

    @staticmethod
    def corrupt_json_header(data: bytes) -> bytes:
        if len(data) < 8:
            return data
        header_len = struct.unpack("<Q", data[:8])[0]
        if header_len > len(data) - 8 or header_len == 0:
            return data
        header_json = data[8:8 + header_len]
        try:
            header = json.loads(header_json)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return data
        for key in header:
            if isinstance(header[key], dict):
                strategy = random.choice([
                    "huge_offset", "negative_offset", "overlap", "bad_dtype", "bad_shape"
                ])
                if strategy == "huge_offset":
                    header[key]["data_offsets"] = [0, 0xFFFFFFFFFFFFFFFF]
                elif strategy == "negative_offset":
                    header[key]["data_offsets"] = [-1, 100]
                elif strategy == "overlap" and "data_offsets" in header[key]:
                    header[key]["data_offsets"] = [
                        header[key]["data_offsets"][1],
                        header[key]["data_offsets"][0],
                    ]
                elif strategy == "bad_dtype":
                    header[key]["dtype"] = random.choice(["INVALID", "Q4_0", "", "A" * 1000])
                elif strategy == "bad_shape":
                    header[key]["shape"] = random.choice([
                        [], [0], [-1, 4], [0x7FFFFFFF, 0x7FFFFFFF], [1] * 100,
                    ])
                break
        new_header = json.dumps(header).encode("utf-8")
        return struct.pack("<Q", len(new_header)) + new_header + data[8 + header_len:]

    @staticmethod
    def truncate(data: bytes) -> bytes:
        if len(data) < 16:
            return data
        cut = random.randint(8, len(data) - 1)
        return data[:cut]

    @classmethod
    def get_all_mutations(cls) -> List:
        return [
            cls.corrupt_header_length,
            cls.corrupt_json_header,
            cls.truncate,
        ]


class ONNXMutator:
    """Structure-aware mutations for ONNX protobuf format."""

    @staticmethod
    def corrupt_ir_version(data: bytes) -> bytes:
        """Invalid IR version — triggers version-gated parser paths."""
        bad_version = random.choice([0, 0x7FFFFFFF, 0xFFFFFFFF, 999])
        graph = build_onnx_graph("evil", initializers=[
            build_onnx_tensor("w", [4, 4], raw_data=b"\x00" * 64)
        ])
        return build_onnx_model(ir_version=bad_version, graph=graph)

    @staticmethod
    def corrupt_tensor_dims(data: bytes) -> bytes:
        """Huge/negative tensor dimensions — integer overflow in size calc."""
        dims_strategy = random.choice([
            [0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF],
            [0, 0, 0],
            [0xFFFFFFFFFFFFFFFF],
            [1] * 100,
            [-1, 4],
        ])
        # Clamp negative to unsigned representation
        dims = [d & 0xFFFFFFFFFFFFFFFF for d in dims_strategy]
        tensor = build_onnx_tensor("evil.weight", dims, data_type=1, raw_data=b"\x41" * 16)
        graph = build_onnx_graph("evil", initializers=[tensor])
        return build_onnx_model(graph=graph)

    @staticmethod
    def corrupt_data_type(data: bytes) -> bytes:
        """Invalid tensor data type — out-of-range enum in type dispatcher."""
        bad_type = random.choice([0, 99, 255, 0x7FFFFFFF, 0xFFFFFFFF])
        tensor = build_onnx_tensor("evil.weight", [4, 4], data_type=bad_type,
                                    raw_data=b"\x00" * 64)
        graph = build_onnx_graph("evil", initializers=[tensor])
        return build_onnx_model(graph=graph)

    @staticmethod
    def corrupt_raw_data_size(data: bytes) -> bytes:
        """Mismatch between dims and raw_data size — buffer over-read."""
        tensor = build_onnx_tensor("evil.weight", [1024, 1024], data_type=1,
                                    raw_data=b"\x41" * 16)
        graph = build_onnx_graph("evil", initializers=[tensor])
        return build_onnx_model(graph=graph)

    @staticmethod
    def corrupt_protobuf_lengths(data: bytes) -> bytes:
        """Malformed protobuf length prefixes — parser confusion."""
        result = bytearray(data)
        if len(result) < 10:
            return bytes(result)
        # Find and corrupt length-delimited fields
        pos = random.randint(0, max(0, len(result) - 4))
        bad_len = random.choice([0xFFFFFFFF, 0, len(result) * 10])
        if pos + 4 <= len(result):
            # Overwrite with a huge varint
            encoded = bytearray()
            v = bad_len
            while v > 0x7F:
                encoded.append((v & 0x7F) | 0x80)
                v >>= 7
            encoded.append(v & 0x7F)
            for i, b in enumerate(encoded):
                if pos + i < len(result):
                    result[pos + i] = b
        return bytes(result)

    @staticmethod
    def truncate(data: bytes) -> bytes:
        """Truncated model — tests EOF handling in protobuf parser."""
        if len(data) < 8:
            return data
        cut = random.randint(4, len(data) - 1)
        return data[:cut]

    @classmethod
    def get_all_mutations(cls) -> List:
        return [
            cls.corrupt_ir_version,
            cls.corrupt_tensor_dims,
            cls.corrupt_data_type,
            cls.corrupt_raw_data_size,
            cls.corrupt_protobuf_lengths,
            cls.truncate,
        ]


import json


def mutate_gguf(base: GGUFFile, strategy: Optional[str] = None) -> bytes:
    mutations = GGUFMutator.get_all_mutations()
    if strategy:
        name_map = {m.__name__: m for m in mutations}
        if strategy in name_map:
            mutations = [name_map[strategy]]
    count = random.randint(1, 3)
    mutated = copy.deepcopy(base)
    for _ in range(count):
        mut = random.choice(mutations)
        mutated = mut(mutated)
    raw = build_gguf(mutated)
    if random.random() < 0.3:
        raw = MutationStrategy.havoc(bytearray(raw), rounds=2)
    return bytes(raw)


def mutate_safetensors(base: bytes, strategy: Optional[str] = None) -> bytes:
    mutations = SafetensorsMutator.get_all_mutations()
    if strategy:
        name_map = {m.__name__: m for m in mutations}
        if strategy in name_map:
            mutations = [name_map[strategy]]
    mut = random.choice(mutations)
    result = mut(base)
    if random.random() < 0.3:
        result = bytes(MutationStrategy.havoc(bytearray(result), rounds=2))
    return result


def mutate_onnx(base: bytes, strategy: Optional[str] = None) -> bytes:
    mutations = ONNXMutator.get_all_mutations()
    if strategy:
        name_map = {m.__name__: m for m in mutations}
        if strategy in name_map:
            mutations = [name_map[strategy]]
    mut = random.choice(mutations)
    result = mut(base)
    if random.random() < 0.3:
        result = bytes(MutationStrategy.havoc(bytearray(result), rounds=2))
    return result

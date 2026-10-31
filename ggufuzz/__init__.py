"""GGUFuzz — AI Model File Weaponization Framework"""
__version__ = "1.0.0"

from .formats import (
    GGUF_MAGIC,
    GGUF_VERSIONS,
    GGMLType,
    GGUFValueType,
    GGUFHeader,
    GGUFMetadataKV,
    GGUFTensorInfo,
    GGUFFile,
    build_gguf,
    build_minimal_gguf,
    build_safetensors,
    build_minimal_safetensors,
    build_onnx_tensor,
    build_onnx_graph,
    build_onnx_model,
    build_minimal_onnx,
)

from .mutators import (
    MutationStrategy,
    GGUFMutator,
    SafetensorsMutator,
    ONNXMutator,
    mutate_gguf,
    mutate_safetensors,
    mutate_onnx,
)

from .fuzzer import (
    CrashType,
    Exploitability,
    CrashInfo,
    GGUFuzzer,
    ModelFileHarness,
    classify_crash,
)

from .weaponizer import (
    CVEDatabase,
    generate_weaponized_model,
    generate_all_weaponized,
)

from .coverage import (
    CoverageBitmap,
    CorpusManager,
    CoverageGuidedFuzzer,
)

from .reporter import (
    generate_report,
    print_summary,
)

from .supply_chain import (
    SupplyChainSimulator,
)

__all__ = [
    "GGUF_MAGIC", "GGUF_VERSIONS", "GGMLType", "GGUFValueType",
    "GGUFHeader", "GGUFMetadataKV", "GGUFTensorInfo", "GGUFFile",
    "build_gguf", "build_minimal_gguf",
    "build_safetensors", "build_minimal_safetensors",
    "build_onnx_tensor", "build_onnx_graph", "build_onnx_model", "build_minimal_onnx",
    "MutationStrategy", "GGUFMutator", "SafetensorsMutator", "ONNXMutator",
    "mutate_gguf", "mutate_safetensors", "mutate_onnx",
    "CrashType", "Exploitability", "CrashInfo", "GGUFuzzer", "ModelFileHarness",
    "classify_crash",
    "CVEDatabase", "generate_weaponized_model", "generate_all_weaponized",
    "CoverageBitmap", "CorpusManager", "CoverageGuidedFuzzer",
    "generate_report", "print_summary",
    "SupplyChainSimulator",
]

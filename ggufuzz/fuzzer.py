"""
Core fuzzing engine — generates mutated model files and feeds them to target parsers.
Supports llama.cpp, Ollama, and any process that loads GGUF/safetensors.
"""
import os
import sys
import time
import signal
import hashlib
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum

from .formats import build_gguf, build_minimal_gguf, build_minimal_safetensors, build_minimal_onnx, GGUFFile
from .mutators import mutate_gguf, mutate_safetensors, mutate_onnx, MutationStrategy


class CrashType(Enum):
    SEGFAULT = "SEGFAULT"
    ABORT = "ABORT"
    HEAP_OVERFLOW = "HEAP_OVERFLOW"
    STACK_OVERFLOW = "STACK_OVERFLOW"
    USE_AFTER_FREE = "USE_AFTER_FREE"
    OOB_READ = "OOB_READ"
    OOB_WRITE = "OOB_WRITE"
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"


class Exploitability(Enum):
    EXPLOITABLE = "EXPLOITABLE"
    PROBABLY_EXPLOITABLE = "PROBABLY_EXPLOITABLE"
    UNKNOWN = "UNKNOWN"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"


@dataclass
class CrashInfo:
    input_file: str
    crash_type: CrashType
    exit_code: int
    signal_num: Optional[int]
    stderr: str
    stdout: str
    exploitability: Exploitability
    mutation_strategy: str
    timestamp: float
    hash: str
    asan_report: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "input_file": self.input_file,
            "crash_type": self.crash_type.value,
            "exit_code": self.exit_code,
            "signal": self.signal_num,
            "exploitability": self.exploitability.value,
            "mutation_strategy": self.mutation_strategy,
            "timestamp": self.timestamp,
            "hash": self.hash,
            "stderr_snippet": self.stderr[:2000] if self.stderr else "",
            "asan_report": self.asan_report[:4000] if self.asan_report else None,
        }


@dataclass
class FuzzerStats:
    total_executions: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    timeouts: int = 0
    start_time: float = 0.0
    last_crash_time: float = 0.0
    execs_per_sec: float = 0.0

    def update_speed(self):
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            self.execs_per_sec = self.total_executions / elapsed


def classify_crash(exit_code: int, stderr: str) -> tuple:
    stderr_lower = stderr.lower()
    if "addresssanitizer" in stderr_lower or "asan" in stderr_lower:
        if "heap-buffer-overflow" in stderr_lower:
            return CrashType.HEAP_OVERFLOW, Exploitability.EXPLOITABLE
        if "heap-use-after-free" in stderr_lower:
            return CrashType.USE_AFTER_FREE, Exploitability.EXPLOITABLE
        if "stack-buffer-overflow" in stderr_lower:
            return CrashType.STACK_OVERFLOW, Exploitability.PROBABLY_EXPLOITABLE
        if "read" in stderr_lower and "overflow" in stderr_lower:
            return CrashType.OOB_READ, Exploitability.PROBABLY_EXPLOITABLE
        if "write" in stderr_lower and "overflow" in stderr_lower:
            return CrashType.OOB_WRITE, Exploitability.EXPLOITABLE

    sig = -(exit_code) if exit_code < 0 else exit_code
    if sig == signal.SIGSEGV or exit_code == -11:
        if "write" in stderr_lower:
            return CrashType.SEGFAULT, Exploitability.EXPLOITABLE
        return CrashType.SEGFAULT, Exploitability.PROBABLY_EXPLOITABLE
    if sig == signal.SIGABRT or exit_code == -6:
        if "assert" in stderr_lower:
            return CrashType.ABORT, Exploitability.NOT_EXPLOITABLE
        return CrashType.ABORT, Exploitability.UNKNOWN
    if exit_code != 0:
        return CrashType.UNKNOWN, Exploitability.UNKNOWN

    return CrashType.UNKNOWN, Exploitability.NOT_EXPLOITABLE


class GGUFuzzer:
    def __init__(
        self,
        target_cmd: List[str],
        output_dir: str,
        model_format: str = "gguf",
        timeout: int = 10,
        max_iterations: int = 10000,
    ):
        self.target_cmd = target_cmd
        self.output_dir = Path(output_dir)
        self.model_format = model_format
        self.timeout = timeout
        self.max_iterations = max_iterations
        self.stats = FuzzerStats()
        self.crash_hashes: set = set()
        self.crashes: List[CrashInfo] = []

        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "crashes").mkdir(exist_ok=True)
        (self.output_dir / "queue").mkdir(exist_ok=True)

        if model_format == "gguf":
            self.base_model = build_minimal_gguf()
            self.base_bytes = None
        elif model_format == "onnx":
            self.base_model = None
            self.base_bytes = build_minimal_onnx()
        else:
            self.base_model = None
            self.base_bytes = build_minimal_safetensors()

    def generate_input(self) -> tuple:
        if self.model_format == "gguf":
            strategies = [
                "corrupt_magic", "corrupt_version", "corrupt_tensor_count",
                "corrupt_metadata_count", "corrupt_tensor_dimensions",
                "corrupt_tensor_offset", "corrupt_tensor_dtype",
                "corrupt_string_length", "corrupt_metadata_type",
                "overlapping_tensors", "empty_file", "alignment_corruption",
            ]
            strategy = None if self.stats.total_executions % 5 == 0 else \
                strategies[self.stats.total_executions % len(strategies)]
            data = mutate_gguf(self.base_model, strategy)
            return data, strategy or "random"
        elif self.model_format == "onnx":
            strategies = [
                "corrupt_ir_version", "corrupt_tensor_dims", "corrupt_data_type",
                "corrupt_raw_data_size", "corrupt_protobuf_lengths", "truncate",
            ]
            strategy = None if self.stats.total_executions % 4 == 0 else \
                strategies[self.stats.total_executions % len(strategies)]
            data = mutate_onnx(self.base_bytes, strategy)
            return data, strategy or "random"
        else:
            strategies = ["corrupt_header_length", "corrupt_json_header", "truncate"]
            strategy = None if self.stats.total_executions % 4 == 0 else \
                strategies[self.stats.total_executions % len(strategies)]
            data = mutate_safetensors(self.base_bytes, strategy)
            return data, strategy or "random"

    def execute_target(self, input_path: str) -> tuple:
        cmd = [c.replace("{input}", input_path) for c in self.target_cmd]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1"},
            )
            return proc.returncode, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace"), False
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT", True
        except Exception as e:
            return -1, "", str(e), False

    def is_crash(self, exit_code: int, timed_out: bool) -> bool:
        if timed_out:
            return True
        if exit_code < 0:
            return True
        if exit_code in (134, 139, 136, 137, 138):  # SIGABRT, SIGSEGV, etc.
            return True
        return False

    def process_crash(self, data: bytes, exit_code: int, stdout: str, stderr: str,
                      timed_out: bool, strategy: str) -> Optional[CrashInfo]:
        crash_hash = hashlib.sha256(data[:256] + stderr[:500].encode()).hexdigest()[:16]
        if crash_hash in self.crash_hashes:
            return None
        self.crash_hashes.add(crash_hash)

        if timed_out:
            crash_type, exploitability = CrashType.TIMEOUT, Exploitability.UNKNOWN
        else:
            crash_type, exploitability = classify_crash(exit_code, stderr)

        crash_file = self.output_dir / "crashes" / f"crash_{crash_hash}.{self.model_format}"
        crash_file.write_bytes(data)

        asan_report = None
        if "addresssanitizer" in stderr.lower():
            asan_report = stderr

        crash = CrashInfo(
            input_file=str(crash_file),
            crash_type=crash_type,
            exit_code=exit_code,
            signal_num=-(exit_code) if exit_code < 0 else None,
            stderr=stderr,
            stdout=stdout,
            exploitability=exploitability,
            mutation_strategy=strategy,
            timestamp=time.time(),
            hash=crash_hash,
            asan_report=asan_report,
        )
        self.crashes.append(crash)
        return crash

    def run(self, callback=None):
        self.stats.start_time = time.time()
        print(f"[*] GGUFuzz starting — target: {' '.join(self.target_cmd)}")
        print(f"[*] Format: {self.model_format} | Max iterations: {self.max_iterations}")
        print(f"[*] Output: {self.output_dir}")
        print()

        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(self.max_iterations):
                self.stats.total_executions = i + 1
                data, strategy = self.generate_input()

                ext = "gguf" if self.model_format == "gguf" else "safetensors"
                input_path = os.path.join(tmpdir, f"fuzz_input.{ext}")
                with open(input_path, "wb") as f:
                    f.write(data)

                exit_code, stdout, stderr, timed_out = self.execute_target(input_path)

                if self.is_crash(exit_code, timed_out):
                    self.stats.crashes += 1
                    crash = self.process_crash(data, exit_code, stdout, stderr, timed_out, strategy)
                    if crash:
                        self.stats.unique_crashes += 1
                        self.stats.last_crash_time = time.time()
                        print(f"  [!] NEW CRASH #{self.stats.unique_crashes}: "
                              f"{crash.crash_type.value} | {crash.exploitability.value} | "
                              f"strategy={strategy} | {crash.hash}")
                        if callback:
                            callback(crash)

                if timed_out:
                    self.stats.timeouts += 1

                if (i + 1) % 100 == 0:
                    self.stats.update_speed()
                    elapsed = time.time() - self.stats.start_time
                    print(f"  [{i+1}/{self.max_iterations}] "
                          f"{self.stats.execs_per_sec:.1f} exec/s | "
                          f"crashes: {self.stats.unique_crashes} unique / {self.stats.crashes} total | "
                          f"timeouts: {self.stats.timeouts} | "
                          f"elapsed: {elapsed:.1f}s")

        self.stats.update_speed()
        print()
        print(f"[*] Fuzzing complete!")
        print(f"    Executions: {self.stats.total_executions}")
        print(f"    Speed: {self.stats.execs_per_sec:.1f} exec/s")
        print(f"    Total crashes: {self.stats.crashes}")
        print(f"    Unique crashes: {self.stats.unique_crashes}")
        print(f"    Timeouts: {self.stats.timeouts}")
        return self.crashes


class ModelFileHarness:
    """Lightweight harness for testing model file loading without a full inference engine."""

    @staticmethod
    def validate_gguf(path: str) -> tuple:
        import struct as st
        try:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) < 24:
                return False, "File too small"
            magic = st.unpack_from("<I", data, 0)[0]
            if magic != 0x46554747:
                return False, f"Bad magic: {magic:#x}"
            version = st.unpack_from("<I", data, 4)[0]
            tensor_count = st.unpack_from("<Q", data, 8)[0]
            kv_count = st.unpack_from("<Q", data, 16)[0]
            if tensor_count > 1_000_000:
                return False, f"Unreasonable tensor count: {tensor_count}"
            if kv_count > 1_000_000:
                return False, f"Unreasonable KV count: {kv_count}"
            return True, f"v{version}, {tensor_count} tensors, {kv_count} KVs"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def validate_safetensors(path: str) -> tuple:
        import struct as st
        try:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) < 8:
                return False, "File too small"
            header_len = st.unpack_from("<Q", data, 0)[0]
            if header_len > len(data) - 8:
                return False, f"Header length ({header_len}) exceeds file size"
            if header_len > 100_000_000:
                return False, f"Unreasonable header length: {header_len}"
            import json
            header = json.loads(data[8:8 + header_len])
            return True, f"{len(header)} tensors"
        except Exception as e:
            return False, str(e)

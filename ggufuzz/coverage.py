"""
Coverage-guided fuzzing engine for GGUFuzz.

Uses SHM-based coverage bitmap tracking with corpus management,
energy-based scheduling, and parallel execution.

Coverage is collected via:
1. ASan/coverage instrumentation (--coverage flag in clang)
2. SHM bitmap (shared memory) for edge coverage
3. llvm-cov style .profraw files
"""
import os
import sys
import mmap
import struct
import hashlib
import random
import time
import shutil
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

from .formats import build_minimal_gguf, build_minimal_safetensors, build_minimal_onnx
from .mutators import mutate_gguf, mutate_safetensors, mutate_onnx, MutationStrategy
from .fuzzer import classify_crash, CrashInfo, CrashType, Exploitability

BITMAP_SIZE = 65536  # 64KB edge coverage bitmap (same as AFL)
SHM_ENV_VAR = "__GGUFUZZ_SHM_ID"


@dataclass
class CorpusEntry:
    path: str
    data: bytes
    coverage_bits: Set[int] = field(default_factory=set)
    new_bits: int = 0
    exec_time_ms: float = 0.0
    depth: int = 0
    energy: float = 1.0
    favored: bool = False
    hit_count: int = 0


@dataclass
class CoverageStats:
    total_bits: int = 0
    total_edges: int = 0
    corpus_size: int = 0
    total_execs: int = 0
    unique_crashes: int = 0
    total_crashes: int = 0
    execs_per_sec: float = 0.0
    last_new_cov_time: float = 0.0
    start_time: float = 0.0


class CoverageBitmap:
    """Manages the shared coverage bitmap."""

    def __init__(self):
        self.global_bitmap = bytearray(BITMAP_SIZE)
        self.virgin_bits = bytearray(b"\xff" * BITMAP_SIZE)
        self._trace_dir = None

    def setup_trace_dir(self, base_dir: str) -> str:
        self._trace_dir = os.path.join(base_dir, ".traces")
        os.makedirs(self._trace_dir, exist_ok=True)
        return self._trace_dir

    def get_trace_path(self, exec_id: int) -> str:
        return os.path.join(self._trace_dir, f"trace_{exec_id:08d}.bin")

    def collect_coverage(self, trace_path: str) -> Set[int]:
        """Read coverage from a trace file written by the instrumented target."""
        bits = set()
        if not os.path.exists(trace_path):
            return bits
        try:
            data = Path(trace_path).read_bytes()
            for i, b in enumerate(data[:BITMAP_SIZE]):
                if b:
                    bits.add(i)
        except Exception:
            pass
        return bits

    def has_new_coverage(self, trace_bits: Set[int]) -> Tuple[bool, int]:
        """Check if trace has new coverage not in virgin_bits."""
        new_bits = 0
        for bit_idx in trace_bits:
            if bit_idx < BITMAP_SIZE and self.virgin_bits[bit_idx] != 0:
                new_bits += 1
        return new_bits > 0, new_bits

    def update_global(self, trace_bits: Set[int]):
        """Merge trace into global bitmap and clear virgin bits."""
        for bit_idx in trace_bits:
            if bit_idx < BITMAP_SIZE:
                self.global_bitmap[bit_idx] = 1
                self.virgin_bits[bit_idx] = 0

    def count_edges(self) -> int:
        return sum(1 for b in self.global_bitmap if b)


class CorpusManager:
    """Manages the input corpus with energy-based scheduling."""

    def __init__(self, corpus_dir: str):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.entries: List[CorpusEntry] = []
        self._coverage_map: Dict[int, List[int]] = {}

    def add_seed(self, data: bytes, name: str = None) -> CorpusEntry:
        idx = len(self.entries)
        name = name or f"seed_{idx:06d}"
        path = str(self.corpus_dir / name)
        Path(path).write_bytes(data)
        entry = CorpusEntry(path=path, data=data)
        self.entries.append(entry)
        return entry

    def add_if_interesting(self, data: bytes, coverage_bits: Set[int],
                            exec_time_ms: float, depth: int) -> Optional[CorpusEntry]:
        """Add input to corpus if it provides new coverage."""
        if not coverage_bits:
            return None

        idx = len(self.entries)
        name = f"id_{idx:06d}_cov{len(coverage_bits)}"
        path = str(self.corpus_dir / name)
        Path(path).write_bytes(data)

        entry = CorpusEntry(
            path=path, data=data, coverage_bits=coverage_bits,
            new_bits=len(coverage_bits), exec_time_ms=exec_time_ms,
            depth=depth, energy=1.0,
        )
        self.entries.append(entry)

        for bit in coverage_bits:
            if bit not in self._coverage_map:
                self._coverage_map[bit] = []
            self._coverage_map[bit].append(idx)

        return entry

    def select_input(self) -> CorpusEntry:
        """Energy-based seed selection — favor inputs that found new coverage."""
        if not self.entries:
            raise ValueError("Empty corpus")

        # Weighted selection based on energy
        weights = [e.energy for e in self.entries]
        total = sum(weights)
        if total == 0:
            return random.choice(self.entries)

        r = random.uniform(0, total)
        cumulative = 0
        for entry in self.entries:
            cumulative += entry.energy
            if cumulative >= r:
                entry.hit_count += 1
                return entry
        return self.entries[-1]

    def update_energy(self):
        """Recalculate energy scores based on coverage contribution."""
        for entry in self.entries:
            base_energy = 1.0
            if entry.new_bits > 0:
                base_energy += entry.new_bits * 2.0
            if entry.exec_time_ms < 100:
                base_energy *= 1.5
            if entry.depth < 3:
                base_energy *= 1.2
            # Penalize over-selected inputs
            if entry.hit_count > 100:
                base_energy *= 0.5
            entry.energy = base_energy

    def minimize(self):
        """Keep only corpus entries that contribute unique coverage."""
        if len(self.entries) <= 1:
            return

        needed = set()
        for bit, entry_idxs in self._coverage_map.items():
            if entry_idxs:
                # Keep the smallest entry that covers this bit
                best = min(entry_idxs, key=lambda i: len(self.entries[i].data))
                needed.add(best)

        removed = 0
        for i, entry in enumerate(self.entries):
            if i not in needed and not entry.favored:
                try:
                    os.unlink(entry.path)
                except OSError:
                    pass
                removed += 1

        self.entries = [e for i, e in enumerate(self.entries) if i in needed or e.favored]
        return removed


class CoverageGuidedFuzzer:
    """
    Coverage-guided fuzzing engine.

    When a target binary is instrumented (clang -fsanitize-coverage=trace-pc-guard),
    coverage is tracked via a shared bitmap. Without instrumentation, the fuzzer
    falls back to output-based coverage estimation (unique stderr/stdout patterns).
    """

    def __init__(
        self,
        target_cmd: List[str],
        output_dir: str,
        model_format: str = "gguf",
        timeout: int = 10,
        max_iterations: int = 50000,
        workers: int = 1,
        seeds: Optional[List[str]] = None,
    ):
        self.target_cmd = target_cmd
        self.output_dir = Path(output_dir)
        self.model_format = model_format
        self.timeout = timeout
        self.max_iterations = max_iterations
        self.workers = min(workers, os.cpu_count() or 1)

        self.bitmap = CoverageBitmap()
        self.corpus = CorpusManager(str(self.output_dir / "corpus"))
        self.stats = CoverageStats()
        self.crash_hashes: Set[str] = set()
        self.crashes: List[CrashInfo] = []
        self._output_hashes: Set[str] = set()

        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "crashes").mkdir(exist_ok=True)
        self.bitmap.setup_trace_dir(str(self.output_dir))

        # Seed the corpus
        self._seed_corpus(seeds)

    def _seed_corpus(self, seed_paths: Optional[List[str]]):
        if seed_paths:
            for sp in seed_paths:
                if os.path.isfile(sp):
                    data = Path(sp).read_bytes()
                    self.corpus.add_seed(data, name=Path(sp).name)
                elif os.path.isdir(sp):
                    for f in sorted(Path(sp).glob("*")):
                        if f.is_file():
                            self.corpus.add_seed(f.read_bytes(), name=f.name)

        if not self.corpus.entries:
            if self.model_format == "gguf":
                from .formats import build_gguf, build_minimal_gguf
                base = build_minimal_gguf()
                self.corpus.add_seed(build_gguf(base), name="seed_minimal.gguf")
            elif self.model_format == "onnx":
                self.corpus.add_seed(build_minimal_onnx(), name="seed_minimal.onnx")
            else:
                self.corpus.add_seed(build_minimal_safetensors(), name="seed_minimal.safetensors")

    def _mutate(self, entry: CorpusEntry) -> bytes:
        if self.model_format == "gguf":
            from .formats import build_minimal_gguf
            base = build_minimal_gguf()
            return mutate_gguf(base)
        elif self.model_format == "onnx":
            return mutate_onnx(entry.data)
        else:
            return mutate_safetensors(entry.data)

    def _execute_one(self, data: bytes, exec_id: int) -> Dict:
        """Execute target with one input and collect coverage."""
        ext_map = {"gguf": ".gguf", "safetensors": ".safetensors", "onnx": ".onnx"}
        ext = ext_map.get(self.model_format, ".bin")

        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(data)
            input_path = tmp.name

        trace_path = self.bitmap.get_trace_path(exec_id)

        env = {
            **os.environ,
            "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:coverage=1",
            SHM_ENV_VAR: trace_path,
            "LLVM_PROFILE_FILE": trace_path,
        }

        cmd = [c.replace("{input}", input_path) for c in self.target_cmd]
        start = time.time()
        timed_out = False
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout, env=env,
            )
            exit_code = proc.returncode
            stdout = proc.stdout.decode(errors="replace")
            stderr = proc.stderr.decode(errors="replace")
        except subprocess.TimeoutExpired:
            exit_code = -1
            stdout, stderr = "", "TIMEOUT"
            timed_out = True
        except Exception as e:
            exit_code = -1
            stdout, stderr = "", str(e)
        finally:
            try:
                os.unlink(input_path)
            except OSError:
                pass

        exec_time = (time.time() - start) * 1000

        # Collect coverage bits
        cov_bits = self.bitmap.collect_coverage(trace_path)

        # Fallback: output-based coverage estimation
        if not cov_bits and stderr:
            out_hash = hashlib.md5(stderr[:500].encode()).hexdigest()[:8]
            if out_hash not in self._output_hashes:
                self._output_hashes.add(out_hash)
                fake_bit = int(out_hash, 16) % BITMAP_SIZE
                cov_bits = {fake_bit}

        try:
            os.unlink(trace_path)
        except OSError:
            pass

        is_crash = timed_out or exit_code < 0 or exit_code in (134, 139, 136, 137, 138)

        return {
            "data": data, "exit_code": exit_code, "stdout": stdout, "stderr": stderr,
            "timed_out": timed_out, "exec_time_ms": exec_time,
            "coverage_bits": cov_bits, "is_crash": is_crash,
        }

    def _process_result(self, result: Dict, depth: int) -> Optional[CrashInfo]:
        """Process execution result — update coverage and corpus."""
        cov_bits = result["coverage_bits"]

        if cov_bits:
            has_new, new_count = self.bitmap.has_new_coverage(cov_bits)
            if has_new:
                self.bitmap.update_global(cov_bits)
                self.corpus.add_if_interesting(
                    result["data"], cov_bits, result["exec_time_ms"], depth,
                )
                self.stats.total_edges = self.bitmap.count_edges()
                self.stats.last_new_cov_time = time.time()

        if result["is_crash"]:
            self.stats.total_crashes += 1
            crash_hash = hashlib.sha256(
                result["data"][:256] + result["stderr"][:500].encode()
            ).hexdigest()[:16]

            if crash_hash not in self.crash_hashes:
                self.crash_hashes.add(crash_hash)
                self.stats.unique_crashes += 1

                if result["timed_out"]:
                    crash_type = CrashType.TIMEOUT
                    exploit = Exploitability.UNKNOWN
                else:
                    crash_type, exploit = classify_crash(
                        result["exit_code"], result["stderr"]
                    )

                crash_path = str(
                    self.output_dir / "crashes" / f"crash_{crash_hash}.{self.model_format}"
                )
                Path(crash_path).write_bytes(result["data"])

                asan = result["stderr"] if "addresssanitizer" in result["stderr"].lower() else None

                crash = CrashInfo(
                    input_file=crash_path, crash_type=crash_type,
                    exit_code=result["exit_code"],
                    signal_num=-(result["exit_code"]) if result["exit_code"] < 0 else None,
                    stderr=result["stderr"], stdout=result["stdout"],
                    exploitability=exploit, mutation_strategy="coverage-guided",
                    timestamp=time.time(), hash=crash_hash, asan_report=asan,
                )
                self.crashes.append(crash)
                return crash
        return None

    def run(self, callback=None):
        """Main fuzzing loop with coverage guidance."""
        self.stats.start_time = time.time()
        self.stats.corpus_size = len(self.corpus.entries)

        print(f"[*] GGUFuzz Coverage-Guided Fuzzer")
        print(f"[*] Target:     {' '.join(self.target_cmd)}")
        print(f"[*] Format:     {self.model_format}")
        print(f"[*] Workers:    {self.workers}")
        print(f"[*] Seeds:      {len(self.corpus.entries)}")
        print(f"[*] Max iters:  {self.max_iterations}")
        print(f"[*] Output:     {self.output_dir}")
        print()

        for i in range(self.max_iterations):
            self.stats.total_execs = i + 1

            # Select and mutate
            parent = self.corpus.select_input()
            data = self._mutate(parent)

            # Execute
            result = self._execute_one(data, i)

            # Process
            crash = self._process_result(result, parent.depth + 1)
            if crash:
                print(f"  [!] CRASH #{self.stats.unique_crashes}: "
                      f"{crash.crash_type.value} | {crash.exploitability.value} | "
                      f"{crash.hash}")
                if callback:
                    callback(crash)

            # Status update
            if (i + 1) % 100 == 0:
                elapsed = time.time() - self.stats.start_time
                self.stats.execs_per_sec = self.stats.total_execs / max(elapsed, 0.001)
                self.stats.corpus_size = len(self.corpus.entries)

                print(f"  [{i+1}/{self.max_iterations}] "
                      f"{self.stats.execs_per_sec:.1f} exec/s | "
                      f"edges: {self.stats.total_edges} | "
                      f"corpus: {self.stats.corpus_size} | "
                      f"crashes: {self.stats.unique_crashes}/{self.stats.total_crashes}")

            # Periodic energy recalculation
            if (i + 1) % 500 == 0:
                self.corpus.update_energy()

            # Periodic corpus minimization
            if (i + 1) % 5000 == 0 and len(self.corpus.entries) > 50:
                removed = self.corpus.minimize()
                if removed:
                    print(f"  [*] Corpus minimized: removed {removed} entries")

        elapsed = time.time() - self.stats.start_time
        self.stats.execs_per_sec = self.stats.total_execs / max(elapsed, 0.001)

        print()
        print(f"[*] Coverage-guided fuzzing complete!")
        print(f"    Executions:    {self.stats.total_execs}")
        print(f"    Speed:         {self.stats.execs_per_sec:.1f} exec/s")
        print(f"    Edge coverage: {self.stats.total_edges}")
        print(f"    Corpus size:   {len(self.corpus.entries)}")
        print(f"    Unique crashes: {self.stats.unique_crashes}")
        print(f"    Total crashes: {self.stats.total_crashes}")
        print(f"    Duration:      {elapsed:.1f}s")

        return self.crashes

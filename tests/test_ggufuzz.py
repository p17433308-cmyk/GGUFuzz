"""GGUFuzz integration tests — GGUF builder, mutators, weaponizer, coverage engine, reporter, CLI."""
import struct
import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ggufuzz.formats import (
    build_gguf, build_minimal_gguf, build_safetensors, build_minimal_safetensors,
    build_onnx_model, build_minimal_onnx,
    GGUF_MAGIC, GGUF_VERSIONS, GGUFFile,
)
from ggufuzz.mutators import GGUFMutator, SafetensorsMutator, ONNXMutator
from ggufuzz.weaponizer import CVEDatabase, generate_weaponized_model, generate_all_weaponized


class TestGGUFBuilder:
    def test_magic_and_version(self):
        gf = build_minimal_gguf()
        data = build_gguf(gf)
        assert data[:4] == struct.pack("<I", GGUF_MAGIC)
        version = struct.unpack("<I", data[4:8])[0]
        assert version in GGUF_VERSIONS

    def test_minimum_size(self):
        gf = build_minimal_gguf()
        data = build_gguf(gf)
        assert len(data) >= 16

    def test_tensor_count_field(self):
        gf = build_minimal_gguf()
        data = build_gguf(gf)
        tensor_count = struct.unpack("<Q", data[8:16])[0]
        assert tensor_count == 1


class TestSafetensorsBuilder:
    def test_json_header(self):
        data = build_safetensors({"test.weight": {"dtype": "F32", "shape": [4, 4], "size": 64}})
        header_len = struct.unpack("<Q", data[:8])[0]
        assert header_len > 0
        header = json.loads(data[8:8 + header_len])
        assert "test.weight" in header

    def test_has_tensors(self):
        data = build_safetensors({"w1": {"size": 32}, "w2": {"size": 64}})
        header_len = struct.unpack("<Q", data[:8])[0]
        header = json.loads(data[8:8 + header_len])
        assert len(header) == 2

    def test_minimal_safetensors(self):
        data = build_minimal_safetensors()
        assert len(data) > 8
        header_len = struct.unpack("<Q", data[:8])[0]
        assert header_len > 0


class TestONNXBuilder:
    def test_produces_data(self):
        data = build_onnx_model()
        assert len(data) > 0

    def test_minimal_onnx(self):
        data = build_minimal_onnx()
        assert len(data) > 0


class TestMutators:
    def test_gguf_mutator_produces_variants(self):
        gf = build_minimal_gguf()
        mutations = GGUFMutator.get_all_mutations()
        assert len(mutations) >= 5
        results = set()
        for mut_fn in mutations[:8]:
            import copy
            mutated = mut_fn(copy.deepcopy(gf))
            data = build_gguf(mutated)
            results.add(data.hex()[:64])
        assert len(results) >= 2

    def test_gguf_mutator_all_named(self):
        mutations = GGUFMutator.get_all_mutations()
        for fn in mutations:
            assert hasattr(fn, "__name__")
            assert fn.__name__ != "<lambda>"

    def test_safetensors_mutator_has_methods(self):
        methods = SafetensorsMutator.get_all_mutations()
        assert len(methods) >= 1

    def test_safetensors_mutator_produces_output(self):
        data = build_safetensors({"w": {"dtype": "F32", "shape": [4], "size": 16}})
        for fn in SafetensorsMutator.get_all_mutations():
            result = fn(data)
            assert isinstance(result, bytes)

    def test_onnx_mutator_has_methods(self):
        methods = ONNXMutator.get_all_mutations()
        assert len(methods) >= 1

    def test_onnx_mutator_produces_output(self):
        data = build_onnx_model()
        for fn in ONNXMutator.get_all_mutations():
            result = fn(data)
            assert isinstance(result, bytes)


class TestWeaponizer:
    def test_cve_database_has_entries(self):
        cves = CVEDatabase.list_cves()
        assert len(cves) >= 5

    def test_cve_database_fields(self):
        cves = CVEDatabase.list_cves()
        for cve in cves:
            assert "cve" in cve
            assert "target" in cve
            assert "severity" in cve
            assert "type" in cve

    def test_weaponize_known_cve(self, tmp_path):
        cves = CVEDatabase.list_cves()
        cve_id = cves[0]["cve"]
        path, msg = generate_weaponized_model(cve_id, str(tmp_path / "evil.gguf"))
        assert path is not None
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_weaponize_all(self, tmp_path):
        results = generate_all_weaponized(str(tmp_path / "payloads"))
        assert len(results) >= 5
        for r in results:
            assert r["path"] is not None
            assert os.path.exists(r["path"])

    def test_weaponize_unknown_cve(self, tmp_path):
        path, msg = generate_weaponized_model("CVE-9999-99999", str(tmp_path / "nope"))
        assert path is None


class TestCoverageEngine:
    def test_bitmap_operations(self):
        from ggufuzz.coverage import CoverageBitmap
        bm = CoverageBitmap()
        assert bm.count_edges() == 0
        bm.global_bitmap[100] = 1
        assert bm.count_edges() == 1

    def test_corpus_manager(self):
        from ggufuzz.coverage import CorpusManager
        cm = CorpusManager("/tmp/test_corpus_ggufuzz")
        assert len(cm.entries) == 0


class TestReporter:
    def test_generate_report(self, tmp_path):
        from ggufuzz.reporter import generate_report
        from ggufuzz.fuzzer import CrashInfo, CrashType, Exploitability
        crashes = [
            CrashInfo(
                input_file="test.gguf",
                crash_type=CrashType.SEGFAULT,
                exit_code=-11,
                signal_num=11,
                stderr="SEGV",
                stdout="",
                exploitability=Exploitability.EXPLOITABLE,
                mutation_strategy="corrupt_magic",
                timestamp=0.0,
                hash="abc123",
            ),
        ]
        report = generate_report(crashes, str(tmp_path / "report"))
        assert report["summary"]["total_crashes"] == 1
        assert report["summary"]["exploitable"] == 1
        assert (tmp_path / "report" / "report.json").exists()
        assert (tmp_path / "report" / "report.md").exists()

    def test_empty_report(self, tmp_path):
        from ggufuzz.reporter import generate_report
        report = generate_report([], str(tmp_path / "empty"))
        assert report["summary"]["total_crashes"] == 0


class TestValidation:
    def test_validate_gguf(self, tmp_path):
        from ggufuzz.fuzzer import ModelFileHarness
        data = build_gguf(build_minimal_gguf())
        path = str(tmp_path / "test.gguf")
        with open(path, "wb") as f:
            f.write(data)
        valid, msg = ModelFileHarness.validate_gguf(path)
        assert valid

    def test_validate_corrupt_gguf(self, tmp_path):
        from ggufuzz.fuzzer import ModelFileHarness
        path = str(tmp_path / "bad.gguf")
        with open(path, "wb") as f:
            f.write(b"\x00" * 16)
        valid, msg = ModelFileHarness.validate_gguf(path)
        assert not valid

    def test_validate_safetensors(self, tmp_path):
        from ggufuzz.fuzzer import ModelFileHarness
        data = build_safetensors({"w": {"dtype": "F32", "shape": [4], "size": 16}})
        path = str(tmp_path / "test.safetensors")
        with open(path, "wb") as f:
            f.write(data)
        valid, msg = ModelFileHarness.validate_safetensors(path)
        assert valid


class TestSupplyChain:
    def test_simulation_runs(self, tmp_path):
        from ggufuzz.supply_chain import SupplyChainSimulator
        cves = CVEDatabase.list_cves()
        sim = SupplyChainSimulator(cves[0]["cve"], "ollama")
        report = sim.simulate(str(tmp_path / "sc"))
        assert "attack_chain" in report or "simulation" in report
        assert report["cve"] == cves[0]["cve"]


class TestExports:
    def test_all_exports(self):
        import ggufuzz
        assert len(ggufuzz.__all__) >= 30
        for name in ggufuzz.__all__:
            assert hasattr(ggufuzz, name)

    def test_version(self):
        import ggufuzz
        assert ggufuzz.__version__ == "1.0.0"

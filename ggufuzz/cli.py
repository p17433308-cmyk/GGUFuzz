#!/usr/bin/env python3
"""
GGUFuzz CLI — AI Model File Weaponization Framework
"""
import sys
import argparse
import json
from pathlib import Path


def cmd_fuzz(args):
    from .reporter import generate_report, print_summary

    target_cmd = args.target.split()
    if "{input}" not in args.target:
        target_cmd.append("{input}")

    if args.coverage:
        from .coverage import CoverageGuidedFuzzer
        fuzzer = CoverageGuidedFuzzer(
            target_cmd=target_cmd,
            output_dir=args.output,
            model_format=args.format,
            timeout=args.timeout,
            max_iterations=args.iterations,
            workers=args.workers,
            seeds=args.seeds.split(",") if args.seeds else None,
        )
    else:
        from .fuzzer import GGUFuzzer
        fuzzer = GGUFuzzer(
            target_cmd=target_cmd,
            output_dir=args.output,
            model_format=args.format,
            timeout=args.timeout,
            max_iterations=args.iterations,
        )

    crashes = fuzzer.run()
    print_summary(crashes)

    if crashes:
        report = generate_report(crashes, args.output)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"\n  Report saved to {args.output}/report.json and {args.output}/report.md")


def cmd_weaponize(args):
    from .weaponizer import generate_weaponized_model, generate_all_weaponized, CVEDatabase

    if args.cve == "all":
        results = generate_all_weaponized(args.output or "payloads")
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\n  Generated {len(results)} weaponized models:")
            for r in results:
                status = "OK" if r["path"] else "FAIL"
                print(f"    [{status}] {r['cve']}: {r['message']}")
    else:
        path, msg = generate_weaponized_model(args.cve, args.output)
        if path:
            if args.json:
                print(json.dumps({"cve": args.cve, "path": path, "message": msg}))
            else:
                print(f"\n  [+] {msg}")
                print(f"  [+] Output: {path}")
        else:
            print(f"\n  [-] Failed: {msg}", file=sys.stderr)
            sys.exit(1)


def cmd_list_cves(args):
    from .weaponizer import CVEDatabase

    cves = CVEDatabase.list_cves()
    if args.json:
        print(json.dumps(cves, indent=2))
    else:
        print(f"\n  {'CVE':<20} {'Target':<25} {'Severity':<10} {'Type'}")
        print(f"  {'-'*20} {'-'*25} {'-'*10} {'-'*30}")
        for cve in cves:
            print(f"  {cve['cve']:<20} {cve['target']:<25} {cve['severity']:<10} {cve['type']}")
        print(f"\n  Total: {len(cves)} CVEs in database")


def cmd_supply_chain(args):
    from .supply_chain import SupplyChainSimulator, print_simulation

    sim = SupplyChainSimulator(args.cve, args.registry)
    report = sim.simulate(args.output or "supply_chain_output")
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_simulation(report)
        print(f"\n  Report saved to {args.output or 'supply_chain_output'}/")


def cmd_validate(args):
    from .fuzzer import ModelFileHarness

    path = args.file
    if path.endswith(".gguf"):
        valid, msg = ModelFileHarness.validate_gguf(path)
    elif path.endswith(".safetensors"):
        valid, msg = ModelFileHarness.validate_safetensors(path)
    else:
        print(f"  Unknown format: {path}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps({"file": path, "valid": valid, "message": msg}))
    else:
        status = "VALID" if valid else "INVALID"
        print(f"\n  [{status}] {path}: {msg}")


def cmd_demo(args):
    """Run full demo — builds real model files, mutates, weaponizes, validates."""
    import struct
    import os
    from .formats import (
        build_gguf, build_minimal_gguf, build_safetensors,
        build_minimal_safetensors, build_onnx_model, build_minimal_onnx,
        GGUF_MAGIC, GGUF_VERSIONS, GGUFFile,
    )
    from .mutators import GGUFMutator, SafetensorsMutator, ONNXMutator
    from .weaponizer import CVEDatabase, generate_weaponized_model
    from .reporter import generate_report, print_summary
    import copy
    import tempfile

    out_dir = args.output if hasattr(args, 'output') and args.output else "demo_output"
    os.makedirs(out_dir, exist_ok=True)

    print("  " + "=" * 70)
    print("  GGUFuzz DEMO — Real Model File Construction & Mutation")
    print("  " + "=" * 70)

    # Phase 1: Build model files in all formats
    print("\n  [Phase 1] Model File Construction")
    print("  " + "-" * 50)

    gf = build_minimal_gguf()
    gguf_data = build_gguf(gf)
    magic = struct.unpack("<I", gguf_data[:4])[0]
    version = struct.unpack("<I", gguf_data[4:8])[0]
    tensor_count = struct.unpack("<Q", gguf_data[8:16])[0]
    print(f"\n  [GGUF] {len(gguf_data)} bytes")
    print(f"    Magic: 0x{magic:08X} (GGUF)")
    print(f"    Version: {version}")
    print(f"    Tensors: {tensor_count}")
    print(f"    Header hex: {gguf_data[:24].hex()}")

    st_data = build_safetensors({"model.weight": {"dtype": "F32", "shape": [16, 16], "size": 1024}})
    header_len = struct.unpack("<Q", st_data[:8])[0]
    print(f"\n  [Safetensors] {len(st_data)} bytes")
    print(f"    Header length: {header_len}")
    print(f"    Header hex: {st_data[:24].hex()}")
    header_json = st_data[8:8 + header_len].decode()
    print(f"    Header JSON: {header_json[:80]}...")

    onnx_data = build_onnx_model()
    print(f"\n  [ONNX] {len(onnx_data)} bytes")
    print(f"    Protobuf hex: {onnx_data[:24].hex()}")

    # Phase 2: Structure-aware mutations
    print("\n\n  [Phase 2] Structure-Aware Mutations")
    print("  " + "-" * 50)

    gguf_mutations = GGUFMutator.get_all_mutations()
    print(f"\n  GGUF mutators: {len(gguf_mutations)}")
    mutation_results = []
    for mut_fn in gguf_mutations:
        mutated = mut_fn(copy.deepcopy(gf))
        data = build_gguf(mutated)
        mutation_results.append(data)
        print(f"    {mut_fn.__name__}: {len(data)} bytes — {data[:8].hex()}")

    st_mutations = SafetensorsMutator.get_all_mutations()
    print(f"\n  Safetensors mutators: {len(st_mutations)}")
    for mut_fn in st_mutations:
        data = mut_fn(st_data)
        print(f"    {mut_fn.__name__}: {len(data)} bytes — {data[:8].hex()}")

    onnx_mutations = ONNXMutator.get_all_mutations()
    print(f"\n  ONNX mutators: {len(onnx_mutations)}")
    for mut_fn in onnx_mutations:
        data = mut_fn(onnx_data)
        print(f"    {mut_fn.__name__}: {len(data)} bytes — {data[:8].hex()}")

    # Phase 3: CVE weaponization
    print("\n\n  [Phase 3] CVE Weaponization")
    print("  " + "-" * 50)

    cves = CVEDatabase.list_cves()
    print(f"\n  CVE database: {len(cves)} entries")
    weaponized = []
    for cve in cves:
        out_path = os.path.join(out_dir, f"weaponized_{cve['cve'].replace('-', '_')}.bin")
        path, msg = generate_weaponized_model(cve["cve"], out_path)
        size = os.path.getsize(path) if path else 0
        weaponized.append({"cve": cve["cve"], "path": path, "size": size})
        status = f"{size} bytes" if path else "FAILED"
        print(f"    {cve['cve']}: {status} — {cve['type']}")

    # Phase 4: Model validation
    print("\n\n  [Phase 4] Model Validation")
    print("  " + "-" * 50)

    from .fuzzer import ModelFileHarness

    gguf_path = os.path.join(out_dir, "test_valid.gguf")
    with open(gguf_path, "wb") as f:
        f.write(gguf_data)
    valid, msg = ModelFileHarness.validate_gguf(gguf_path)
    print(f"\n  Valid GGUF: {'PASS' if valid else 'FAIL'} — {msg}")

    corrupt_path = os.path.join(out_dir, "test_corrupt.gguf")
    with open(corrupt_path, "wb") as f:
        f.write(b"\x00" * 16)
    valid, msg = ModelFileHarness.validate_gguf(corrupt_path)
    print(f"  Corrupt GGUF: {'PASS' if not valid else 'FAIL'} — {msg}")

    st_path = os.path.join(out_dir, "test_valid.safetensors")
    with open(st_path, "wb") as f:
        f.write(st_data)
    valid, msg = ModelFileHarness.validate_safetensors(st_path)
    print(f"  Valid Safetensors: {'PASS' if valid else 'FAIL'} — {msg}")

    # Phase 5: Supply chain simulation
    print("\n\n  [Phase 5] Supply Chain Attack Simulation")
    print("  " + "-" * 50)

    from .supply_chain import SupplyChainSimulator
    sim = SupplyChainSimulator(cves[0]["cve"], "ollama")
    sc_dir = os.path.join(out_dir, "supply_chain")
    report = sim.simulate(sc_dir)
    chain = report.get("attack_chain", [])
    print(f"\n  Target CVE: {cves[0]['cve']}")
    print(f"  Registry: Ollama")
    print(f"  Attack chain steps: {len(chain)}")
    for step in chain:
        name = step.get("phase", step.get("name", "?"))
        print(f"    - {name}")
    print(f"  Report saved to: {sc_dir}/")

    # Summary
    total_mutations = len(gguf_mutations) + len(st_mutations) + len(onnx_mutations)
    total_weaponized = sum(1 for w in weaponized if w["path"])
    total_bytes = len(gguf_data) + len(st_data) + len(onnx_data)
    total_bytes += sum(len(d) for d in mutation_results)
    total_bytes += sum(w["size"] for w in weaponized)

    print("\n\n  " + "=" * 70)
    print("  DEMO COMPLETE — all data is real, no simulation")
    print(f"  Model files:     3 formats (GGUF, Safetensors, ONNX)")
    print(f"  Mutations:       {total_mutations} structure-aware mutators")
    print(f"  CVE payloads:    {total_weaponized}/{len(cves)} weaponized")
    print(f"  Validation:      3 checks")
    print(f"  Supply chain:    1 simulation")
    print(f"  Total bytes:     {total_bytes}")
    print("  " + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        prog="ggufuzz",
        description="GGUFuzz — AI Model File Weaponization Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ggufuzz fuzz --format gguf --target "llama-cli --model {input}" --output crashes/
  ggufuzz fuzz --format gguf --target "llama-cli --model {input}" --coverage
  ggufuzz weaponize --cve CVE-2026-33298 --output evil.gguf
  ggufuzz weaponize --cve all --output payloads/
  ggufuzz supply-chain --cve CVE-2026-33298 --registry ollama --output sim/
  ggufuzz list-cves
  ggufuzz validate --file model.gguf
  ggufuzz demo
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # fuzz
    p_fuzz = subparsers.add_parser("fuzz", help="Fuzz a model file parser")
    p_fuzz.add_argument("--format", choices=["gguf", "safetensors", "onnx"], default="gguf")
    p_fuzz.add_argument("--target", required=True, help="Target command ({input} placeholder for model file)")
    p_fuzz.add_argument("--output", default="fuzz_output", help="Output directory")
    p_fuzz.add_argument("--timeout", type=int, default=10, help="Per-execution timeout (seconds)")
    p_fuzz.add_argument("--iterations", type=int, default=10000, help="Max fuzzing iterations")
    p_fuzz.add_argument("--coverage", action="store_true", help="Enable coverage-guided mode")
    p_fuzz.add_argument("--workers", type=int, default=1, help="Parallel workers (coverage mode)")
    p_fuzz.add_argument("--seeds", help="Comma-separated seed files/dirs")
    p_fuzz.add_argument("--json", action="store_true", help="JSON output")

    # weaponize
    p_weap = subparsers.add_parser("weaponize", help="Generate weaponized model files")
    p_weap.add_argument("--cve", required=True, help="CVE ID or 'all'")
    p_weap.add_argument("--output", help="Output file or directory (for 'all')")
    p_weap.add_argument("--json", action="store_true", help="JSON output")

    # list-cves
    p_list = subparsers.add_parser("list-cves", help="List all CVEs in the database")
    p_list.add_argument("--json", action="store_true", help="JSON output")

    # supply-chain
    p_sc = subparsers.add_parser("supply-chain", help="Simulate supply chain attack")
    p_sc.add_argument("--cve", required=True, help="CVE to weaponize")
    p_sc.add_argument("--registry", default="ollama", choices=["ollama", "huggingface", "modelscope"])
    p_sc.add_argument("--output", help="Output directory")
    p_sc.add_argument("--json", action="store_true", help="JSON output")

    # validate
    p_val = subparsers.add_parser("validate", help="Validate a model file")
    p_val.add_argument("--file", required=True, help="Model file to validate")
    p_val.add_argument("--json", action="store_true", help="JSON output")

    # demo
    p_demo = subparsers.add_parser("demo", help="Run full demo with real model construction and mutation")
    p_demo.add_argument("--output", "-o", default="demo_output")

    args = parser.parse_args()

    BANNER = r"""
   ██████╗  ██████╗ ██╗   ██╗███████╗██╗   ██╗███████╗███████╗
  ██╔════╝ ██╔════╝ ██║   ██║██╔════╝██║   ██║╚══███╔╝╚══███╔╝
  ██║  ███╗██║  ███╗██║   ██║█████╗  ██║   ██║  ███╔╝   ███╔╝
  ██║   ██║██║   ██║██║   ██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝
  ╚██████╔╝╚██████╔╝╚██████╔╝██║     ╚██████╔╝███████╗███████╗
   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝
  AI Model File Weaponization Framework v1.0.0
    """
    print(BANNER)

    commands = {
        "fuzz": cmd_fuzz,
        "weaponize": cmd_weaponize,
        "list-cves": cmd_list_cves,
        "supply-chain": cmd_supply_chain,
        "validate": cmd_validate,
        "demo": cmd_demo,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

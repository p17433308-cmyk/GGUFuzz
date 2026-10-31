"""
CVE-ready report generator — produces structured reports from crash data.
Outputs JSON, Markdown, and terminal-friendly summaries.
"""
import json
import time
from pathlib import Path
from typing import List
from .fuzzer import CrashInfo, Exploitability


def generate_report(crashes: List[CrashInfo], output_dir: str, format: str = "all") -> dict:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    report = {
        "tool": "GGUFuzz",
        "version": "1.0.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total_crashes": len(crashes),
            "exploitable": sum(1 for c in crashes if c.exploitability == Exploitability.EXPLOITABLE),
            "probably_exploitable": sum(1 for c in crashes if c.exploitability == Exploitability.PROBABLY_EXPLOITABLE),
            "unknown": sum(1 for c in crashes if c.exploitability == Exploitability.UNKNOWN),
            "not_exploitable": sum(1 for c in crashes if c.exploitability == Exploitability.NOT_EXPLOITABLE),
        },
        "crashes": [c.to_dict() for c in crashes],
    }

    if format in ("json", "all"):
        json_path = Path(output_dir) / "report.json"
        json_path.write_text(json.dumps(report, indent=2))

    if format in ("markdown", "all"):
        md = _generate_markdown(report, crashes)
        md_path = Path(output_dir) / "report.md"
        md_path.write_text(md)

    return report


def _generate_markdown(report: dict, crashes: List[CrashInfo]) -> str:
    s = report["summary"]
    lines = [
        "# GGUFuzz Crash Report",
        "",
        f"**Generated:** {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total crashes | {s['total_crashes']} |",
        f"| EXPLOITABLE | {s['exploitable']} |",
        f"| PROBABLY EXPLOITABLE | {s['probably_exploitable']} |",
        f"| UNKNOWN | {s['unknown']} |",
        f"| NOT EXPLOITABLE | {s['not_exploitable']} |",
        "",
        "## Crash Details",
        "",
    ]

    sorted_crashes = sorted(crashes, key=lambda c: (
        0 if c.exploitability == Exploitability.EXPLOITABLE else
        1 if c.exploitability == Exploitability.PROBABLY_EXPLOITABLE else
        2 if c.exploitability == Exploitability.UNKNOWN else 3
    ))

    for i, crash in enumerate(sorted_crashes, 1):
        lines.extend([
            f"### Crash #{i} — {crash.crash_type.value}",
            "",
            f"- **Exploitability:** {crash.exploitability.value}",
            f"- **Mutation strategy:** {crash.mutation_strategy}",
            f"- **Exit code:** {crash.exit_code}",
            f"- **Input file:** `{crash.input_file}`",
            f"- **Hash:** `{crash.hash}`",
            "",
        ])
        if crash.asan_report:
            lines.extend([
                "**ASan Report:**",
                "```",
                crash.asan_report[:2000],
                "```",
                "",
            ])
        elif crash.stderr:
            lines.extend([
                "**stderr:**",
                "```",
                crash.stderr[:1000],
                "```",
                "",
            ])

    return "\n".join(lines)


def print_summary(crashes: List[CrashInfo]):
    if not crashes:
        print("\n  No crashes found.")
        return

    print(f"\n  {'='*60}")
    print(f"  CRASH SUMMARY — {len(crashes)} unique crashes")
    print(f"  {'='*60}")

    by_exploitability = {}
    for c in crashes:
        key = c.exploitability.value
        by_exploitability.setdefault(key, []).append(c)

    for level in ["EXPLOITABLE", "PROBABLY_EXPLOITABLE", "UNKNOWN", "NOT_EXPLOITABLE"]:
        group = by_exploitability.get(level, [])
        if group:
            print(f"\n  [{level}] — {len(group)} crashes")
            for c in group:
                print(f"    - {c.crash_type.value} via {c.mutation_strategy} [{c.hash}]")

"""
Supply chain attack simulation — demonstrates how weaponized model files
can be distributed through model registries.

This module does NOT actually upload anything. It simulates the attack chain
and generates a report showing each step and its impact.
"""
import os
import json
import time
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List

from .weaponizer import generate_weaponized_model, CVEDatabase


@dataclass
class AttackStep:
    phase: str
    action: str
    detail: str
    risk: str
    mitigated_by: Optional[str] = None


class SupplyChainSimulator:
    """
    Simulates end-to-end supply chain attack via poisoned model files.
    Attack chain:
      1. Attacker crafts weaponized model file (GGUF with memory corruption trigger)
      2. Model is uploaded to registry (HuggingFace, Ollama library, etc.)
      3. Victim downloads model via CLI (ollama pull, huggingface-cli download)
      4. Victim loads model — parser hits corrupted data — code execution
    """

    REGISTRIES = {
        "ollama": {
            "name": "Ollama Model Library",
            "pull_cmd": "ollama pull {model_name}",
            "parser": "llama.cpp GGUF parser",
            "format": "gguf",
            "auth_required": False,
            "scanning": "None (no model file scanning)",
        },
        "huggingface": {
            "name": "HuggingFace Hub",
            "pull_cmd": "huggingface-cli download {model_name}",
            "parser": "safetensors / GGUF (varies)",
            "format": "gguf",
            "auth_required": False,
            "scanning": "Pickle scanning only (misses GGUF memory corruption)",
        },
        "modelscope": {
            "name": "ModelScope",
            "pull_cmd": "modelscope download {model_name}",
            "parser": "Various",
            "format": "gguf",
            "auth_required": False,
            "scanning": "Minimal",
        },
    }

    def __init__(self, cve_id: str, registry: str = "ollama"):
        self.cve_id = cve_id
        self.registry = self.REGISTRIES.get(registry, self.REGISTRIES["ollama"])
        self.registry_key = registry
        self.steps: List[AttackStep] = []
        self.cve_info = CVEDatabase.get(cve_id)

    def simulate(self, output_dir: str) -> dict:
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Phase 1: Craft
        self.steps.append(AttackStep(
            phase="1. Weaponization",
            action="Generate malicious model file",
            detail=f"GGUFuzz generates a weaponized GGUF file targeting {self.cve_id}: "
                   f"{self.cve_info['description'] if self.cve_info else 'unknown'}",
            risk="Attacker creates a model file that appears valid but contains "
                 "crafted data triggering memory corruption in the parser.",
        ))

        weapon_path = os.path.join(output_dir, "weaponized_model.gguf")
        result_path, msg = generate_weaponized_model(self.cve_id, weapon_path)

        if result_path:
            file_size = os.path.getsize(result_path)
            file_hash = hashlib.sha256(Path(result_path).read_bytes()).hexdigest()
            self.steps[-1].detail += f"\n  File: {result_path} ({file_size} bytes, SHA256: {file_hash[:16]}...)"

        # Phase 2: Distribution
        self.steps.append(AttackStep(
            phase="2. Distribution",
            action=f"Upload to {self.registry['name']}",
            detail=f"Attacker uploads the weaponized model to {self.registry['name']}. "
                   f"Auth required: {self.registry['auth_required']}. "
                   f"Current scanning: {self.registry['scanning']}.",
            risk="Model registries do not scan GGUF files for memory corruption payloads. "
                 "Pickle scanning (where it exists) is irrelevant for this attack vector.",
            mitigated_by="Format-aware model file scanning (does not exist today)",
        ))

        # Phase 3: Delivery
        self.steps.append(AttackStep(
            phase="3. Delivery",
            action="Victim downloads model",
            detail=f"Victim runs: `{self.registry['pull_cmd'].format(model_name='attacker/evil-model')}`\n"
                   f"  The model is downloaded and stored locally with no integrity verification "
                   f"beyond basic checksums (which match, since the file is intentionally crafted).",
            risk="Users routinely download and run models from public registries with no security review.",
        ))

        # Phase 4: Exploitation
        self.steps.append(AttackStep(
            phase="4. Exploitation",
            action="Model loading triggers vulnerability",
            detail=f"When the victim loads the model, the {self.registry['parser']} parses the GGUF header. "
                   f"The crafted data triggers {self.cve_info['type'] if self.cve_info else 'memory corruption'}, "
                   f"achieving code execution in the context of the inference process.",
            risk="Full code execution on the victim's machine. The inference process typically runs "
                 "with the user's full privileges (no sandboxing in Ollama, llama.cpp, or vLLM).",
        ))

        # Phase 5: Impact
        self.steps.append(AttackStep(
            phase="5. Impact",
            action="Post-exploitation",
            detail="With code execution achieved, the attacker can:\n"
                   "  - Exfiltrate all other locally stored models\n"
                   "  - Access API keys and credentials in the user's environment\n"
                   "  - Establish persistence\n"
                   "  - Pivot to other systems on the network\n"
                   "  - Modify other models to propagate (wormable)",
            risk="AI infrastructure typically has access to sensitive data, API keys, "
                 "and network resources. Compromise of an inference server is high-impact.",
        ))

        report = self._build_report(output_dir)
        return report

    def _build_report(self, output_dir: str) -> dict:
        report = {
            "simulation": "GGUFuzz Supply Chain Attack",
            "cve": self.cve_id,
            "registry": self.registry_key,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "attack_chain": [
                {
                    "phase": s.phase,
                    "action": s.action,
                    "detail": s.detail,
                    "risk": s.risk,
                    "mitigation": s.mitigated_by,
                }
                for s in self.steps
            ],
            "recommendations": [
                "Implement format-aware scanning for GGUF/safetensors in model registries",
                "Run model loading in sandboxed environments (seccomp, gVisor)",
                "Verify model file integrity with signed checksums from trusted sources",
                "Use AddressSanitizer builds for model loading in CI/CD pipelines",
                "Monitor for anomalous behavior after model loading (unexpected syscalls, network activity)",
            ],
        }

        json_path = Path(output_dir) / "supply_chain_report.json"
        json_path.write_text(json.dumps(report, indent=2))

        md = self._build_markdown(report)
        md_path = Path(output_dir) / "supply_chain_report.md"
        md_path.write_text(md)

        return report

    def _build_markdown(self, report: dict) -> str:
        lines = [
            "# GGUFuzz Supply Chain Attack Simulation",
            "",
            f"**CVE:** {report['cve']}",
            f"**Registry:** {report['registry']}",
            f"**Generated:** {report['timestamp']}",
            "",
            "## Attack Chain",
            "",
        ]
        for step in report["attack_chain"]:
            lines.extend([
                f"### {step['phase']}",
                f"**Action:** {step['action']}",
                "",
                step["detail"],
                "",
                f"> **Risk:** {step['risk']}",
                "",
            ])
            if step.get("mitigation"):
                lines.append(f"> **Mitigation:** {step['mitigation']}")
                lines.append("")

        lines.extend([
            "## Recommendations",
            "",
        ])
        for rec in report["recommendations"]:
            lines.append(f"- {rec}")

        return "\n".join(lines)


def print_simulation(report: dict):
    print("\n" + "=" * 70)
    print("  SUPPLY CHAIN ATTACK SIMULATION")
    print(f"  CVE: {report['cve']} | Registry: {report['registry']}")
    print("=" * 70)

    for step in report["attack_chain"]:
        print(f"\n  [{step['phase']}]")
        print(f"  Action: {step['action']}")
        for line in step["detail"].split("\n"):
            print(f"    {line}")
        print(f"    Risk: {step['risk'][:100]}...")

    print("\n" + "=" * 70)

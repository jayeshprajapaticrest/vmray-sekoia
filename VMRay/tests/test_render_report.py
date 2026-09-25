import json
from pathlib import Path

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.render_report_action import RenderReport, render_report

CHILD = {
    "sample_id": 43,
    "sample_verdict": "malicious",
    "sample_vti_score": 90,
    "sample_type": "Windows Exe (x86-32)",
    "sample_filename": "payload.exe",
    "sample_threat_names": ["Lumma"],
    "sample_sha256hash": "d" * 64,
    "sample_iocs": {"iocs": {"ips": [{"ip_address": "203.0.113.9"}]}},
    "sample_webif_url": "https://eu.cloud.vmray.com/samples/43",
    "sample_child_samples": [],
}

REPORT = {
    "samples": [
        {
            "sample_id": 42,
            "sample_verdict": "malicious",
            "sample_vti_score": 100,
            "sample_verdict_reason_description": "Downloads and runs a known stealer.",
            "sample_type": "URL",
            "sample_url": "http://evil.example/login",
            "sample_filename": "sample.url",
            "sample_sha256hash": "a" * 64,
            "sample_threat_names": ["ClickFix"],
            "sample_classifications": ["Downloader"],
            "sample_iocs": {
                "iocs": {"domains": [{"domain": "evil.example"}], "urls": [{"url": "http://evil.example/p"}]}
            },
            "sample_threat_indicators": {
                "threat_indicators": [
                    {"operation": "weak rule", "category": "Heuristics", "score": 1},
                    {"operation": "strong rule", "category": "YARA", "classifications": ["Downloader"], "score": 5},
                ]
            },
            "sample_mitre_attack": {
                "mitre_attack_techniques": [
                    {"id": 7, "technique_id": "T1204.002", "technique": "Malicious File", "tactics": ["Execution"]}
                ]
            },
            "sample_analyses": [
                {"analysis_verdict": "malicious", "analysis_vti_score": 100, "analysis_configuration_name": "web_root"}
            ],
            "sample_child_sample_ids": [43],
            "sample_child_samples": [CHILD],
            "sample_webif_url": "https://eu.cloud.vmray.com/samples/42",
            "errors": {"sample_threat_names": "timed out"},
        },
        {"sample_id": 50, "sample_verdict": "clean", "sample_vti_score": 5, "sample_filename": "invoice.pdf"},
    ],
    "errors": {"41": "unknown sample"},
}


def test_renders_every_section_of_a_sample():
    content = render_report(REPORT)

    assert "## Sample 1/2 — VMRay verdict: MALICIOUS (VTI score 100/100)" in content
    assert "Downloads and runs a known stealer." in content
    assert "**Threat:** ClickFix" in content
    assert "**Classification:** Downloader" in content
    assert "**URL:** `http://evil.example/login`" in content
    assert "sample.url" not in content  # the URL container's filename is noise
    assert "`" + "a" * 64 + "`" in content
    assert "**IOCs:** 1 Domains, 1 URLs" in content
    assert "`evil.example`" in content
    assert "**strong rule** (YARA) — Downloader [score 5/5]" in content
    assert content.index("strong rule") < content.index("weak rule")
    assert "**MITRE ATT&CK:** T1204.002 Malicious File (Execution)" in content
    assert "**MALICIOUS** (VTI 100/100) — web_root" in content
    assert "[Full VMRay report](https://eu.cloud.vmray.com/samples/42)" in content
    assert "failed to load: sample_threat_names" in content


def test_renders_child_samples_as_lines():
    content = render_report(REPORT)

    assert "**Child samples (1):**" in content
    assert "**MALICIOUS (VTI score 90/100)** · Windows Exe (x86-32) · `payload.exe` · Lumma · 1 IOCs" in content
    assert "[report](https://eu.cloud.vmray.com/samples/43)" in content


def test_renders_every_top_level_sample_and_report_errors():
    content = render_report(REPORT)

    assert "## Sample 2/2 — VMRay verdict: CLEAN (VTI score 5/100)" in content
    assert "**Filename:** invoice.pdf" in content
    assert "could not be fetched from VMRay: 41" in content


def test_single_sample_has_plain_heading():
    content = render_report({"samples": [{"sample_id": 1, "sample_verdict": "clean"}]})

    assert content.startswith("## VMRay verdict: CLEAN")


def test_unexpanded_children_are_counted():
    content = render_report({"samples": [{"sample_id": 1, "sample_child_sample_ids": [2, 3]}]})

    assert "**Child samples:** 2 (not expanded" in content


def test_empty_report():
    assert render_report({"samples": []}) == "VMRay returned no samples for this report."


def test_long_lists_are_capped():
    vtis = [{"operation": f"rule {i}", "score": 1} for i in range(15)]
    content = render_report({"samples": [{"sample_id": 1, "sample_threat_indicators": {"threat_indicators": vtis}}]})

    assert "_...and 5 more_" in content


def test_action_reads_inline_and_from_data_path(data_storage):
    assert "MALICIOUS" in RenderReport().run({"report": REPORT})["content"]

    (Path(data_storage) / "report.json").write_text(json.dumps(REPORT))
    assert "MALICIOUS" in RenderReport().run({"report_path": "report.json"})["content"]


def test_action_requires_a_report():
    with pytest.raises(MissingActionArgumentError):
        RenderReport().run({})

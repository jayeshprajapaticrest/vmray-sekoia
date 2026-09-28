import json
from pathlib import Path

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.render_report_action import RenderReport, render_report

CHILD = {
    "sample_id": 43,
    "sample_verdict": "malicious",
    "sample_type": "Windows Exe (x86-32)",
    "sample_filename": "payload.exe",
    "sample_threat_names": ["Lumma"],
    "sample_iocs": {"iocs": {"ips": [{"ioc_type": "ip", "ip_address": "203.0.113.9", "verdict": "malicious"}]}},
    "sample_webif_url": "https://eu.cloud.vmray.com/samples/43",
    "sample_child_sample_ids": [44],
}

ROOT = {
    "sample_id": 42,
    "sample_verdict": "malicious",
    "sample_vti_score": 100,
    "sample_type": "URL",
    "sample_url": "http://evil.example/login",
    "sample_filename": "sample.url",
    "sample_created": "2026-09-24T04:59:46",
    "sample_md5hash": "c" * 32,
    "sample_sha256hash": "a" * 64,
    "sample_threat_names": ["ClickFix"],
    "sample_classifications": ["Downloader"],
    "sample_webif_url": "https://eu.cloud.vmray.com/samples/42",
    "sample_iocs": {
        "iocs": {
            "domains": [{"ioc_type": "domain", "domain": "evil.example", "verdict": "malicious"}],
            "processes": [{"ioc_type": "process", "process_names": ["mshta.exe", "cmd.exe"]}],
            "registry": [{"ioc_type": "registry", "reg_key_name": "HKCU\\Run|Evil", "verdict": "suspicious"}],
        }
    },
    "sample_threat_indicators": {
        "threat_indicators": [
            {"score": 1, "category": "Heuristics", "operation": "weak rule"},
            {"score": 5, "category": "YARA", "operation": "strong rule", "classifications": ["Downloader"]},
        ]
    },
    "sample_mitre_attack": {
        "mitre_attack_techniques": [
            {"id": 7, "technique_id": "T1204.002", "technique": "Malicious File", "tactics": ["Execution"]}
        ]
    },
    "sample_analyses": [
        {"analysis_analyzer_name": "static", "analysis_created": "2026-09-24T04:00:00", "analysis_verdict": "clean"},
        {
            "analysis_analyzer_name": "vmray",
            "analysis_vm_description": "Windows 10 64-bit",
            "analysis_created": "2026-09-24T05:00:00",
            "analysis_verdict": "malicious",
        },
    ],
    "sample_child_sample_ids": [43],
    "sample_child_samples": [CHILD],
    "errors": {"sample_threat_names": "timed out"},
}


@pytest.fixture
def content():
    return render_report({"samples": [ROOT]})


def test_overview_table(content):
    assert content.startswith("## VMRay Report")
    assert "#### Overview" in content
    assert "| **Verdict** | **MALICIOUS** |" in content
    assert "| **VTI score** | 100/100 |" in content
    assert "| **URL** | `http://evil.example/login` |" in content
    assert "sample.url" not in content  # a URL sample's container filename is noise
    assert "| **Type** | URL |" in content
    assert "| **Created** | 2026-09-24T04:59:46 |" in content
    assert "| **SHA256** | `" + "a" * 64 + "` |" in content
    assert "| **Report** | [View in VMRay](https://eu.cloud.vmray.com/samples/42) |" in content


def test_detections(content):
    assert "**Threat Names:** `ClickFix`" in content
    assert "**Classifications:** `Downloader`" in content


def test_ioc_summary_counts_only_present_types(content):
    assert "| Domains | Processes | Registry |" in content
    assert "| 1 | 1 | 1 |" in content


def test_threat_identifiers_table_sorted_by_score(content):
    assert "| Score | Category | Operation | Classification |" in content
    assert "| **5/5** | YARA | strong rule | Downloader |" in content
    assert "| **1/5** | Heuristics | weak rule | — |" in content
    assert content.index("strong rule") < content.index("weak rule")


def test_mitre_table_links_sub_techniques_correctly(content):
    assert "| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Execution |" in content


def test_ioc_table(content):
    assert "| Type | Value | Verdict |" in content
    assert "| DOMAIN | `evil.example` | **MALICIOUS** |" in content
    assert "| PROCESS | `mshta.exe, cmd.exe` | — |" in content  # list values joined, missing verdict dashed


def test_table_cells_are_escaped(content):
    assert "`HKCU\\\\Run\\|Evil`" in content  # backslash and pipe escaped so the row stays intact


def test_analyses_table_newest_first(content):
    assert "| Analysis | Target Environment | Created | Verdict |" in content
    assert "| vmray | Windows 10 64-bit | `2026-09-24T05:00:00` | **MALICIOUS** |" in content
    assert "| static | — | `2026-09-24T04:00:00` | **CLEAN** |" in content
    assert content.index("Windows 10 64-bit") < content.index("| static |")


def test_child_samples_listed_in_a_table_without_details(content):
    assert "#### Child Samples (1)" in content
    assert (
        "| **MALICIOUS** | `payload.exe` | Windows Exe (x86-32) | 1 | [View](https://eu.cloud.vmray.com/samples/43) |"
        in content
    )
    assert "### Child sample" not in content  # listed only, no per-child detail sections
    assert "203.0.113.9" not in content  # the child's own IOCs are not rendered
    assert content.count("#### Overview") == 1  # only the top-level sample gets full sections


def test_partial_data_warning(content):
    assert "failed to load: sample_threat_names" in content


def test_screenshots_never_rendered(content):
    assert "Screenshot" not in content


def test_multiple_samples_and_report_errors():
    content = render_report({"samples": [ROOT, {"sample_id": 50, "sample_verdict": "clean"}], "errors": {"41": "x"}})

    assert "### Sample (1/2)" in content
    assert "### Sample (2/2)" in content
    assert "could not be fetched from VMRay: 41" in content


def test_no_samples():
    assert render_report({"samples": []}) == "## VMRay Report\n\n**No matches found for this observable.**"


def test_long_tables_are_capped():
    vtis = [{"score": 1, "operation": f"rule {i}"} for i in range(25)]
    content = render_report({"samples": [{"sample_id": 1, "sample_threat_indicators": {"threat_indicators": vtis}}]})

    assert "_…and 5 more_" in content


def test_action_reads_inline_and_from_data_path(data_storage):
    assert "MALICIOUS" in RenderReport().run({"report": {"samples": [ROOT]}})["content"]

    (Path(data_storage) / "report.json").write_text(json.dumps({"samples": [ROOT]}))
    assert "MALICIOUS" in RenderReport().run({"report_path": "report.json"})["content"]


def test_action_requires_a_report():
    with pytest.raises(MissingActionArgumentError):
        RenderReport().run({})


def test_nested_children_are_indented_rows():
    grandchild = {"sample_id": 44, "sample_verdict": "clean", "sample_filename": "drop.dll"}
    child = {
        "sample_id": 43,
        "sample_verdict": "malicious",
        "sample_filename": "payload.exe",
        "sample_child_samples": [grandchild],
    }
    content = render_report({"samples": [{"sample_id": 42, "sample_child_samples": [child]}]})

    assert "| **MALICIOUS** | `payload.exe` | — | 1 | — |" in content
    assert "| **CLEAN** | ↳ `drop.dll` | — | — | — |" in content


def test_unbuilt_children_are_counted():
    content = render_report({"samples": [{"sample_id": 1, "sample_child_sample_ids": [2, 3]}]})

    assert "#### Child Samples (2)" in content
    assert "_Not expanded — see the VMRay report._" in content

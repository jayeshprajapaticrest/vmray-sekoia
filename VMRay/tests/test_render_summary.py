import json
from pathlib import Path

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.models import AnalysisDetails
from vmray_modules.render_summary_action import RenderSummary, render_summary


@pytest.fixture
def full_analysis():
    return {
        "sample_id": 12345,
        "sample_verdict": "malicious",
        "sample_verdict_reason_description": "Sample injects into a remote process and contacts a known C2.",
        "sample_score": 98,
        "sample_vti_score": 98,
        "sample_threat_names": ["Emotet"],
        "sample_classifications": ["Trojan", "Downloader"],
        "sample_sha256hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0",
        "sample_filename": "invoice.exe",
        "sample_webif_url": "https://eu.cloud.vmray.com/samples/12345",
        "sample_child_sample_ids": [67890],
        "sample_child_relations_truncated": True,
        "threat_indicators": [
            {"category": "Injection", "operation": "Injects into a remote process", "classification": ["Injection"]},
            {"category": "Network", "operation": "Contacts a known C2 server"},
        ],
        "mitre_attack_techniques": [
            {"id": "T1055", "name": "Process Injection", "tactics": ["Defense Evasion"]},
            {"id": "T1071.001", "name": "Web Protocols"},
        ],
        "iocs": {
            "domains": [{"domain": "evil.example"}],
            "urls": [{"url": "http://evil.example/payload"}],
            "ips": [{"ip_address": "203.0.113.5"}],
        },
        "sample_analyses": [
            {
                "analysis_id": 1,
                "analysis_verdict": "malicious",
                "analysis_vti_score": 98,
                "analysis_configuration_name": "Windows 10",
            },
        ],
        "errors": {"iocs": "request timed out after 3 retries"},
    }


def test_render_summary_full(full_analysis):
    content = render_summary_from_dict(full_analysis)

    assert "## VMRay verdict: MALICIOUS (VTI score 98/100)" in content
    assert "Emotet" in content
    assert "Trojan, Downloader" in content
    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0" in content
    assert "Injects into a remote process" in content
    assert "T1055 Process Injection (Defense Evasion)" in content
    assert "[Full VMRay report](https://eu.cloud.vmray.com/samples/12345)" in content
    assert "1 child sample(s) extracted (list truncated by VMRay" in content
    assert "⚠️ _Partial data — these sections failed to load: iocs._" in content
    assert "1 Domains" in content and "1 URLs" in content and "1 IPs" in content
    assert "`evil.example`" in content
    assert "`http://evil.example/payload`" in content
    assert "`203.0.113.5`" in content
    assert "**MALICIOUS** (VTI 98/100) — Windows 10" in content


def test_render_summary_caps_iocs_per_type():
    analysis = {
        "sample_id": 1,
        "iocs": {"domains": [{"domain": f"evil-{i}.example"} for i in range(15)]},
    }
    content = render_summary_from_dict(analysis)

    assert "evil-9.example" in content  # 10th item, within the cap
    assert "evil-10.example" not in content  # 11th item, beyond the cap
    assert "...and 5 more" in content


def test_render_summary_caps_analyses():
    analysis = {
        "sample_id": 1,
        "sample_analyses": [{"analysis_id": i, "analysis_verdict": "clean"} for i in range(15)],
    }
    content = render_summary_from_dict(analysis)

    assert content.count("**CLEAN**") == 10
    assert "_...and 5 more_" in content


def test_render_summary_minimal():
    content = render_summary_from_dict({"sample_id": 1})

    assert content.startswith("## VMRay verdict: UNKNOWN")
    # nothing else should be present — no crashes on missing optional data
    assert "Threat:" not in content
    assert "MITRE ATT&CK" not in content


def test_render_summary_caps_long_lists():
    analysis = {
        "sample_id": 1,
        "threat_indicators": [{"category": "c", "operation": f"rule {i}"} for i in range(15)],
    }
    content = render_summary_from_dict(analysis)

    assert "rule 9" in content  # 10th item (index 9), within the cap
    assert "rule 10" not in content  # 11th item, beyond the cap
    assert "...and 5 more" in content


def render_summary_from_dict(analysis: dict) -> str:
    return render_summary(AnalysisDetails.model_validate(analysis))


def test_action_run_with_inline_analysis(full_analysis):
    action = RenderSummary()
    result = action.run({"analysis": full_analysis})

    assert "MALICIOUS" in result["content"]


def test_action_run_with_analysis_path(data_storage, full_analysis):
    (Path(data_storage) / "analysis.json").write_text(json.dumps(full_analysis))

    action = RenderSummary()
    result = action.run({"analysis_path": "analysis.json"})

    assert "MALICIOUS" in result["content"]


def test_action_run_missing_argument():
    action = RenderSummary()

    with pytest.raises(MissingActionArgumentError):
        action.run({})

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.build_report_action import BuildReport
from vmray_modules.models import VMRayConfiguration, VMRayModule

BASE_URL = "https://eu.cloud.vmray.com"


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return BuildReport(module=m)


def ok(data):
    return {"result": "ok", "data": data}


def mock_full_sample(requests_mock, sample_id, children=(), latest_submission=True):
    """Every endpoint BuildReport calls for one sample."""
    r = requests_mock
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}",
        json=ok({"sample_id": sample_id, "sample_verdict": "malicious", "sample_child_sample_ids": list(children)}),
    )
    r.get(
        f"{BASE_URL}/rest/submission/sample/{sample_id}",
        json=ok(
            [
                {"submission_id": sample_id * 10, "submission_created": "2026-01-01T00:00:00"},
                {"submission_id": sample_id * 10 + 1, "submission_created": "2026-09-01T00:00:00"},
            ]
            if latest_submission
            else []
        ),
    )
    r.get(
        f"{BASE_URL}/rest/analysis/submission/{sample_id * 10 + 1}",
        json=ok(
            [{"analysis_id": 1, "analysis_verdict": "malicious"}, {"analysis_id": 2, "analysis_verdict": "clean"}]
        ),
    )
    r.get(f"{BASE_URL}/rest/analysis/sample/{sample_id}", json=ok([{"analysis_id": 9, "analysis_verdict": "clean"}]))
    r.get(f"{BASE_URL}/rest/sample/{sample_id}/vtis", json=ok({"threat_indicators": [{"operation": "x", "score": 5}]}))
    r.get(f"{BASE_URL}/rest/sample/{sample_id}/mitre_attack", json=ok({"mitre_attack_techniques": [{"id": "T1055"}]}))
    r.get(f"{BASE_URL}/rest/sample/{sample_id}/iocs", json=ok({"iocs": {"urls": [{"url": "http://evil.example"}]}}))
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}/classifications",
        json=ok(
            {
                "sample_classifications": [{"classification_name": "Downloader"}],
                "children_classifications": [{"classification_name": "Trojan"}],
            }
        ),
    )
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}/threat_names",
        json=ok({"sample_threat_names": [{"threat_name": "ClickFix"}], "children_threat_names": []}),
    )


def test_builds_full_report_from_samples(requests_mock):
    mock_full_sample(requests_mock, 42)

    result = make_action().run({"samples": [{"sample_id": 42}]})

    sample = result["samples"][0]
    assert sample["sample_id"] == 42
    assert sample["sample_verdict"] == "malicious"
    assert sample["sample_threat_indicators"]["threat_indicators"][0]["score"] == 5
    assert sample["sample_mitre_attack"]["mitre_attack_techniques"][0]["id"] == "T1055"
    assert sample["sample_iocs"]["iocs"]["urls"][0]["url"] == "http://evil.example"
    assert sample["sample_classifications"] == ["Downloader", "Trojan"]  # sample + children merged
    assert sample["sample_threat_names"] == ["ClickFix"]
    assert sample["errors"] == {}
    assert result["errors"] == {}


def test_analyses_come_from_the_latest_submission(requests_mock):
    mock_full_sample(requests_mock, 42)

    sample = make_action().run({"samples": [{"sample_id": 42}]})["samples"][0]

    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [1, 2]  # submission 421, not 420


def test_analyses_fall_back_to_all_when_no_submission(requests_mock):
    mock_full_sample(requests_mock, 42, latest_submission=False)

    sample = make_action().run({"samples": [{"sample_id": 42}]})["samples"][0]

    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [9]


def test_accepts_submissions(requests_mock):
    mock_full_sample(requests_mock, 42)

    result = make_action().run({"submissions": [{"submission_id": 111, "submission_sample_id": 42}]})

    assert [s["sample_id"] for s in result["samples"]] == [42]


def test_samples_take_precedence_over_submissions(requests_mock):
    mock_full_sample(requests_mock, 42)
    # no mocks for sample 43 — using the submissions list would raise NoMockAddress

    result = make_action().run({"samples": [{"sample_id": 42}], "submissions": [{"submission_sample_id": 43}]})

    assert [s["sample_id"] for s in result["samples"]] == [42]


@pytest.mark.parametrize("arguments", [{}, {"samples": [], "submissions": []}])
def test_requires_samples_or_submissions(arguments):
    with pytest.raises(MissingActionArgumentError):
        make_action().run(arguments)


def test_duplicate_ids_build_once(requests_mock):
    mock_full_sample(requests_mock, 42)

    result = make_action().run({"samples": [{"sample_id": 42}, {"sample_id": 42}]})

    assert len(result["samples"]) == 1


def test_default_depth_builds_direct_children_only(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])
    mock_full_sample(requests_mock, 43, children=[44])
    # no mocks for 44 — building a grandchild would raise NoMockAddress

    sample = make_action().run({"samples": [{"sample_id": 42}]})["samples"][0]

    child = sample["sample_child_samples"][0]
    assert child["sample_id"] == 43
    assert child["sample_iocs"]["iocs"]["urls"]  # child got a full report
    assert child["sample_child_samples"] == []  # but its own children were not built


def test_depth_zero_builds_no_children(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])

    sample = make_action().run({"samples": [{"sample_id": 42}], "max_recursion_depth": 0})["samples"][0]

    assert sample["sample_child_samples"] == []


def test_failing_section_is_recorded_and_the_rest_is_filled(requests_mock):
    mock_full_sample(requests_mock, 42)
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", status_code=500, json={"error_msg": "boom"})

    sample = make_action().run({"samples": [{"sample_id": 42}]})["samples"][0]

    assert "sample_iocs" in sample["errors"]
    assert sample["sample_iocs"] == {}
    assert sample["sample_mitre_attack"]["mitre_attack_techniques"]


def test_unfetchable_sample_is_recorded_and_others_still_built(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/41", status_code=404, json={"error_msg": "unknown sample"})
    mock_full_sample(requests_mock, 42)

    result = make_action().run({"samples": [{"sample_id": 41}, {"sample_id": 42}]})

    assert "41" in result["errors"]
    assert [s["sample_id"] for s in result["samples"]] == [42]


def test_filters_are_forwarded(requests_mock):
    mock_full_sample(requests_mock, 42)
    iocs = requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok({"iocs": {}}))

    sample = make_action().run(
        {"samples": [{"sample_id": 42}], "ioc_severity_filter": "malicious", "analysis_verdict_filter": ["Malicious"]}
    )["samples"][0]

    assert iocs.last_request.qs == {"ioc_severity": ["malicious"]}
    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [1]


def test_unfetchable_child_is_recorded_on_the_parent(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])
    requests_mock.get(f"{BASE_URL}/rest/sample/43", status_code=404, json={"error_msg": "gone"})

    sample = make_action().run({"samples": [{"sample_id": 42}]})["samples"][0]

    assert "child_sample:43" in sample["errors"]
    assert sample["sample_child_samples"] == []
    assert sample["sample_iocs"]["iocs"]["urls"]  # parent report still complete

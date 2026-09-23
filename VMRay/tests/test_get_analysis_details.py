from vmray_modules.get_analysis_details_action import GetAnalysisDetails
from vmray_modules.models import VMRayConfiguration, VMRayModule

BASE_URL = "https://eu.cloud.vmray.com"


def make_module():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return m


def mock_base_sample(requests_mock, **overrides):
    data = {"sample_id": 42, "sample_verdict": "malicious", "sample_child_relations_truncated": False}
    data.update(overrides)
    requests_mock.get(f"{BASE_URL}/rest/sample/42", json={"result": "ok", "data": data})


def test_full_fan_out_all_sections_succeed(requests_mock):
    mock_base_sample(requests_mock)
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/vtis",
        json={"result": "ok", "data": {"threat_indicators": [{"category": "Injection"}]}},
    )
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/iocs",
        json={"result": "ok", "data": {"iocs": {"urls": [{"url": "http://evil.example"}]}}},
    )
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/mitre_attack",
        json={"result": "ok", "data": {"mitre_attack_techniques": [{"id": "T1055"}]}},
    )
    action = GetAnalysisDetails(module=make_module())

    result = action.run({"sample_id": 42})

    assert result["sample_id"] == 42
    assert len(result["threat_indicators"]) == 1
    assert len(result["iocs"]["urls"]) == 1
    assert len(result["mitre_attack_techniques"]) == 1
    assert result["errors"] == {}


def test_toggles_skip_calls(requests_mock):
    mock_base_sample(requests_mock)
    # deliberately no mocks registered for vtis/iocs/mitre_attack — a real
    # HTTP call to any of them would raise NoMockAddress and fail the test
    action = GetAnalysisDetails(module=make_module())

    result = action.run({"sample_id": 42, "include_vtis": False, "include_iocs": False, "include_mitre_attack": False})

    assert result["threat_indicators"] == []
    assert result["errors"] == {}


def test_one_section_failing_does_not_abort_the_others(requests_mock):
    mock_base_sample(requests_mock)
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/vtis",
        json={"result": "ok", "data": {"threat_indicators": [{"category": "Injection"}]}},
    )
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", status_code=500, json={"error_msg": "internal error"})
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/mitre_attack",
        json={"result": "ok", "data": {"mitre_attack_techniques": [{"id": "T1055"}]}},
    )
    action = GetAnalysisDetails(module=make_module())

    result = action.run({"sample_id": 42})

    # the two healthy sections still populated
    assert len(result["threat_indicators"]) == 1
    assert len(result["mitre_attack_techniques"]) == 1
    # the failed one is empty (default) and recorded in errors, not swallowed silently
    assert result["iocs"]["urls"] == []
    assert "iocs" in result["errors"]


def test_recursive_children_merge_into_base_names(requests_mock):
    mock_base_sample(requests_mock, sample_threat_names=["Emotet"])
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/threat_names",
        json={
            "result": "ok",
            "data": {
                "sample_threat_names": [{"threat_name": "Emotet"}],
                "children_threat_names": [{"threat_name": "TrickBot"}],
            },
        },
    )
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/classifications",
        json={
            "result": "ok",
            "data": {"sample_classifications": [], "children_classifications": [{"classification_name": "Trojan"}]},
        },
    )
    action = GetAnalysisDetails(module=make_module())

    result = action.run(
        {
            "sample_id": 42,
            "include_vtis": False,
            "include_iocs": False,
            "include_mitre_attack": False,
            "include_recursive": True,
        }
    )

    assert set(result["sample_threat_names"]) == {"Emotet", "TrickBot"}
    assert result["sample_classifications"] == ["Trojan"]


def test_truncated_relations_triggers_fallback_call(requests_mock):
    mock_base_sample(requests_mock, sample_child_relations_truncated=True)
    requests_mock.get(
        f"{BASE_URL}/rest/sample_relation/sample/42",
        json={"result": "ok", "data": [{"child_sample_id": 99, "relation_type": "dropped"}]},
    )
    action = GetAnalysisDetails(module=make_module())

    result = action.run({"sample_id": 42, "include_vtis": False, "include_iocs": False, "include_mitre_attack": False})

    assert result["sample_child_relations"] == [{"child_sample_id": 99, "relation_type": "dropped"}]


def test_not_truncated_never_calls_relations_fallback(requests_mock):
    """No mock registered for sample_relation — a call there would raise
    NoMockAddress and fail the test, proving the fallback is genuinely
    conditional on the truncated flag."""
    mock_base_sample(requests_mock, sample_child_relations_truncated=False)
    action = GetAnalysisDetails(module=make_module())

    action.run({"sample_id": 42, "include_vtis": False, "include_iocs": False, "include_mitre_attack": False})

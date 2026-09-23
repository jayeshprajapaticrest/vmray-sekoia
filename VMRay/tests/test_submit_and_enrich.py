from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.submit_and_enrich_action import SubmitAndEnrich

BASE_URL = "https://eu.cloud.vmray.com"


def make_module():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return m


def submit_response(submissions=None, samples=None, errors=None):
    return {
        "result": "ok",
        "data": {"submissions": submissions or [], "samples": samples or [], "jobs": [], "errors": errors or []},
    }


def test_happy_path_submits_waits_and_enriches(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(submissions=[{"submission_id": 111}], samples=[{"sample_id": 42}]),
    )
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json={"result": "ok", "data": {"submission_finished": True}})
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42",
        json={"result": "ok", "data": {"sample_id": 42, "sample_verdict": "malicious"}},
    )
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/vtis",
        json={"result": "ok", "data": {"threat_indicators": [{"category": "Injection"}]}},
    )
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json={"result": "ok", "data": {"iocs": {}}})
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42/mitre_attack", json={"result": "ok", "data": {"mitre_attack_techniques": []}}
    )
    action = SubmitAndEnrich(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload", "pull_time": 0.001})

    assert result["submission_id"] == 111
    assert result["sample_id"] == 42
    assert result["analysis"]["sample_verdict"] == "malicious"
    assert len(result["analysis"]["threat_indicators"]) == 1
    assert action.outputs == {"completed": True}


def test_submission_failed_short_circuits_before_enrichment(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(errors=[{"submission_filename": "x", "error_msg": "quota exceeded"}]),
    )
    # no /sample/{id} mock registered — a call there would fail the test
    action = SubmitAndEnrich(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload"})

    assert result["analysis"] is None
    assert result["submission_id"] is None
    assert action.outputs == {"submission_failed": True}


def test_timeout_short_circuits_before_enrichment(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(submissions=[{"submission_id": 111}], samples=[{"sample_id": 42}]),
    )
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json={"result": "ok", "data": {"submission_finished": False}})
    # no /sample/42/vtis etc mocks — enrichment must never be attempted
    action = SubmitAndEnrich(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload", "timeout": 0.02, "pull_time": 0.005})

    assert result["timed_out"] is True
    assert result["analysis"] is None
    assert action.outputs == {"timed_out": True}


def test_missing_sample_id_after_successful_submission(requests_mock):
    """Submission finishes but the submit response never carried a sample_id
    (empty samples[]) — distinct from submission_failed, and enrichment
    cannot proceed without one."""
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(submissions=[{"submission_id": 111}], samples=[]),
    )
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json={"result": "ok", "data": {"submission_finished": True}})
    action = SubmitAndEnrich(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload", "pull_time": 0.001})

    assert result["submission_id"] == 111
    assert result["sample_id"] is None
    assert result["analysis"] is None
    assert action.outputs == {"sample_id_missing": True}

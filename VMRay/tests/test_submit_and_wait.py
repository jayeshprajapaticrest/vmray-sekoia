from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.submit_and_wait_action import SubmitAndWait

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


def test_submit_and_wait_happy_path_finishes_on_first_poll(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(submissions=[{"submission_id": 111}], samples=[{"sample_id": 222}]),
    )
    requests_mock.get(
        f"{BASE_URL}/rest/submission/111",
        json={"result": "ok", "data": {"submission_finished": True}},
    )
    requests_mock.get(
        f"{BASE_URL}/rest/sample/222",
        json={"result": "ok", "data": {"sample_verdict": "malicious", "sample_vti_score": 98}},
    )
    action = SubmitAndWait(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload", "pull_time": 0.01})

    assert result["submission_id"] == 111
    assert result["sample_id"] == 222
    assert result["sample_verdict"] == "malicious"
    assert result["sample_vti_score"] == 98
    assert result["timed_out"] is False
    assert action.outputs == {"completed": True}


def test_submit_and_wait_polls_until_finished(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(submissions=[{"submission_id": 111}], samples=[{"sample_id": 222}]),
    )
    # not finished, then finished — requests_mock cycles through the list,
    # repeating the last entry once exhausted.
    requests_mock.get(
        f"{BASE_URL}/rest/submission/111",
        [
            {"json": {"result": "ok", "data": {"submission_finished": False}}},
            {"json": {"result": "ok", "data": {"submission_finished": False}}},
            {"json": {"result": "ok", "data": {"submission_finished": True}}},
        ],
    )
    requests_mock.get(f"{BASE_URL}/rest/sample/222", json={"result": "ok", "data": {"sample_verdict": "clean"}})
    action = SubmitAndWait(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload", "pull_time": 0.001})

    assert result["sample_verdict"] == "clean"
    assert action.outputs == {"completed": True}


def test_submit_and_wait_times_out(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(submissions=[{"submission_id": 111}], samples=[{"sample_id": 222}]),
    )
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json={"result": "ok", "data": {"submission_finished": False}})
    action = SubmitAndWait(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload", "timeout": 0.02, "pull_time": 0.005})

    assert result["timed_out"] is True
    assert result["submission_id"] == 111
    assert result["sample_id"] == 222
    assert result["sample_verdict"] is None  # never fetched — submission never finished
    assert action.outputs == {"timed_out": True}


def test_submit_and_wait_submission_failed(requests_mock):
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(errors=[{"submission_filename": "payload.url", "error_msg": "quota exceeded"}]),
    )
    action = SubmitAndWait(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload"})

    assert result["submission_id"] is None
    assert result["errors"] == [{"submission_filename": "payload.url", "error_msg": "quota exceeded"}]
    assert action.outputs == {"submission_failed": True}

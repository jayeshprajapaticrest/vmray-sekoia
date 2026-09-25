import json
from urllib.parse import parse_qs

from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.submit_url_sample_action import SubmitUrlSample

BASE_URL = "https://eu.cloud.vmray.com"
URL = "http://evil.example/payload"


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return SubmitUrlSample(module=m)


def ok(data):
    return {"result": "ok", "data": data}


def mock_submit(requests_mock, submission_ids=(), errors=()):
    return requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=ok({"submissions": [{"submission_id": i} for i in submission_ids], "errors": list(errors)}),
    )


def finished(submission_id, sample_id, **extra):
    return {
        "json": ok(
            {"submission_id": submission_id, "submission_finished": True, "submission_sample_id": sample_id, **extra}
        )
    }


def running(submission_id):
    return {"json": ok({"submission_id": submission_id, "submission_finished": False})}


def test_submits_polls_until_finished_and_returns_submissions(requests_mock):
    mock_submit(requests_mock, [111])
    poll = requests_mock.get(
        f"{BASE_URL}/rest/submission/111",
        [running(111), finished(111, 222, submission_verdict="malicious", submission_score=100)],
    )
    action = make_action()

    result = action.run({"sample_url": URL, "query_retry_wait": 0.01})

    assert poll.call_count == 2
    assert result["sample_ids"] == [222]
    assert result["submissions"][0]["submission_verdict"] == "malicious"
    assert result["timed_out"] is False
    assert action.outputs == {"completed": True}


def test_waits_for_every_submission_in_the_response(requests_mock):
    mock_submit(requests_mock, [111, 112])
    requests_mock.get(f"{BASE_URL}/rest/submission/111", [finished(111, 222)])
    requests_mock.get(f"{BASE_URL}/rest/submission/112", [running(112), running(112), finished(112, 223)])

    result = make_action().run({"sample_url": URL, "query_retry_wait": 0.01})

    assert result["sample_ids"] == [222, 223]
    assert result["pending_submission_ids"] == []


def test_timeout_returns_finished_and_pending(requests_mock):
    mock_submit(requests_mock, [111, 112])
    requests_mock.get(f"{BASE_URL}/rest/submission/111", [finished(111, 222)])
    requests_mock.get(f"{BASE_URL}/rest/submission/112", [running(112)])
    action = make_action()

    result = action.run({"sample_url": URL, "query_retry_wait": 0.01, "timeout": 0.05})

    assert result["timed_out"] is True
    assert result["sample_ids"] == [222]
    assert result["pending_submission_ids"] == [112]
    assert action.outputs == {"timed_out": True}


def test_rejected_submission_takes_submission_failed_branch(requests_mock):
    mock_submit(requests_mock, [], errors=[{"submission_filename": "payload.url", "error_msg": "quota exceeded"}])
    action = make_action()

    result = action.run({"sample_url": URL})

    assert result["errors"] == [{"submission_filename": "payload.url", "error_msg": "quota exceeded"}]
    assert result["sample_ids"] == []
    assert action.outputs == {"submission_failed": True}


def test_sends_reference_submission_parameters(requests_mock):
    submit = mock_submit(requests_mock, [111])
    requests_mock.get(f"{BASE_URL}/rest/submission/111", [finished(111, 222)])

    make_action().run(
        {
            "sample_url": URL,
            "tags": ["alert-AL1"],
            "max_recursive_samples": 10,
            "analysis_timeout": 120,
            "net_scheme_name": "Isolated",
        }
    )

    form = parse_qs(submit.last_request.text)
    assert form["sample_url"] == [URL]
    assert form["tags"] == ["alert-AL1"]
    assert form["reanalyze"] == ["True"]  # reference default: always a fresh analysis
    assert form["shareable"] == ["False"]
    assert form["max_recursive_samples"] == ["10"]
    assert json.loads(form["user_config"][0]) == {"net_scheme_name": "Isolated", "timeout": 120}

from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.submit_file_action import SubmitFile
from vmray_modules.submit_url_action import SubmitUrl

BASE_URL = "https://eu.cloud.vmray.com"


def make_module():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return m


def submit_response(submissions=None, samples=None, jobs=None, errors=None):
    return {
        "result": "ok",
        "data": {
            "submissions": submissions or [],
            "samples": samples or [],
            "jobs": jobs or [],
            "errors": errors or [],
        },
    }


def test_submit_url_happy_path(requests_mock):
    m = requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(
            submissions=[{"submission_id": 111}],
            samples=[{"sample_id": 222}],
            jobs=[{"job_id": 1}, {"job_id": 2}],
        ),
    )
    action = SubmitUrl(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload"})

    assert result["submission_id"] == 111
    assert result["sample_id"] == 222
    assert result["job_ids"] == [1, 2]
    assert result["errors"] == []
    # default traceability tag applied
    assert m.last_request.text is not None
    assert "sekoia" in m.last_request.text


def test_submit_url_custom_tags(requests_mock):
    m = requests_mock.post(f"{BASE_URL}/rest/sample/submit", json=submit_response())
    action = SubmitUrl(module=make_module())

    action.run({"sample_url": "http://evil.example/payload", "tags": ["alert-AL2026001"]})

    assert "alert-AL2026001" in m.last_request.text
    assert "sekoia" not in m.last_request.text  # explicit tags replace the default, not append


def test_submit_url_200_with_errors_is_not_silently_swallowed(requests_mock):
    """A 200 does not mean success — the errors array must surface."""
    requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(errors=[{"submission_filename": "payload.url", "error_msg": "quota exceeded"}]),
    )
    action = SubmitUrl(module=make_module())

    result = action.run({"sample_url": "http://evil.example/payload"})

    assert result["submission_id"] is None
    assert result["errors"] == [{"submission_filename": "payload.url", "error_msg": "quota exceeded"}]


def test_submit_file_reads_from_data_path(requests_mock, data_storage):
    from pathlib import Path

    Path(data_storage, "sample.exe").write_bytes(b"fake-sample-bytes")
    m = requests_mock.post(
        f"{BASE_URL}/rest/sample/submit",
        json=submit_response(submissions=[{"submission_id": 333}], samples=[{"sample_id": 444}]),
    )
    action = SubmitFile(module=make_module())

    result = action.run({"file_name": "sample.exe"})

    assert result["submission_id"] == 333
    assert result["sample_id"] == 444
    assert b"fake-sample-bytes" in m.last_request.body

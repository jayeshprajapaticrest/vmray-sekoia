import json
from urllib.parse import parse_qs

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


# -- submission options -------------------------------------------------------


def test_submit_url_sends_every_submission_option(requests_mock):
    m = requests_mock.post(f"{BASE_URL}/rest/sample/submit", json=submit_response())
    action = SubmitUrl(module=make_module())

    action.run(
        {
            "sample_url": "http://evil.example/payload",
            "enable_reputation": True,
            "enable_whois": False,
            "analyzer_mode": "reputation_static_dynamic",
            "known_malicious": True,
            "known_benign": False,
            "max_jobs": 1,
            "archive_action": "compound_sample",
            "archive_password": "malware",
            "shareable": True,
            "net_scheme_name": "Isolated",
        }
    )

    form = parse_qs(m.last_request.text)
    assert form["enable_reputation"] == ["True"]
    assert form["enable_whois"] == ["False"]
    assert form["analyzer_mode"] == ["reputation_static_dynamic"]
    assert form["known_malicious"] == ["True"]
    assert form["known_benign"] == ["False"]
    assert form["max_jobs"] == ["1"]
    assert form["archive_action"] == ["compound_sample"]
    assert form["archive_password"] == ["malware"]
    assert form["shareable"] == ["True"]
    assert json.loads(form["user_config"][0]) == {"net_scheme_name": "Isolated"}
    assert "net_scheme_name" not in form  # user_config only, never a top-level field


def test_submit_url_unset_options_are_omitted_and_shareable_defaults_off(requests_mock):
    m = requests_mock.post(f"{BASE_URL}/rest/sample/submit", json=submit_response())
    action = SubmitUrl(module=make_module())

    action.run({"sample_url": "http://evil.example/payload"})

    form = parse_qs(m.last_request.text)
    assert form["shareable"] == ["False"]  # always sent, so VMRay's per-user default never leaks the hash
    for unset in (
        "enable_reputation",
        "enable_whois",
        "analyzer_mode",
        "known_malicious",
        "known_benign",
        "max_jobs",
        "archive_action",
        "archive_password",
        "user_config",
    ):
        assert unset not in form


def test_submit_file_sends_submission_options(requests_mock, data_storage):
    from pathlib import Path

    Path(data_storage, "sample.zip").write_bytes(b"fake-archive-bytes")
    m = requests_mock.post(f"{BASE_URL}/rest/sample/submit", json=submit_response())
    action = SubmitFile(module=make_module())

    action.run({"file_name": "sample.zip", "archive_action": "separate_samples", "net_scheme_name": "Isolated"})

    body = m.last_request.body
    assert b'name="archive_action"' in body and b"separate_samples" in body
    assert b'name="user_config"' in body and b"Isolated" in body

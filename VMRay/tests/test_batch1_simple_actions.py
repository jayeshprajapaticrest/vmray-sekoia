"""Tests for the four simple, single-call actions: SearchSample, GetQuota,
GetSample, GetReportPdf. Mocked at the requests transport layer via
requests_mock — this also exercises the client's real error-envelope logic
(_check_response), not a mocked-out client."""

from pathlib import Path

import pytest

from vmray_modules.get_quota_action import GetQuota
from vmray_modules.get_report_pdf_action import GetReportPdf
from vmray_modules.get_sample_action import GetSample
from vmray_modules.models import VMRayConfiguration, VMRayModule
from vmray_modules.search_sample_action import SearchSample

BASE_URL = "https://eu.cloud.vmray.com"


@pytest.fixture
def module():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return m


def ok_envelope(data):
    return {"result": "ok", "data": data}


# -- SearchSample -----------------------------------------------------------


def test_search_sample_found(requests_mock, module):
    requests_mock.get(
        f"{BASE_URL}/rest/sample/sha256/{'a' * 64}",
        json=ok_envelope([{"sample_id": 42, "sample_verdict": "malicious"}]),
    )
    action = SearchSample(module=module)

    result = action.run({"hash": "a" * 64})

    assert result["found"] is True
    assert result["analysis"]["sample_id"] == 42
    assert action.outputs == {"found": True}


def test_search_sample_not_found(requests_mock, module):
    requests_mock.get(f"{BASE_URL}/rest/sample/sha256/{'a' * 64}", json=ok_envelope([]))
    action = SearchSample(module=module)

    result = action.run({"hash": "a" * 64})

    assert result["found"] is False
    assert result["analysis"] is None
    assert action.outputs == {"not_found": True}


def test_search_sample_picks_correct_hash_endpoint(requests_mock, module):
    """32/40/64-char hashes route to md5/sha1/sha256 respectively — client-level
    logic, exercised here through the action rather than re-tested directly."""
    requests_mock.get(f"{BASE_URL}/rest/sample/md5/{'a' * 32}", json=ok_envelope([{"sample_id": 1}]))
    action = SearchSample(module=module)

    result = action.run({"hash": "a" * 32})

    assert result["found"] is True


# -- GetQuota -----------------------------------------------------------------


def test_get_quota(requests_mock, module):
    requests_mock.get(f"{BASE_URL}/rest/api_key/quota", json=ok_envelope({"quota_limit": 100, "used_quota": 7}))
    action = GetQuota(module=module)

    result = action.run({})

    assert result == {"quota_limit": 100, "used_quota": 7}


# -- GetSample ----------------------------------------------------------------


def test_get_sample_writes_zip_to_data_path(requests_mock, module, data_storage):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/file", content=b"fake-encrypted-zip-bytes")
    action = GetSample(module=module)

    result = action.run({"sample_id": 42})

    written = Path(data_storage) / result["file_path"]
    assert written.read_bytes() == b"fake-encrypted-zip-bytes"
    assert result["file_path"].startswith("vmray-sample-42-")
    assert result["file_path"].endswith(".zip")


def test_get_sample_passes_encryption_password(requests_mock, module, data_storage):
    m = requests_mock.get(f"{BASE_URL}/rest/sample/42/file", content=b"x")
    action = GetSample(module=module)

    action.run({"sample_id": 42, "encryption_password": "custom-pw"})

    assert m.last_request.qs == {"encryption_password": ["custom-pw"]}


# -- GetReportPdf ---------------------------------------------------------------


def test_get_report_pdf_writes_pdf_to_data_path(requests_mock, module, data_storage):
    requests_mock.get(f"{BASE_URL}/rest/sample/42/report", content=b"%PDF-fake-report")
    action = GetReportPdf(module=module)

    result = action.run({"sample_id": 42})

    written = Path(data_storage) / result["file_path"]
    assert written.read_bytes() == b"%PDF-fake-report"
    assert result["file_path"].endswith(".pdf")

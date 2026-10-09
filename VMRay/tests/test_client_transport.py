"""Transport-level tests for VMRayClient: does verify_ssl thread through,
does a 4xx surface distinctly from a 5xx, does the error envelope get
checked on a 200. Retry/backoff behaviour is deliberately NOT tested here —
see the note below and test_client_retry_real_transport.py.
"""

import pytest

from vmray_modules.client import BadResponseError, VMRayAPIError, VMRayClient

BASE_URL = "https://eu.cloud.vmray.com"


def test_requests_mock_does_not_exercise_our_retry_adapter(requests_mock):
    """Documented limitation, not a bug: requests_mock patches the transport
    at a level that bypasses any HTTPAdapter we mounted, so a persistent 5xx
    here fails on the FIRST attempt — the opposite of what our real retry
    adapter does. Confirmed directly (this test used to assert the opposite
    and failed) so nobody re-discovers this the hard way and trusts a
    requests_mock-based test to cover retry/Retry-After behaviour again.
    Real retry/backoff coverage lives in test_client_retry_real_transport.py,
    against a real local socket — the only way to prove it honestly.
    """
    requests_mock.get(
        f"{BASE_URL}/rest/system_info",
        [
            {"status_code": 500, "json": {"error_msg": "boom"}},
            {"json": {"result": "ok", "data": {"version": "2026.2.1"}}},
        ],
    )
    client = VMRayClient(base_url=BASE_URL, api_key="x")

    with pytest.raises(BadResponseError):
        client.system_info()

    assert requests_mock.call_count == 1  # no retry happened — this is the limitation, not a passing feature


def test_retry_exhaustion_raises_bad_response_error(requests_mock):
    """Persistent 5xx must still surface as a clear error, not hang or
    silently return an empty result — true regardless of whether retries
    fired first (they don't, under requests_mock; they do for real, see
    test_client_retry_real_transport.py)."""
    requests_mock.get(f"{BASE_URL}/rest/system_info", status_code=503, json={"error_msg": "down"})
    client = VMRayClient(base_url=BASE_URL, api_key="x")

    with pytest.raises(BadResponseError):
        client.system_info()


def test_4xx_does_not_retry_and_raises_immediately(requests_mock):
    """400/404 are not in status_forcelist — a single attempt, no retry
    burned on an error retrying can never fix."""
    requests_mock.get(f"{BASE_URL}/rest/sample/999999999", status_code=404, json={"error_msg": "unknown sample"})
    client = VMRayClient(base_url=BASE_URL, api_key="x")

    with pytest.raises(BadResponseError) as exc_info:
        client.get_sample(999999999)

    assert requests_mock.call_count == 1
    assert exc_info.value.status_code == 404


def test_200_with_error_envelope_raises_api_error(requests_mock):
    """Layer 2 of the error contract: a 200 whose body says result != "ok"
    must still be treated as a failure, not a success."""
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42",
        status_code=200,
        json={"result": "error", "error_msg": "sample not accessible"},
    )
    client = VMRayClient(base_url=BASE_URL, api_key="x")

    with pytest.raises(VMRayAPIError):
        client.get_sample(42)


def test_verify_ssl_false_threads_through_to_the_session():
    client = VMRayClient(base_url=BASE_URL, api_key="x", verify_ssl=False)

    assert client.session.verify is False


def test_verify_ssl_defaults_true():
    client = VMRayClient(base_url=BASE_URL, api_key="x")

    assert client.session.verify is True


# -- review findings ------------------------------------------------------------------------------------


def test_every_request_has_a_timeout(requests_mock):
    requests_mock.get("https://vmray.example/rest/sample/1", json={"result": "ok", "data": {"sample_id": 1}})

    VMRayClient("https://vmray.example", "k").get_sample(1)

    assert requests_mock.last_request.timeout == (10, 120)


def test_network_failure_is_a_client_error(requests_mock):
    import requests

    from vmray_modules.client import VMRayClientError

    requests_mock.get("https://vmray.example/rest/sample/1", exc=requests.ConnectTimeout("slow"))

    with pytest.raises(VMRayClientError, match="could not be reached"):
        VMRayClient("https://vmray.example", "k").get_sample(1)


@pytest.mark.parametrize("body", ["<html>login</html>", "[1, 2]"])
def test_a_body_that_is_not_a_json_object_is_an_api_error(requests_mock, body):
    requests_mock.get("https://vmray.example/rest/sample/1", text=body)

    with pytest.raises(VMRayAPIError):
        VMRayClient("https://vmray.example", "k").get_sample(1)


def test_base_url_given_with_rest_is_not_doubled(requests_mock):
    requests_mock.get("https://vmray.example/rest/sample/1", json={"result": "ok", "data": {"sample_id": 1}})

    assert VMRayClient("https://vmray.example/rest/", "k").get_sample(1) == {"sample_id": 1}


def test_submit_is_not_retried_on_a_server_error():
    """Retrying a POST after a 502 could submit — and bill — the same URL twice."""
    retry = VMRayClient("https://vmray.example", "k").session.get_adapter("https://vmray.example").max_retries

    assert "POST" not in retry.allowed_methods
    assert retry.retry_after_max <= 120 and retry.backoff_max <= 30

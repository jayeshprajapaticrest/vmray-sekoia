from vmray_modules.get_samples_by_hash_action import GetSamplesByHash
from vmray_modules.models import VMRayConfiguration, VMRayModule

BASE_URL = "https://eu.cloud.vmray.com"
SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return GetSamplesByHash(module=m)


def mock_lookup(requests_mock, hash_type, value, samples):
    return requests_mock.get(f"{BASE_URL}/rest/sample/{hash_type}/{value}", json={"result": "ok", "data": samples})


def test_checks_every_hash_and_returns_found_and_not_found(requests_mock):
    mock_lookup(requests_mock, "sha256", SHA256, [{"sample_id": 42, "sample_verdict": "malicious"}])
    mock_lookup(requests_mock, "md5", MD5, [])
    action = make_action()

    result = action.run({"hashes": [SHA256, MD5]})

    assert result["found"] is True
    assert result["sample_ids"] == [42]
    assert result["samples"][0]["sample_verdict"] == "malicious"
    assert result["not_found"] == [MD5]
    assert action.outputs == {"found": True}


def test_lookup_only_no_detail_calls(requests_mock):
    """Only the hash endpoint is mocked — any /sample/{id}, /vtis, /iocs call would raise NoMockAddress."""
    mock_lookup(requests_mock, "sha256", SHA256, [{"sample_id": 42}])

    make_action().run({"hashes": [SHA256]})

    assert requests_mock.call_count == 1


def test_every_matching_sample_is_returned(requests_mock):
    mock_lookup(requests_mock, "sha256", SHA256, [{"sample_id": 42}, {"sample_id": 43}])

    result = make_action().run({"hashes": [SHA256]})

    assert result["sample_ids"] == [42, 43]


def test_duplicates_and_case_are_collapsed_before_lookup(requests_mock):
    lookup = mock_lookup(requests_mock, "sha256", SHA256, [{"sample_id": 42}])

    make_action().run({"hashes": [SHA256, SHA256.upper(), f"  {SHA256} ", ""]})

    assert lookup.call_count == 1


def test_hashes_of_the_same_file_return_one_sample(requests_mock):
    """md5 and sha256 of one file resolve to the same VMRay sample."""
    mock_lookup(requests_mock, "sha256", SHA256, [{"sample_id": 42}])
    mock_lookup(requests_mock, "md5", MD5, [{"sample_id": 42}])

    result = make_action().run({"hashes": [SHA256, MD5]})

    assert result["sample_ids"] == [42]
    assert len(result["samples"]) == 1


def test_nothing_found_takes_not_found_branch(requests_mock):
    mock_lookup(requests_mock, "sha1", SHA1, [])
    action = make_action()

    result = action.run({"hashes": [SHA1]})

    assert result["found"] is False
    assert result["sample_ids"] == []
    assert action.outputs == {"not_found": True}


def test_bad_or_failing_hash_is_recorded_and_the_rest_still_checked(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/md5/{MD5}", status_code=500, json={"error_msg": "boom"})
    mock_lookup(requests_mock, "sha256", SHA256, [{"sample_id": 42}])

    result = make_action().run({"hashes": ["not-a-hash", MD5, SHA256]})

    assert set(result["errors"]) == {"not-a-hash", MD5}
    assert result["sample_ids"] == [42]

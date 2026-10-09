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


# -- review findings ------------------------------------------------------------------------------------


def test_every_lookup_failing_is_an_error_not_not_found(requests_mock):
    """A wrong API key or VMRay being down must not read as "VMRay never saw these hashes"."""
    import pytest

    from vmray_modules.client import VMRayClientError

    requests_mock.get(f"{BASE_URL}/rest/sample/sha256/{SHA256}", status_code=401, json={"error_msg": "bad key"})
    action = make_action()

    with pytest.raises(VMRayClientError, match="No hash could be looked up"):
        action.run({"hashes": [SHA256]})
    assert action.outputs == {}


def test_one_failing_hash_keeps_the_others(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/sha256/{SHA256}", text="<html>proxy</html>")
    mock_lookup(requests_mock, "md5", MD5, [{"sample_id": 42}])

    result = make_action().run({"hashes": [SHA256, MD5]})

    assert result["sample_ids"] == [42]
    assert "not JSON" in result["errors"][SHA256] or "other than JSON" in result["errors"][SHA256]


def test_a_single_hash_and_empty_values_are_accepted(requests_mock):
    mock_lookup(requests_mock, "md5", MD5, [{"sample_id": 42}])

    assert make_action().run({"hashes": MD5})["sample_ids"] == [42]
    assert make_action().run({"hashes": [MD5, None, "", "  "]})["sample_ids"] == [42]


def test_a_non_hex_value_is_never_put_in_the_url(requests_mock):
    result = make_action().run({"hashes": ["../../submission/" + "1" * 15, "z" * 32]})

    assert set(result["errors"]) == {"../../submission/" + "1" * 15, "z" * 32}
    assert requests_mock.call_count == 0


def test_matches_without_a_sample_id_are_ignored(requests_mock):
    mock_lookup(requests_mock, "md5", MD5, [{"no_id": True}, "x", {"sample_id": 42}])

    assert make_action().run({"hashes": [MD5]})["sample_ids"] == [42]

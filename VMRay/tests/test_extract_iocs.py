import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.extract_iocs_action import ExtractIocs, extract_iocs, iocs_to_indicators
from vmray_modules.models import IOCSet

CLEAN_CHILD = {
    "sample_id": 44,
    "sample_verdict": "clean",
    "sample_sha256hash": "e" * 64,
    "sample_iocs": {"iocs": {"domains": [{"domain": "cdn.example", "severity": "suspicious"}]}},
}
MALICIOUS_CHILD = {
    "sample_id": 43,
    "sample_verdict": "malicious",
    "sample_sha256hash": "d" * 64,
    "sample_iocs": {"iocs": {"ips": [{"ip_address": "203.0.113.9", "severity": "malicious"}]}},
    "sample_child_samples": [CLEAN_CHILD],
}
REPORT = {
    "samples": [
        {
            "sample_id": 42,
            "sample_verdict": "malicious",
            "sample_sha256hash": "a" * 64,
            "sample_iocs": {
                "iocs": {
                    "domains": [
                        {"domain": "evil.example", "severity": "malicious"},
                        {"domain": "sus.example", "severity": "suspicious"},
                        {"domain": "unrated.example"},
                    ],
                    "files": [
                        {"filename": "dropped.exe", "severity": "malicious", "hashes": [{"sha256_hash": "f" * 64}]}
                    ],
                }
            },
            "sample_child_samples": [MALICIOUS_CHILD],
        },
    ]
}


def values(indicators):
    return {(i.type, i.value) for i in indicators}


def test_only_malicious_iocs_by_default():
    result = values(extract_iocs(REPORT, ["malicious"], include_child_iocs=True))

    assert ("domain", "evil.example") in result
    assert ("hash", "f" * 64) in result  # dropped file from the IOC set
    assert ("IP address", "203.0.113.9") in result  # malicious IOC of a child sample
    assert ("hash", "d" * 64) in result  # malicious child's own SHA256
    assert ("domain", "sus.example") not in result  # suspicious IOC
    assert ("domain", "unrated.example") not in result  # no severity
    assert ("domain", "cdn.example") not in result  # suspicious IOC of the clean grandchild
    assert ("hash", "e" * 64) not in result  # clean grandchild's SHA256


def test_both_severities():
    result = values(extract_iocs(REPORT, ["malicious", "Suspicious"], include_child_iocs=True))

    assert {("domain", "evil.example"), ("domain", "sus.example"), ("domain", "cdn.example")} <= result
    assert ("domain", "unrated.example") not in result
    assert ("hash", "e" * 64) not in result  # the grandchild itself is clean


def test_empty_filter_extracts_every_ioc():
    result = values(extract_iocs(REPORT, [], include_child_iocs=True))

    assert {("domain", "unrated.example"), ("domain", "cdn.example"), ("hash", "e" * 64)} <= result


def test_unknown_severities_are_ignored():
    """The analyzer's rule: only 'malicious' and 'suspicious' count; with none left, nothing is filtered."""
    assert values(extract_iocs(REPORT, ["bogus"], include_child_iocs=True)) == values(
        extract_iocs(REPORT, [], include_child_iocs=True)
    )


def test_top_level_sample_hash_is_not_added():
    """The top-level sample is the alert's own observable — only child samples add their SHA256."""
    result = values(extract_iocs(REPORT, [], include_child_iocs=True))

    assert ("hash", "a" * 64) not in result


def test_child_iocs_can_be_excluded():
    result = values(extract_iocs(REPORT, ["malicious"], include_child_iocs=False))

    assert ("IP address", "203.0.113.9") not in result
    assert ("hash", "d" * 64) not in result
    assert ("domain", "evil.example") in result


def test_indicators_are_deduplicated():
    report = {
        "samples": [
            {"sample_iocs": {"iocs": {"domains": [{"domain": "evil.example", "severity": "malicious"}]}}},
            {"sample_iocs": {"iocs": {"domains": [{"domain": "evil.example", "severity": "malicious"}]}}},
        ]
    }

    assert len(extract_iocs(report, ["malicious"], include_child_iocs=True)) == 1


def test_action_defaults_to_malicious_iocs_and_children():
    result = ExtractIocs().run({"report": REPORT})

    assert {"type": "domain", "value": "evil.example"} in result["indicators"]
    assert {"type": "IP address", "value": "203.0.113.9"} in result["indicators"]
    assert {"type": "domain", "value": "sus.example"} not in result["indicators"]


def test_action_groups_indicators_by_type():
    """One group per non-empty type, in push order — the playbook's Foreach makes one add_ioc call per group."""
    result = ExtractIocs().run({"report": REPORT})

    assert result["indicator_groups"] == [
        {"type": "hash", "indicators": ["f" * 64, "d" * 64]},
        {"type": "IP address", "indicators": ["203.0.113.9"]},
        {"type": "domain", "indicators": ["evil.example"]},
    ]


def test_action_has_no_groups_without_indicators():
    result = ExtractIocs().run({"report": {"samples": [{"sample_verdict": "clean"}]}})

    assert result["indicators"] == []
    assert result["indicator_groups"] == []


def test_action_requires_a_report():
    with pytest.raises(MissingActionArgumentError):
        ExtractIocs().run({})


# -- iocs_to_indicators: per-category mapping and hash extraction (moved from the removed IocsToIndicators) --

FULL_IOCS = {
    "ips": [{"ip_address": "203.0.113.66"}],
    "domains": [{"domain": "evil.example"}],
    "urls": [{"url": "http://evil.example/payload"}],
    "email_addresses": [{"email_address": "attacker@evil.example"}],
    "emails": [{"sender": "other-attacker@evil.example"}],
    # VMRay's real file IOC shape (FileIOCSerializer): hashes is a list of per-content hash sets
    "files": [
        {
            "filename": "dropped.exe",
            "hashes": [{"md5_hash": "c" * 32, "sha1_hash": "b" * 40, "sha256_hash": "a" * 64, "ssdeep_hash": "3:x:y"}],
        }
    ],
    # these three categories have no Sekoia indicator_type and must never
    # produce output, no matter their shape
    "mutexes": [{"name": "Global\\mtx1"}],
    "registry": [{"key": "HKLM\\Software\\Evil"}],
    "processes": [{"name": "evil.exe"}],
}


def indicators_by_type(items, type_):
    return sorted(i.value for i in items if i.type == type_)


def test_full_mapping_covers_every_sekoia_type():
    iocs = IOCSet.model_validate(FULL_IOCS)
    indicators = iocs_to_indicators(iocs)

    by_type = {t: indicators_by_type(indicators, t) for t in ("IP address", "domain", "url", "email", "hash")}

    assert by_type["IP address"] == ["203.0.113.66"]
    assert by_type["domain"] == ["evil.example"]
    assert by_type["url"] == ["http://evil.example/payload"]
    assert by_type["email"] == ["attacker@evil.example", "other-attacker@evil.example"]
    assert by_type["hash"] == ["a" * 64]  # sha256 preferred over sha1/md5


def test_dropped_categories_never_appear():
    iocs = IOCSet.model_validate(FULL_IOCS)
    indicators = iocs_to_indicators(iocs)

    values = {i.value for i in indicators}
    assert "Global\\mtx1" not in values
    assert "HKLM\\Software\\Evil" not in values
    assert "evil.exe" not in values
    # ips+domains+urls+files (1 each) + email_addresses+emails (2 distinct emails) = 6
    assert len(indicators) == 6


def test_deduplicates_same_value_and_type():
    iocs = IOCSet.model_validate(
        {
            "domains": [{"domain": "evil.example"}, {"domain": "evil.example"}],
            "urls": [{"url": "http://evil.example/a"}],
        }
    )
    indicators = iocs_to_indicators(iocs)

    assert indicators_by_type(indicators, "domain") == ["evil.example"]


@pytest.mark.parametrize(
    "hashes,expected",
    [
        ([{"md5_hash": "c" * 32, "sha1_hash": "b" * 40, "sha256_hash": "a" * 64}], ["a" * 64]),  # sha256 preferred
        ([{"md5_hash": "c" * 32, "sha1_hash": "b" * 40}], ["b" * 40]),  # falls back to sha1
        ([{"md5_hash": "c" * 32}], ["c" * 32]),  # then md5
        ([{"sha256_hash": "a" * 64}, {"sha256_hash": "d" * 64}], ["a" * 64, "d" * 64]),  # one per file content
        ([{"ssdeep_hash": "3:x:y"}, "not-a-dict"], []),  # nothing Sekoia accepts
    ],
)
def test_file_hashes_from_vmray_shape(hashes, expected):
    iocs = IOCSet.model_validate({"files": [{"filename": "dropped.exe", "hashes": hashes}]})
    indicators = iocs_to_indicators(iocs)

    assert indicators_by_type(indicators, "hash") == expected


def test_item_missing_every_candidate_key_is_skipped_not_raised():
    iocs = IOCSet.model_validate(
        {
            "domains": [{"unexpected_field": "evil.example"}],
            "files": [{"unexpected_field": "no hash here"}],
        }
    )
    indicators = iocs_to_indicators(iocs)

    assert indicators == []

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.models import IOCSet
from vmray_modules.report_to_indicators_action import ReportToIndicators, iocs_to_indicators, report_to_indicators

CLEAN_CHILD = {
    "sample_id": 44,
    "sample_verdict": "clean",
    "sample_sha256hash": "e" * 64,
    "sample_iocs": {"iocs": {"domains": [{"domain": "cdn.example"}]}},
}
MALICIOUS_CHILD = {
    "sample_id": 43,
    "sample_verdict": "malicious",
    "sample_sha256hash": "d" * 64,
    "sample_iocs": {"iocs": {"ips": [{"ip_address": "203.0.113.9"}]}},
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
                    "domains": [{"domain": "evil.example"}],
                    "files": [{"hashes": [{"type": "sha256", "value": "f" * 64}]}],
                }
            },
            "sample_child_samples": [MALICIOUS_CHILD],
        },
        {
            "sample_id": 50,
            "sample_verdict": "suspicious",
            "sample_iocs": {"iocs": {"domains": [{"domain": "sus.example"}]}},
        },
    ]
}


def values(indicators):
    return {(i.type, i.value) for i in indicators}


def test_only_malicious_samples_contribute_by_default():
    result = values(report_to_indicators(REPORT, ["malicious"], include_child_samples=True))

    assert ("domain", "evil.example") in result
    assert ("hash", "f" * 64) in result  # dropped file from the IOC set
    assert ("IP address", "203.0.113.9") in result  # malicious child's IOCs
    assert ("hash", "d" * 64) in result  # malicious child's own SHA256
    assert ("domain", "cdn.example") not in result  # clean grandchild judged on its own verdict
    assert ("domain", "sus.example") not in result  # suspicious top-level sample


def test_top_level_sample_hash_is_not_added():
    """The top-level sample is the alert's own observable — only child samples add their SHA256."""
    result = values(report_to_indicators(REPORT, ["malicious"], include_child_samples=True))

    assert ("hash", "a" * 64) not in result


def test_children_can_be_excluded():
    result = values(report_to_indicators(REPORT, ["malicious"], include_child_samples=False))

    assert ("IP address", "203.0.113.9") not in result
    assert ("hash", "d" * 64) not in result
    assert ("domain", "evil.example") in result


def test_empty_verdicts_means_every_sample():
    result = values(report_to_indicators(REPORT, [], include_child_samples=True))

    assert ("domain", "sus.example") in result
    assert ("domain", "cdn.example") in result


def test_indicators_are_deduplicated():
    report = {
        "samples": [
            {"sample_verdict": "malicious", "sample_iocs": {"iocs": {"domains": [{"domain": "evil.example"}]}}},
            {"sample_verdict": "malicious", "sample_iocs": {"iocs": {"domains": [{"domain": "evil.example"}]}}},
        ]
    }

    assert len(report_to_indicators(report, ["malicious"], include_child_samples=True)) == 1


def test_action_defaults_to_malicious_only():
    result = ReportToIndicators().run({"report": REPORT})

    assert {"type": "domain", "value": "evil.example"} in result["indicators"]
    assert {"type": "domain", "value": "sus.example"} not in result["indicators"]


def test_action_requires_a_report():
    with pytest.raises(MissingActionArgumentError):
        ReportToIndicators().run({})


# -- iocs_to_indicators: per-category mapping and hash extraction (moved from the removed IocsToIndicators) --

FULL_IOCS = {
    "ips": [{"ip_address": "203.0.113.66"}],
    "domains": [{"domain": "evil.example"}],
    "urls": [{"url": "http://evil.example/payload"}],
    "email_addresses": [{"email_address": "attacker@evil.example"}],
    "emails": [{"sender": "other-attacker@evil.example"}],
    "files": [{"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32}],
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
    "file_item,expected",
    [
        ({"sha256": "a" * 64}, "a" * 64),
        ({"sha1": "b" * 40}, "b" * 40),  # falls back when sha256 absent
        ({"hashes": {"sha256": "a" * 64, "md5": "c" * 32}}, "a" * 64),  # nested dict form
        ({"hashes": [{"type": "SHA256", "value": "a" * 64}]}, "a" * 64),  # nested list form, case-insensitive
        ({"hashes": [{"type": "md5", "value": "c" * 32}]}, "c" * 32),  # only md5 available anywhere
    ],
)
def test_hash_extraction_shapes(file_item, expected):
    iocs = IOCSet.model_validate({"files": [file_item]})
    indicators = iocs_to_indicators(iocs)

    assert indicators_by_type(indicators, "hash") == [expected]


def test_item_missing_every_candidate_key_is_skipped_not_raised():
    iocs = IOCSet.model_validate(
        {
            "domains": [{"unexpected_field": "evil.example"}],
            "files": [{"unexpected_field": "no hash here"}],
        }
    )
    indicators = iocs_to_indicators(iocs)

    assert indicators == []

import json
from pathlib import Path

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.iocs_to_indicators_action import IocsToIndicators, iocs_to_indicators
from vmray_modules.models import IOCSet

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


def test_action_run_with_inline_iocs():
    action = IocsToIndicators()
    result = action.run({"iocs": FULL_IOCS})

    assert len(result["indicators"]) == 6


def test_action_run_with_full_analysis_details_shape():
    """The action also accepts a whole AnalysisDetails object with the IOC
    set nested under "iocs", not just the IOCSet directly."""
    action = IocsToIndicators()
    result = action.run({"iocs": {"sample_id": 1, "iocs": FULL_IOCS}})

    assert len(result["indicators"]) == 6


def test_action_run_with_iocs_path(data_storage):
    (Path(data_storage) / "iocs.json").write_text(json.dumps(FULL_IOCS))

    action = IocsToIndicators()
    result = action.run({"iocs_path": "iocs.json"})

    assert len(result["indicators"]) == 6


def test_action_run_missing_argument():
    action = IocsToIndicators()

    with pytest.raises(MissingActionArgumentError):
        action.run({})

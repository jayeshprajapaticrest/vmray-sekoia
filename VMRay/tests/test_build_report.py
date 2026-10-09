import base64
import io
import json as jsonlib
import re
from pathlib import Path

import pytest
from PIL import Image
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.build_report_action import BuildReport, ioc_severity
from vmray_modules.models import VMRayConfiguration, VMRayModule

BASE_URL = "https://eu.cloud.vmray.com"


def make_action():
    m = VMRayModule()
    m.configuration = VMRayConfiguration(base_url=BASE_URL, api_key="test-key")
    return BuildReport(module=m)


@pytest.fixture(autouse=True)
def storage(data_storage):
    """BuildReport writes the report to data_path — every test gets a fresh one."""
    return data_storage


def build(arguments):
    """Run BuildReport and return the report it wrote to data_path."""
    action = make_action()
    result = action.run(arguments)
    return jsonlib.loads(action.data_path.joinpath(result["report_path"]).read_bytes())


def ok(data):
    return {"result": "ok", "data": data}


def mock_full_sample(requests_mock, sample_id, children=(), latest_submission=True):
    """Every endpoint BuildReport calls for one sample. It has no screenshots: VMRay answers the
    analysis-archive lookup with a 404, which BuildReport must treat as "nothing to embed"."""
    r = requests_mock
    r.get(re.compile(rf"{BASE_URL}/rest/analysis/\d+/archive/.*"), status_code=404, json={"error_msg": "not found"})
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}",
        json=ok({"sample_id": sample_id, "sample_verdict": "malicious", "sample_child_sample_ids": list(children)}),
    )
    r.get(
        f"{BASE_URL}/rest/submission/sample/{sample_id}",
        json=ok(
            [
                {"submission_id": sample_id * 10, "submission_created": "2026-01-01T00:00:00"},
                {"submission_id": sample_id * 10 + 1, "submission_created": "2026-09-01T00:00:00"},
            ]
            if latest_submission
            else []
        ),
    )
    r.get(
        f"{BASE_URL}/rest/analysis/submission/{sample_id * 10 + 1}",
        json=ok(
            [{"analysis_id": 1, "analysis_verdict": "malicious"}, {"analysis_id": 2, "analysis_verdict": "clean"}]
        ),
    )
    r.get(f"{BASE_URL}/rest/analysis/sample/{sample_id}", json=ok([{"analysis_id": 9, "analysis_verdict": "clean"}]))
    r.get(f"{BASE_URL}/rest/sample/{sample_id}/vtis", json=ok({"threat_indicators": [{"operation": "x", "score": 5}]}))
    r.get(f"{BASE_URL}/rest/sample/{sample_id}/mitre_attack", json=ok({"mitre_attack_techniques": [{"id": "T1055"}]}))
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}/iocs",
        json=ok({"iocs": {"urls": [{"url": "http://evil.example", "severity": "malicious"}]}}),
    )
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}/classifications",
        json=ok(
            {
                "sample_classifications": [{"classification_name": "Downloader"}],
                "children_classifications": [{"classification_name": "Trojan"}],
            }
        ),
    )
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}/threat_names",
        json=ok({"sample_threat_names": [{"threat_name": "ClickFix"}], "children_threat_names": []}),
    )


def test_builds_full_report_from_samples(requests_mock):
    mock_full_sample(requests_mock, 42)

    result = build({"sample_ids": [42]})

    sample = result["samples"][0]
    assert sample["sample_id"] == 42
    assert sample["sample_verdict"] == "malicious"
    assert sample["sample_threat_indicators"]["threat_indicators"][0]["score"] == 5
    assert sample["sample_mitre_attack"]["mitre_attack_techniques"][0]["id"] == "T1055"
    assert sample["sample_iocs"]["iocs"]["urls"][0]["url"] == "http://evil.example"
    assert sample["sample_classifications"] == ["Downloader", "Trojan"]  # sample + children merged
    assert sample["sample_threat_names"] == ["ClickFix"]
    assert sample["errors"] == {}
    assert result["errors"] == {}


def test_analyses_come_from_the_latest_submission(requests_mock):
    mock_full_sample(requests_mock, 42)

    sample = build({"sample_ids": [42]})["samples"][0]

    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [1, 2]  # submission 421, not 420


def test_analyses_fall_back_to_all_when_no_submission(requests_mock):
    mock_full_sample(requests_mock, 42, latest_submission=False)

    sample = build({"sample_ids": [42]})["samples"][0]

    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [9]


def test_accepts_submission_ids(requests_mock):
    mock_full_sample(requests_mock, 42)
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json=ok({"submission_id": 111, "submission_sample_id": 42}))

    result = build({"submission_ids": [111]})

    assert [s["sample_id"] for s in result["samples"]] == [42]


def test_unresolvable_submission_is_recorded_and_others_still_built(requests_mock):
    mock_full_sample(requests_mock, 42)
    requests_mock.get(f"{BASE_URL}/rest/submission/110", status_code=404, json={"error_msg": "not found"})
    requests_mock.get(f"{BASE_URL}/rest/submission/111", json=ok({"submission_id": 111, "submission_sample_id": 42}))

    result = build({"submission_ids": [110, 111]})

    assert [s["sample_id"] for s in result["samples"]] == [42]
    assert "submission:110" in result["errors"]


def test_sample_ids_take_precedence_over_submission_ids(requests_mock):
    mock_full_sample(requests_mock, 42)
    # no mock for submission 111 — resolving it would raise NoMockAddress

    result = build({"sample_ids": [42], "submission_ids": [111]})

    assert [s["sample_id"] for s in result["samples"]] == [42]


@pytest.mark.parametrize("arguments", [{}, {"sample_ids": [], "submission_ids": []}])
def test_requires_sample_ids_or_submission_ids(arguments):
    with pytest.raises(MissingActionArgumentError):
        make_action().run(arguments)  # raises before writing


def test_duplicate_ids_build_once(requests_mock):
    mock_full_sample(requests_mock, 42)

    result = build({"sample_ids": [42, 42]})

    assert len(result["samples"]) == 1


def test_default_depth_builds_the_whole_hierarchy(requests_mock):
    """The analyzer's default: 10 levels."""
    mock_full_sample(requests_mock, 42, children=[43])
    mock_full_sample(requests_mock, 43, children=[44])
    mock_full_sample(requests_mock, 44)

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["sample_child_samples"][0]["sample_child_samples"][0]["sample_id"] == 44


def test_depth_one_builds_direct_children_only(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])
    mock_full_sample(requests_mock, 43, children=[44])
    # no mocks for 44 — building a grandchild would raise NoMockAddress

    sample = build({"sample_ids": [42], "max_recursion_depth": 1})["samples"][0]

    child = sample["sample_child_samples"][0]
    assert child["sample_id"] == 43
    assert child["sample_iocs"]["iocs"]["urls"]  # child got a full report
    assert child["sample_child_samples"] == []  # but its own children were not built


def test_depth_zero_builds_no_children(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])

    sample = build({"sample_ids": [42], "max_recursion_depth": 0})["samples"][0]

    assert sample["sample_child_samples"] == []


def test_failing_section_is_recorded_and_the_rest_is_filled(requests_mock):
    mock_full_sample(requests_mock, 42)
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", status_code=500, json={"error_msg": "boom"})

    sample = build({"sample_ids": [42]})["samples"][0]

    assert "sample_iocs" in sample["errors"]
    assert sample["sample_iocs"] == {}
    assert sample["sample_mitre_attack"]["mitre_attack_techniques"]


def test_unfetchable_sample_is_recorded_and_others_still_built(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/sample/41", status_code=404, json={"error_msg": "unknown sample"})
    mock_full_sample(requests_mock, 42)

    result = build({"sample_ids": [41, 42]})

    assert "41" in result["errors"]
    assert [s["sample_id"] for s in result["samples"]] == [42]


def test_filters_are_forwarded(requests_mock):
    mock_full_sample(requests_mock, 42)
    iocs = requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json=ok({"iocs": {}}))

    arguments = {"sample_ids": [42], "ioc_severity_filter": ["Malicious"], "analysis_verdict_filter": ["Malicious"]}
    sample = build(arguments)["samples"][0]

    assert iocs.last_request.qs == {"ioc_severity": ["malicious"]}
    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [1]


@pytest.mark.parametrize(
    "values,expected",
    [
        ([], None),
        (["malicious"], "malicious"),
        ([" Suspicious "], "suspicious"),
        (["malicious", "suspicious"], None),
        (["clean"], None),
        (["malicious", "bogus"], "malicious"),
    ],
)
def test_ioc_severity_follows_the_analyzer(values, expected):
    """Exactly one valid severity filters; none or both fetch everything; other values are ignored."""
    assert ioc_severity(values) == expected


def test_unknown_analysis_verdicts_are_ignored(requests_mock):
    mock_full_sample(requests_mock, 42)

    sample = build({"sample_ids": [42], "analysis_verdict_filter": ["bogus"]})["samples"][0]

    assert [a["analysis_id"] for a in sample["sample_analyses"]] == [1, 2]  # as if empty: nothing filtered out


def test_unfetchable_child_is_recorded_on_the_parent(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])
    requests_mock.get(f"{BASE_URL}/rest/sample/43", status_code=404, json={"error_msg": "gone"})

    sample = build({"sample_ids": [42]})["samples"][0]

    assert "child_sample:43" in sample["errors"]
    assert sample["sample_child_samples"] == []
    assert sample["sample_iocs"]["iocs"]["urls"]  # parent report still complete


# -- screenshots (the analyzer's _fetch_screenshots) ------------------------------------


def png(width, height, color=(200, 30, 30)):
    buf = io.BytesIO()
    Image.new("RGB", (width, height), color).save(buf, format="PNG")
    return buf.getvalue()


def mock_screenshot_sample(requests_mock, sample_id, analyses, shots_by_analysis, children=()):
    """A sample whose latest submission has `analyses`; each analysis archive lists `shots_by_analysis[id]`."""
    r = requests_mock
    r.get(
        f"{BASE_URL}/rest/sample/{sample_id}",
        json=ok({"sample_id": sample_id, "sample_child_sample_ids": list(children)}),
    )
    r.get(f"{BASE_URL}/rest/submission/sample/{sample_id}", json=ok([{"submission_id": sample_id * 10}]))
    r.get(f"{BASE_URL}/rest/analysis/submission/{sample_id * 10}", json=ok(analyses))
    for path in ("vtis", "mitre_attack", "iocs"):
        r.get(f"{BASE_URL}/rest/sample/{sample_id}/{path}", json=ok({}))
    r.get(f"{BASE_URL}/rest/sample/{sample_id}/classifications", json=ok({}))
    r.get(f"{BASE_URL}/rest/sample/{sample_id}/threat_names", json=ok({}))
    for analysis_id, shots in shots_by_analysis.items():
        summary = {"screenshots": [{"screenshot_archive_path": f"screenshots/{name}"} for name in shots]}
        r.get(
            f"{BASE_URL}/rest/analysis/{analysis_id}/archive/logs/summary.json",
            content=jsonlib.dumps(summary).encode(),
        )
        for name, content in shots.items():
            r.get(f"{BASE_URL}/rest/analysis/{analysis_id}/archive/screenshots/{name}", content=content)


def archive_calls(requests_mock):
    return [r.path for r in requests_mock.request_history if "/archive/" in r.path]


def test_screenshots_are_embedded_as_compressed_jpeg_newest_analysis_first(requests_mock):
    analyses = [
        {"analysis_id": 1, "analysis_created": "2026-09-24T04:00:00"},
        {"analysis_id": 2, "analysis_created": "2026-09-24T05:00:00"},
    ]
    mock_screenshot_sample(requests_mock, 42, analyses, {1: {"a.png": png(100, 60)}, 2: {"b.png": png(1600, 900)}})

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["has_screenshots"] is True
    newest, older = sample["sample_analyses"]
    assert newest["analysis_id"] == 2  # sorted newest first, as in the analyzer
    shot = newest["analysis_screenshots"][0]
    assert shot["name"] == "b.png"  # "screenshots/" prefix stripped
    image = Image.open(io.BytesIO(base64.b64decode(shot["data"])))
    assert image.format == "JPEG"
    assert image.width == 800  # 1600px downscaled, aspect kept
    assert image.height == 450
    assert older["analysis_screenshots"][0]["name"] == "a.png"


def test_every_screenshot_is_embedded_no_size_cap(requests_mock):
    shots = {f"s{i}.png": png(800, 600, (i * 20, 90, 200)) for i in range(5)}
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1, "analysis_created": "x"}], {1: shots})

    sample = build({"sample_ids": [42]})["samples"][0]

    kept = sample["sample_analyses"][0]["analysis_screenshots"]
    assert [s["name"] for s in kept] == [f"s{i}.png" for i in range(5)]
    assert "screenshots_truncated" not in sample


def test_include_screenshots_false_fetches_nothing(requests_mock):
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1}], {1: {"a.png": png(10, 10)}})

    sample = build({"sample_ids": [42], "include_screenshots": False})["samples"][0]

    assert archive_calls(requests_mock) == []
    assert sample["has_screenshots"] is False


def test_only_the_submitted_or_looked_up_sample_gets_screenshots(requests_mock):
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1}], {1: {"a.png": png(10, 10)}}, children=[43])
    mock_screenshot_sample(requests_mock, 43, [{"analysis_id": 2}], {2: {"c.png": png(10, 10)}})

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["has_screenshots"] is True
    assert sample["sample_child_samples"][0]["has_screenshots"] is False
    assert not any("/analysis/2/" in path for path in archive_calls(requests_mock))  # child's archive never read


def test_unreadable_screenshot_is_skipped_and_the_rest_kept(requests_mock):
    shots = {"broken.png": b"not an image", "ok.png": png(20, 20)}
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1}], {1: shots})

    sample = build({"sample_ids": [42]})["samples"][0]

    assert [s["name"] for s in sample["sample_analyses"][0]["analysis_screenshots"]] == ["ok.png"]


def test_missing_screenshot_summary_never_fails_the_report(requests_mock):
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1}], {})
    requests_mock.get(
        f"{BASE_URL}/rest/analysis/1/archive/logs/summary.json", status_code=404, json={"error_msg": "x"}
    )

    result = build({"sample_ids": [42]})

    sample = result["samples"][0]
    assert sample["has_screenshots"] is False
    assert sample["errors"] == {}


def test_only_a_summary_travels_inline_the_report_is_a_file(requests_mock, storage):
    mock_full_sample(requests_mock, 42)
    requests_mock.get(re.compile(rf"{BASE_URL}/rest/analysis/\\d+/archive/.*"), status_code=404, json={})

    result = make_action().run({"sample_ids": [42]})

    assert set(result) == {"report_path", "sample_ids", "errors"}  # no samples/screenshots inline (SYM216)
    assert result["sample_ids"] == [42]
    report = jsonlib.loads((Path(storage) / result["report_path"]).read_bytes())
    assert report["samples"][0]["sample_id"] == 42


def test_report_file_feeds_render_report_and_extract_iocs(requests_mock, storage):
    from vmray_modules.extract_iocs_action import ExtractIocs
    from vmray_modules.render_report_action import RenderReport

    mock_full_sample(requests_mock, 42)
    report_path = make_action().run({"sample_ids": [42]})["report_path"]

    assert "<b>VMRay Report</b>" in RenderReport().run({"report_path": report_path})["content"]
    indicators = ExtractIocs().run({"report_path": report_path})["indicators"]
    assert {"type": "url", "value": "http://evil.example"} in indicators


@pytest.mark.parametrize("blank_report", [{}, None])
def test_report_path_wins_over_a_blank_inline_report(requests_mock, storage, blank_report):
    """Sekoia's editor sends `{}` for the inline Report input left blank: that must not replace the report file."""
    from vmray_modules.extract_iocs_action import ExtractIocs
    from vmray_modules.render_report_action import RenderReport

    mock_full_sample(requests_mock, 42)
    report_path = make_action().run({"sample_ids": [42]})["report_path"]
    arguments = {"report_path": report_path, "report": blank_report}

    content = RenderReport().run(arguments)["content"]
    assert "No matches found" not in content
    assert "MALICIOUS" in content
    assert {"type": "url", "value": "http://evil.example"} in ExtractIocs().run(arguments)["indicators"]


def test_a_blank_inline_report_alone_is_missing():
    from vmray_modules.render_report_action import RenderReport

    with pytest.raises(MissingActionArgumentError):
        RenderReport().run({"report": {}})


# -- robustness: odd VMRay data must cost one section, screenshot or sample — never the whole report --------


@pytest.mark.parametrize(
    "summary", [b"[]", b"null", b'{"screenshots": "x"}', b'{"screenshots": ["screenshots/a.png"]}']
)
def test_malformed_screenshot_summary_is_skipped(requests_mock, summary):
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1}], {})
    requests_mock.get(f"{BASE_URL}/rest/analysis/1/archive/logs/summary.json", content=summary)

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["has_screenshots"] is False


def test_unusable_images_are_skipped_and_the_rest_kept(requests_mock):
    shots = {"thin.png": png(1000, 1), "ok.png": png(100, 60)}
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1}], {1: shots})

    sample = build({"sample_ids": [42]})["samples"][0]

    names = [s["name"] for s in sample["sample_analyses"][0]["analysis_screenshots"]]
    assert "ok.png" in names  # a 1000x1 image no longer shrinks to 0 px and crashes


def test_oversized_image_is_skipped_before_decoding(requests_mock, monkeypatch):
    from vmray_modules import build_report_action

    monkeypatch.setattr(build_report_action, "_SCREENSHOT_MAX_PIXELS", 100 * 60 - 1)
    mock_screenshot_sample(requests_mock, 42, [{"analysis_id": 1}], {1: {"big.png": png(100, 60)}})

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["has_screenshots"] is False


def test_network_failure_on_one_sample_keeps_the_others(requests_mock):
    import requests

    mock_full_sample(requests_mock, 42)
    requests_mock.get(f"{BASE_URL}/rest/sample/41", exc=requests.ConnectionError("connection reset"))

    result = build({"sample_ids": [41, 42]})

    assert [s["sample_id"] for s in result["samples"]] == [42]
    assert "ConnectionError" in result["errors"]["41"]


def test_non_json_answer_for_a_child_is_recorded_on_the_parent(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])
    requests_mock.get(f"{BASE_URL}/rest/sample/43", text="<html>proxy error</html>")

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["sample_child_samples"] == []
    assert "child_sample:43" in sample["errors"]


def test_null_threat_names_from_vmray_do_not_fail_the_report(requests_mock):
    mock_full_sample(requests_mock, 42)
    requests_mock.get(
        f"{BASE_URL}/rest/sample/42",
        json=ok({"sample_id": 42, "sample_threat_names": None, "sample_classifications": None}),
    )
    requests_mock.get(f"{BASE_URL}/rest/sample/42/threat_names", status_code=500, json={"error_msg": "boom"})

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["sample_threat_names"] == []
    assert "sample_threat_names" in sample["errors"]


def test_section_of_the_wrong_shape_lands_in_errors(requests_mock):
    mock_full_sample(requests_mock, 42)
    requests_mock.get(f"{BASE_URL}/rest/sample/42/iocs", json={"result": "ok"})  # ok, but no data

    sample = build({"sample_ids": [42]})["samples"][0]

    assert sample["sample_iocs"] == {}
    assert "sample_iocs" in sample["errors"]
    assert sample["sample_mitre_attack"]["mitre_attack_techniques"]  # the other sections are still filled


def test_a_child_pointing_back_up_the_tree_is_not_built_again(requests_mock):
    mock_full_sample(requests_mock, 42, children=[43])
    mock_full_sample(requests_mock, 43, children=[42, 43])  # VMRay data pointing back at parent and itself

    sample = build({"sample_ids": [42]})["samples"][0]

    child = sample["sample_child_samples"][0]
    assert child["sample_child_samples"] == []
    assert set(child["errors"]) == {"child_sample:42", "child_sample:43"}
    assert len([r for r in requests_mock.request_history if r.path == "/rest/sample/42"]) == 1


def test_recursion_depth_is_bounded():
    from pydantic import ValidationError

    from vmray_modules.models import BuildReportArguments

    with pytest.raises(ValidationError):
        BuildReportArguments(sample_ids=[1], max_recursion_depth=11)
    assert BuildReportArguments(sample_ids=[1], max_recursion_depth=10).max_recursion_depth == 10


def test_submission_without_a_sample_is_reported(requests_mock):
    requests_mock.get(f"{BASE_URL}/rest/submission/110", json=ok({"submission_id": 110, "submission_finished": False}))

    result = build({"submission_ids": [110]})

    assert result["samples"] == []
    assert result["errors"] == {"submission:110": "VMRay returned no sample for this submission"}


def test_one_odd_sample_does_not_cost_the_others(requests_mock):
    mock_full_sample(requests_mock, 42)
    mock_full_sample(requests_mock, 41)
    requests_mock.get(f"{BASE_URL}/rest/sample/41", json=ok({"sample_id": 41, "sample_vti_score": "high"}))

    result = build({"sample_ids": [41, 42]})

    assert [s["sample_id"] for s in result["samples"]] == [42]
    assert "41" in result["errors"]


# -- load_report: the report file Render report and Extract IOCs read ---------------------------------------


@pytest.mark.parametrize(
    "report_path,content,message",
    [
        ("../outside.json", None, "must be a Build report file"),
        ("/etc/hostname", None, "must be a Build report file"),
        ("missing.json", None, "No report file"),
        ("broken.json", b"not json", "could not be read"),
        ("list.json", b"[1, 2]", "Not a Build report result"),
    ],
)
def test_report_path_problems_give_a_clear_error(storage, report_path, content, message):
    from vmray_modules.render_report_action import RenderReport

    if content is not None:
        (Path(storage) / report_path).write_bytes(content)
    (Path(storage).parent / "outside.json").write_text('{"samples": []}')

    with pytest.raises(ValueError, match=message):
        RenderReport().run({"report_path": report_path})


def test_report_path_works_on_storage_that_cannot_resolve_paths(requests_mock, storage, monkeypatch):
    """In Sekoia the data path is an S3Path, whose resolve() raises NotImplementedError."""
    from pathlib import PosixPath

    from vmray_modules.render_report_action import RenderReport

    class S3LikePath(PosixPath):
        def resolve(self, strict=False):
            raise NotImplementedError("resolve is unsupported on S3 service")

        def is_relative_to(self, *other):
            raise NotImplementedError("unsupported on S3 service")

    mock_full_sample(requests_mock, 42)
    report_path = make_action().run({"sample_ids": [42]})["report_path"]
    monkeypatch.setattr(RenderReport, "data_path", property(lambda self: S3LikePath(storage)))

    assert "MALICIOUS" in RenderReport().run({"report_path": report_path})["content"]
    with pytest.raises(ValueError, match="must be a Build report file"):
        RenderReport().run({"report_path": "../" + report_path})

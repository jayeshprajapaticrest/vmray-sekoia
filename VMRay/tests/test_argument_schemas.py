import json
from pathlib import Path

import pytest

from vmray_modules.models import BuildReportArguments, GetSamplesByHashArguments, SubmitUrlSampleArguments
from vmray_modules.report_models import ExtractIocsArguments, RenderReportArguments


@pytest.mark.parametrize(
    "model",
    [
        GetSamplesByHashArguments,
        SubmitUrlSampleArguments,
        BuildReportArguments,
        RenderReportArguments,
        ExtractIocsArguments,
    ],
)
def test_every_input_shows_in_the_playbook_editor(model):
    """Sekoia's editor hides an input's title unless it has a plain `type` — an optional input generated as
    `anyOf: [..., {"type": "null"}]` shows up without one."""
    for name, prop in model.model_json_schema()["properties"].items():
        assert "type" in prop, name
        assert "anyOf" not in prop, name
        assert prop.get("default", "unset") is not None, name


def test_empty_optional_inputs_still_mean_not_set():
    assert BuildReportArguments().sample_ids is None
    assert SubmitUrlSampleArguments(sample_url="http://x.example").enable_reputation is None


def test_render_report_inputs_have_readable_titles_and_a_512_kb_default():
    props = RenderReportArguments.model_json_schema()["properties"]

    assert [p["title"] for p in props.values()] == ["Report Path", "Report (inline)", "Max comment size (KB)"]
    assert props["max_comment_kb"]["default"] == 512


def test_get_samples_by_hash_input_title():
    assert GetSamplesByHashArguments.model_json_schema()["properties"]["hashes"]["title"] == "File hashes"


def test_every_action_manifest_has_its_slug():
    """`generate-files-from-code` rewrites the action manifests without a `slug`: put it back after regenerating."""
    for path in sorted(Path(__file__).parents[1].glob("action_*.json")):
        manifest = json.loads(path.read_text())
        assert manifest.get("slug") == manifest["name"].lower().replace(" ", "_"), path.name

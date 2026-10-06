import json
from pathlib import Path

import pytest
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.render_report_action import RenderReport, render_report, render_screenshot_comments

CHILD = {
    "sample_id": 43,
    "sample_verdict": "malicious",
    "sample_type": "Windows Exe (x86-32)",
    "sample_filename": "payload.exe",
    "sample_iocs": {"iocs": {"ips": [{"ioc_type": "ip", "ip_address": "203.0.113.9", "verdict": "malicious"}]}},
    "sample_webif_url": "https://eu.cloud.vmray.com/samples/43",
    "sample_child_sample_ids": [44],
}

ROOT = {
    "sample_id": 42,
    "sample_verdict": "malicious",
    "sample_vti_score": 100,
    "sample_type": "URL",
    "sample_url": "http://evil.example/login",
    "sample_filename": "sample.url",
    "sample_created": "2026-09-24T04:59:46",
    "sample_md5hash": "c" * 32,
    "sample_sha256hash": "a" * 64,
    "sample_threat_names": ["ClickFix"],
    "sample_classifications": ["Downloader"],
    "sample_webif_url": "https://eu.cloud.vmray.com/samples/42",
    "sample_iocs": {
        "iocs": {
            "domains": [{"ioc_type": "domain", "domain": "evil.example", "verdict": "malicious"}],
            "processes": [{"ioc_type": "process", "process_names": ["mshta.exe", "cmd.exe"]}],
            "registry": [{"ioc_type": "registry", "reg_key_name": "HKCU\\Run|Evil", "verdict": "suspicious"}],
        }
    },
    "sample_threat_indicators": {
        "threat_indicators": [
            {"score": 1, "category": "Heuristics", "operation": "weak rule"},
            {"score": 5, "category": "YARA", "operation": "strong rule", "classifications": ["Downloader"]},
        ]
    },
    "sample_mitre_attack": {
        "mitre_attack_techniques": [
            {"id": 7, "technique_id": "T1204.002", "technique": "Malicious File", "tactics": ["Execution"]}
        ]
    },
    "sample_analyses": [
        {"analysis_analyzer_name": "static", "analysis_created": "2026-09-24T04:00:00", "analysis_verdict": "clean"},
        {
            "analysis_analyzer_name": "vmray",
            "analysis_vm_description": "Windows 10 64-bit",
            "analysis_created": "2026-09-24T05:00:00Z",
            "analysis_verdict": "malicious",
        },
    ],
    "sample_child_sample_ids": [43],
    "sample_child_samples": [CHILD],
    "errors": {"sample_threat_names": "timed out"},
}

RED, AMBER, GREEN, GREY = "#B22F45", "#EDBB7E", "#3A9A81", "#969696"


def badge(text, color):
    return f'<font color="{color}"><b>{text}</b></font>'


def heading(title):
    """A section heading: the summary of the section's own open toggle, bold body-size text."""
    return f"<details open><summary><b>{title}</b></summary>"


def title(text, size):
    return f'<font size="{size}"><b>{text}</b></font>'


@pytest.fixture
def content():
    return render_report({"samples": [ROOT]})


def test_comment_title_and_section_headings(content):
    assert content.startswith(title("VMRay Report", 5))  # one size scale: comment 5, sample 4, sections bold
    for section in (
        "Overview",
        "IOC Summary",
        "VMRay Threat Identifiers",
        "MITRE ATT&amp;CK",
        "Indicators of Compromise",
        "Analyses",
        "Child Samples (1)",
    ):
        assert heading(section) in content
    assert not any(line.startswith("#") for line in content.splitlines())  # no markdown headings mixed in


def test_overview_is_a_property_value_table_like_every_other_section(content):
    section = content[content.index(heading("Overview")) :]
    assert section.split("\n")[2:4] == ["| Property | Value |", "|---|---|"]
    assert "| **Verdict** | " + badge("MALICIOUS", RED) + " |" in content
    assert "| **VTI Score** | 100/100 |" in content
    assert "| **URL** | `http://evil.example/login` |" in content
    assert "sample.url" not in content  # a URL sample's container filename is noise
    assert "| **Created** | 2026-09-24 04:59:46 |" in content  # long.html's date format
    assert f"| **SHA256** | `{'a' * 64}` |" in content
    assert '| **Report** | <a href="https://eu.cloud.vmray.com/samples/42">View in VMRay</a> |' in content
    assert "<table" not in content


def test_detections_are_overview_rows(content):
    assert "| **Threat Names** | `ClickFix` |" in content
    assert "| **Classifications** | `Downloader` |" in content
    assert "Detections" not in content


def test_ioc_summary_counters(content):
    assert "| Domains | Processes | Registry |" in content
    assert "| **1** | **1** | **1** |" in content


def test_section_heading_is_its_own_toggle(content):
    assert "Toggle" not in content  # no separate Toggle button under the heading
    section = content[content.index(heading("VMRay Threat Identifiers")) :]
    assert section.split("\n")[2].startswith("| Score |")  # table straight under the heading


def test_threat_identifiers_coloured_scores(content):
    assert "| " + badge("5/5", RED) + " | YARA | strong rule | Downloader |" in content
    assert "| " + badge("1/5", GREY) + " | Heuristics | weak rule | — |" in content
    assert content.index("strong rule") < content.index("weak rule")


def test_mitre_id_buttons_then_collapsed_details(content):
    link = "[T1204.002](https://attack.mitre.org/techniques/T1204/002/)"  # no code span: shown literally in links
    section = content[content.index(heading("MITRE ATT&amp;CK")) :]
    assert section.split("\n")[2] == link  # button row, always visible
    assert "<details><summary>Details</summary>" in section  # collapsed, as in long.html
    assert f"| {link} | Malicious File | Execution |" in section


def test_ioc_table_with_coloured_verdicts(content):
    assert "| DOMAIN | `evil.example` | " + badge("MALICIOUS", RED) + " |" in content
    assert "| PROCESS | `mshta.exe, cmd.exe` | — |" in content
    assert "| REGISTRY | `HKCU\\Run\\|Evil` | " + badge("SUSPICIOUS", AMBER) + " |" in content


def test_analyses_newest_first_with_formatted_dates(content):
    assert "| vmray | Windows 10 64-bit | 2026-09-24 05:00:00 | " + badge("MALICIOUS", RED) + " |" in content
    assert "| static | — | 2026-09-24 04:00:00 | " + badge("CLEAN", GREEN) + " |" in content
    assert content.index("Windows 10 64-bit") < content.index("| static |")


def test_child_samples_are_tree_rows_only(content):
    assert (
        "<div>&emsp;" + badge("MALICIOUS", RED) + " · <b>payload.exe</b> · Windows Exe (x86-32) · (1 child) · "
        '<a href="https://eu.cloud.vmray.com/samples/43">View in VMRay</a></div>'
    ) in content  # a leaf here: its own child (44) was never built, so it is only counted
    assert "203.0.113.9" not in content  # no child detail sections
    assert content.count(heading("Overview")) == 1


def test_odd_technique_id_is_never_put_into_a_link():
    techniques = [{"technique_id": "T1059](http://attacker.example)", "technique": "x"}]
    content = render_report(
        {"samples": [{"sample_id": 1, "sample_mitre_attack": {"mitre_attack_techniques": techniques}}]}
    )

    assert "](http://attacker.example)" not in content.replace("`T1059](http://attacker.example)`", "")


def test_sections_are_spaced_apart(content):
    """Sekoia puts no margin between toggles, so every section is followed by a spacer line."""
    sections = content.count("<details open><summary><b>")
    assert sections == 7  # every section of the fixture: no screenshots
    assert content.count("</details>\n<br>") == sections  # MITRE's inner Details toggle gets none


def test_every_toggle_is_closed(content):
    assert content.count("<details") == content.count("</details>")


def test_partial_data_warning(content):
    assert "failed to load: sample_threat_names" in content


def test_screenshots_never_rendered(content):
    assert "Screenshot" not in content
    assert "<img" not in content


def test_missing_verdict_is_grey_na():
    assert badge("N/A", GREY) in render_report({"samples": [{"sample_id": 1}]})


# -- a crafted sample must not be able to inject markup, links or remote images --

HOSTILE = (
    '![x](http://attacker.example/p.png) <img src="http://attacker.example/q.png"> [click](http://attacker.example)'
)


def test_hostile_filename_is_escaped_in_the_overview():
    content = render_report({"samples": [{"sample_id": 1, "sample_filename": HOSTILE}]})

    assert "| **Filename** | `" + HOSTILE + "` |" in content  # a literal code span — nothing inside is live
    assert content.count("<img") == 1  # only the one inside that code span


def test_hostile_values_are_escaped_in_markdown_tables():
    sample = {
        "sample_id": 1,
        "sample_threat_indicators": {"threat_indicators": [{"score": 3, "category": "x", "operation": HOSTILE}]},
        "sample_iocs": {"iocs": {"filenames": [{"filename": HOSTILE}]}},
        "sample_child_samples": [{"sample_id": 2, "sample_filename": HOSTILE}],
    }
    content = render_report({"samples": [sample]})

    # rule text: markdown punctuation backslash-escaped, HTML entity-escaped
    assert "\\!\\[x\\]\\(http:\\/\\/attacker.example/p.png\\)" in content  # no image, no autolink
    assert "&lt;img" in content
    # IOC value: a literal code span (markdown/HTML inside is not interpreted)
    assert "`" + HOSTILE + "`" in content
    # child name, inside the tree's HTML block: entity-escaped
    assert (
        "<b>![x](http://attacker.example/p.png) &lt;img src=&quot;http://attacker.example/q.png&quot;&gt;" in content
    )
    # the only raw "<img" is inside the code span, never as live markup
    assert content.count("<img") == content.count("`" + HOSTILE + "`")


def test_multiple_samples_and_report_errors():
    content = render_report({"samples": [ROOT, {"sample_id": 50, "sample_verdict": "clean"}], "errors": {"41": "x"}})

    assert title("Sample 1 of 2", 4) in content
    assert title("Sample 2 of 2", 4) in content
    assert "could not be fetched from VMRay: 41" in content


def test_no_samples():
    assert render_report({"samples": []}) == title("VMRay Report", 5) + "\n\n**No matches found for this observable.**"


def test_long_tables_are_capped():
    vtis = [{"score": 1, "operation": f"rule {i}"} for i in range(25)]
    content = render_report({"samples": [{"sample_id": 1, "sample_threat_indicators": {"threat_indicators": vtis}}]})

    assert "_…and 5 more_" in content


def test_children_with_children_are_collapsed_toggles():
    grandchild = {"sample_id": 44, "sample_verdict": "clean", "sample_filename": "drop.dll"}
    child = {
        "sample_id": 43,
        "sample_verdict": "malicious",
        "sample_filename": "payload.exe",
        "sample_child_samples": [grandchild],
    }
    content = render_report({"samples": [{"sample_id": 42, "sample_child_samples": [child]}]})

    tree = content[content.index(heading("Child Samples (1)")) :]
    assert (
        "<details><summary>" + badge("MALICIOUS", RED) + " · <b>payload.exe</b> · (1 child)</summary><dd>"
        "<div>&emsp;" + badge("CLEAN", GREEN) + " · <b>drop.dll</b></div>"
        "</dd></details>"
    ) in tree  # collapsed (no `open`), as in long.html; the grandchild indented under it
    assert "\n" not in tree[tree.index("<details><summary>") : tree.index("</dd></details>")]  # the tree is one line


def test_tree_depth_is_capped():
    node = {"sample_id": 99, "sample_filename": "deepest"}
    for i in range(12):
        node = {"sample_id": i, "sample_filename": f"level{i}", "sample_child_samples": [node]}
    content = render_report({"samples": [{"sample_id": 1, "sample_child_samples": [node]}]})

    assert content.count("<dd>") == 9  # depth 10 renders as a plain row, nothing nested further
    assert content.count("<dd>") == content.count("</dd>")


def test_unbuilt_children_are_counted():
    content = render_report({"samples": [{"sample_id": 1, "sample_child_sample_ids": [2, 3]}]})

    assert heading("Child Samples (2)") in content
    assert "_Not expanded — see the VMRay report._" in content


def test_action_reads_inline_and_from_data_path(data_storage):
    assert "MALICIOUS" in RenderReport().run({"report": {"samples": [ROOT]}})["content"]

    (Path(data_storage) / "report.json").write_text(json.dumps({"samples": [ROOT]}))
    assert "MALICIOUS" in RenderReport().run({"report_path": "report.json"})["content"]


def test_action_requires_a_report():
    with pytest.raises(MissingActionArgumentError):
        RenderReport().run({})


def test_bare_urls_and_emails_in_text_do_not_autolink():
    vtis = [{"score": 2, "operation": "Contacts http://c2.example and www.c2.example, mails a@c2.example"}]
    content = render_report({"samples": [{"sample_id": 1, "sample_threat_indicators": {"threat_indicators": vtis}}]})

    assert "http:\\/\\/c2.example and www\\.c2.example, mails a\\@c2.example" in content


# -- screenshots: pointer in the main comment, images in separate comments (SYM216) ------

SHOT = "iVBORw0KGgo="


def with_screenshots(data=SHOT, name="a.png", count=1):
    return {
        "sample_id": 1,
        "sample_filename": "invoice.pdf",
        "has_screenshots": True,
        "sample_analyses": [
            {
                "analysis_analyzer_name": "vmray",
                "analysis_vm_description": "Windows 10 64-bit",
                "analysis_screenshots": [{"name": name, "data": data}] * count,
            },
            {"analysis_analyzer_name": "static", "analysis_screenshots": []},
        ],
    }


def test_main_comment_points_at_screenshots_without_embedding_them():
    content = render_report({"samples": [with_screenshots(count=3)]})

    section = content[content.index(heading("Screenshots")) :]
    assert "**3 screenshot(s)** — posted in the separate _VMRay Screenshots_ comment(s)." in section
    assert "<img" not in content  # images never go in the main comment


def test_screenshots_pointer_comes_after_analyses_and_before_children():
    sample = with_screenshots() | {"sample_child_samples": [{"sample_id": 2}]}
    content = render_report({"samples": [sample]})

    assert content.index(heading("Analyses")) < content.index(heading("Screenshots")) < content.index("Child Samples")


def test_no_screenshots_no_section_and_no_comments():
    report = {"samples": [{"sample_id": 1}]}

    assert "Screenshots" not in render_report(report)
    assert render_screenshot_comments(report, 256 * 1024) == []


def test_screenshot_comment_tiles_labelled_by_sample_and_analysis():
    comments = render_screenshot_comments({"samples": [with_screenshots()]}, 256 * 1024)

    assert len(comments) == 1
    assert comments[0].startswith(title("VMRay Screenshots (1/1)", 5))
    assert "`invoice.pdf` · **vmray** — Windows 10 64-bit" in comments[0]
    assert (
        f'<details><summary>📷 a.png</summary><img src="data:image/jpeg;base64,{SHOT}" '
        'alt="a.png" width="100%"></details>'
    ) in comments[0]
    assert "<table" not in comments[0]  # a table cell would shrink the image
    assert "**static**" not in comments[0]  # analyses without screenshots get no heading


def test_screenshots_split_so_every_comment_fits():
    data = "A" * 10_000  # ~10 KB tile
    comments = render_screenshot_comments({"samples": [with_screenshots(data=data, count=7)]}, 32 * 1024)

    assert len(comments) == 3  # 3 + 3 + 1 tiles
    assert all(len(c.encode()) <= 32 * 1024 for c in comments)
    assert [c.splitlines()[0] for c in comments] == [title(f"VMRay Screenshots ({i}/3)", 5) for i in (1, 2, 3)]
    assert sum(c.count("<img") for c in comments) == 7  # nothing lost
    assert all(c.count("<details>") == c.count("</details>") for c in comments)  # no entry split across parts
    assert all("`invoice.pdf` · **vmray**" in c for c in comments)  # each part keeps its context


def test_child_sample_screenshots_are_included():
    child = with_screenshots(name="c.png") | {"sample_id": 2, "sample_filename": "payload.exe"}
    report = {"samples": [{"sample_id": 1, "sample_child_samples": [child]}]}

    comments = render_screenshot_comments(report, 256 * 1024)

    assert "`payload.exe` · **vmray**" in comments[0]


def test_screenshot_alt_is_escaped_and_non_base64_data_is_dropped():
    hostile = render_screenshot_comments({"samples": [with_screenshots(name='"><img src=x>')]}, 256 * 1024)
    assert 'alt="&quot;&gt;&lt;img src=x&gt;"' in hostile[0]

    assert render_screenshot_comments({"samples": [with_screenshots(data='x" onerror="alert(1)')]}, 256 * 1024) == []


def test_action_returns_main_comment_and_screenshot_comments():
    result = RenderReport().run(
        {"report": {"samples": [with_screenshots(data="A" * 10_000, count=4)]}, "max_comment_kb": 32}
    )

    assert "<img" not in result["content"]
    assert len(result["screenshot_comments"]) == 2


def test_each_screenshot_is_embedded_once_behind_its_own_toggle():
    comments = render_screenshot_comments({"samples": [with_screenshots(count=2)]}, 256 * 1024)

    assert comments[0].count("<img") == 2  # one image per screenshot, no separate thumbnail copy
    assert comments[0].count("<details><summary>📷 a.png</summary>") == 2
    assert "</details><details>" in comments[0]  # an analysis's entries on one line, no gaps between them
    assert "<details open" not in comments[0]  # collapsed until clicked

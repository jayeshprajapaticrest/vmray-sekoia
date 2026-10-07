"""RenderReport — pure transform: a BuildReport result -> one alert comment.

Mirrors the Cortex-Analyzers TheHive template (VMRay_4_1/long.html): same
sections, order, columns and colours. Sekoia renders comments as GitHub-flavoured
markdown with Angular's HTML sanitizer, so the template's visual elements map to:
coloured labels and score badges -> `<font color>`; section headings and their
Toggle buttons -> one `<details open>` per section whose summary is the bold
heading, MITRE's Details button -> a collapsed `<details>`; the overview
definition list -> a Property | Value table, styled like every other section,
and detections -> a table of their own; short columns kept from wrapping by
non-breaking spaces and a minimum width (an invisible spacer image); titles ->
`<font size>` 5 (comment) and 4 (sample), so headings step down on one scale;
screenshots -> long.html's list mode, one toggle per screenshot holding its
single inline `data:` image, shown on click at the comment's full width (no
thumbnail copy; a table cell would shrink it).

Screenshots are returned separately (`screenshot_comments`), split into comments
of at most `max_comment_kb` each: Sekoia rejects playbook action arguments above
an undocumented size (SYM216), and the Comment Alert action only takes inline
text, so one comment holding every screenshot fails.
`style` attributes and `<style>` blocks are stripped by Sekoia, so no CSS.

Every value that can come from the analysed sample (filenames, URLs, IOC values,
rule text) is escaped — as a code span, or HTML-escaped inside HTML — so a
crafted value cannot inject markup, links or remote images into the comment.

Field names follow the VMRay OpenAPI spec (v2026.2.1) and the template. No VMRay
or Sekoia call.
"""

import html
import re
from datetime import datetime
from typing import Any

import orjson
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.report_models import RenderReportArguments, RenderReportResults

_MAX_ROWS = 20  # per table (and per IOC type) — keeps a comment readable; the report link has the rest

# long.html's colours
_VERDICT_COLORS = {
    "malicious": "#B22F45",
    "blacklisted": "#B22F45",
    "suspicious": "#EDBB7E",
    "clean": "#3A9A81",
    "whitelisted": "#3A9A81",
}
_GREY = "#969696"
_SCORE_COLORS = {5: "#B22F45", 4: "#E25959", 3: "#EDBB7E", 2: "#F9DA51"}

# (key under sample_iocs.iocs, value key, label) — the template's IOC order and fields
_IOC_TYPES = (
    ("domains", "domain", "Domains"),
    ("ips", "ip_address", "IPs"),
    ("urls", "url", "URLs"),
    ("files", "filename", "Files"),
    ("filenames", "filename", "Filenames"),
    ("processes", "process_names", "Processes"),
    ("mutexes", "mutex_name", "Mutexes"),
    ("registry", "reg_key_name", "Registry"),
    ("emails", "sender", "Emails"),
    ("email_addresses", "email_address", "Email Addresses"),
)

_MARKDOWN_SPECIALS = "\\`*_[]()!#~|"

_SCREENSHOT_WIDTH = "100%"  # an opened screenshot fills the comment's width (images are stored up to 800px wide)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+=*")


# -- escaping ---------------------------------------------------------------


def _text(value: Any) -> str:
    """Plain text for a markdown table cell: markdown and HTML neutralised, and
    GFM's bare-URL/email autolinking broken (the escapes still render as the
    original characters)."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    for char in _MARKDOWN_SPECIALS:
        text = text.replace(char, "\\" + char)
    text = text.replace("://", ":\\/\\/").replace("www.", "www\\.").replace("@", "\\@")
    return html.escape(text, quote=False)


def _code(value: Any) -> str:
    """A markdown code span, table-safe. Code spans are rendered literally, so no
    markdown, HTML, link or image inside the value can take effect."""
    return "`" + str(value).replace("`", "'").replace("|", "\\|").replace("\r", " ").replace("\n", " ") + "`"


def _h(value: Any) -> str:
    """Text for use inside an HTML block (markdown is not parsed there)."""
    return html.escape(str(value), quote=True)


# -- badges -------------------------------------------------------------------


def _font(text: str, color: str) -> str:
    return f'<font color="{color}"><b>{_h(text)}</b></font>'


def _verdict(verdict: str | None) -> str:
    if not verdict:
        return _font("N/A", _GREY)
    return _font(verdict.upper(), _VERDICT_COLORS.get(verdict.lower(), _GREY))


def _score(score: int | None) -> str:
    if score is None:
        return "—"
    return _font(f"{score}/5", _SCORE_COLORS.get(score, _GREY))


def _date(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


# -- layout helpers -------------------------------------------------------------


# 1x1 transparent GIF. Sekoia's tables break even single words to fit a long value in the next column, so
# a short column (labels, verdicts, dates) gets a minimum width from an invisible image of that width in its
# header — the only width control left once Sekoia strips `style`.
_SPACER = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"


def _nowrap(text: str) -> str:
    """Already-escaped text whose spaces must not wrap (multi-word labels, dates)."""
    return text.replace(" ", "&nbsp;")


def _header(headers: list[str], min_widths: dict[str, int] | None = None) -> list[str]:
    cells = [
        f'{h}<img src="{_SPACER}" width="{min_widths[h]}" height="1" alt="">' if min_widths and h in min_widths else h
        for h in headers
    ]
    return ["| " + " | ".join(cells) + " |", "|" + "---|" * len(headers)]


def _table(headers: list[str], rows: list[list[str]], min_widths: dict[str, int] | None = None) -> list[str]:
    """A markdown table; `min_widths` maps a header to the pixel width its column must never shrink below."""
    lines = _header(headers, min_widths)
    lines += ["| " + " | ".join(row) + " |" for row in rows[:_MAX_ROWS]]
    if len(rows) > _MAX_ROWS:
        lines.append("| " + " | ".join([f"_…and {len(rows) - _MAX_ROWS} more_"] + [""] * (len(headers) - 1)) + " |")
    return lines


def _toggle(body: list[str], label: str, expanded: bool = True) -> list[str]:
    """A collapsible block. The blank lines let markdown (tables) render inside."""
    return ["", f"<details{' open' if expanded else ''}><summary>{label}</summary>", "", *body, "", "</details>"]


def _heading(text: str, size: int) -> str:
    """A title line. <font size> rather than a markdown heading, so the comment title, the per-sample
    header and the section headings all step down on one scale: 5, 4, then bold body text."""
    return f'<font size="{size}"><b>{_h(text)}</b></font>'


def _section(title: str, body: list[str]) -> list[str]:
    """A long.html section whose heading is its own toggle (open by default) — no separate Toggle button.
    Bold text, not an <h4>: a heading tag inside <summary> pushes the disclosure triangle onto its own
    line, and Sekoia strips the CSS that would fix it."""
    return [*_toggle(body, label=f"<b>{_h(title)}</b>"), "<br>"]  # Sekoia adds no margin between toggles


def _sample_name(sample: dict[str, Any]) -> str:
    if sample.get("sample_type") == "URL":
        name = sample.get("sample_url") or sample.get("sample_display_url")
    else:
        name = sample.get("sample_filename")
    return name or sample.get("sample_sha256hash") or "Sample"


_TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")


def _mitre_link(technique_id: str) -> str:
    """A technique ID linked to attack.mitre.org. Plain link text: Sekoia shows a code span inside a link
    as literal backticks. An ID not shaped like Txxxx[.yyy] is only shown, never put into a URL."""
    if not _TECHNIQUE_ID.fullmatch(technique_id):
        return _code(technique_id)
    return f"[{technique_id}](https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/)"


# -- sections (long.html 1-7) -------------------------------------------------------


def _overview(sample: dict[str, Any]) -> list[str]:
    """long.html's overview, as a Property | Value table styled like every other section."""
    rows = [["Verdict", _verdict(sample.get("sample_verdict"))]]
    if sample.get("sample_vti_score") is not None:
        rows.append(["VTI Score", f"{_text(sample['sample_vti_score'])}/100"])
    if sample.get("sample_verdict_reason_description"):
        rows.append(["Reason", _text(sample["sample_verdict_reason_description"])])
    url = sample.get("sample_url") or sample.get("sample_display_url")
    if sample.get("sample_type") == "URL" and url:
        rows.append(["URL", _code(url)])
    elif sample.get("sample_filename"):
        rows.append(["Filename", _code(sample["sample_filename"])])
    if sample.get("sample_type"):
        rows.append(["Type", _text(sample["sample_type"])])
    if sample.get("sample_created"):
        rows.append(["Created", _nowrap(_text(_date(sample["sample_created"])))])
    for key, label in (("sample_md5hash", "MD5"), ("sample_sha1hash", "SHA1"), ("sample_sha256hash", "SHA256")):
        if sample.get(key):
            rows.append([label, _code(sample[key])])
    if sample.get("sample_webif_url"):
        rows.append(["Report", f'<a href="{_h(sample["sample_webif_url"])}">View in VMRay</a>'])
    table = _table(
        ["Property", "Value"], [[f"**{_nowrap(label)}**", value] for label, value in rows], {"Property": 110}
    )
    return _section("Overview", table)


def _detections(sample: dict[str, Any]) -> list[str]:
    rows = [
        [f"**{_nowrap(label)}**", " ".join(_code(v) for v in sample[key])]
        for key, label in (("sample_threat_names", "Threat Names"), ("sample_classifications", "Classifications"))
        if sample.get(key)
    ]
    return _section("Detections", _table(["Detection", "Values"], rows, {"Detection": 115})) if rows else []


def _ioc_summary(iocs: dict[str, Any]) -> list[str]:
    present = [(label, len(iocs.get(key) or [])) for key, _value_key, label in _IOC_TYPES if iocs.get(key)]
    if not present:
        return []
    return _section(
        "IOC Summary", _table([_nowrap(label) for label, _ in present], [[f"**{n}**" for _, n in present]])
    )


def _threat_indicators(vtis: list[dict[str, Any]]) -> list[str]:
    if not vtis:
        return []
    rows = [
        [
            _score(vti.get("score")),
            _nowrap(_text(vti.get("category") or "—")),
            _text(vti.get("operation") or "—"),
            _text(", ".join(vti.get("classifications") or []) or "—"),
        ]
        for vti in sorted(vtis, key=lambda v: v.get("score") or 0, reverse=True)
    ]
    table = _table(["Score", "Category", "Operation", "Classification"], rows, {"Score": 45, "Category": 110})
    return _section("VMRay Threat Identifiers", table)


def _mitre(techniques: list[dict[str, Any]]) -> list[str]:
    if not techniques:
        return []
    ids = [t["technique_id"] for t in techniques if t.get("technique_id")]
    buttons = " · ".join(_mitre_link(i) for i in ids)
    rows = [
        [
            _mitre_link(t["technique_id"]) if t.get("technique_id") else "—",
            _text(t.get("technique") or "—"),
            _text(", ".join(t.get("tactics") or []) or "—"),
        ]
        for t in techniques
    ]
    details = _toggle(_table(["ID", "Technique", "Tactics"], rows, {"ID": 85}), label="Details", expanded=False)
    return _section("MITRE ATT&CK", [buttons, *details])


def _iocs(iocs: dict[str, Any]) -> list[str]:
    rows: list[list[str]] = []
    omitted = 0
    for key, value_key, _label in _IOC_TYPES:
        items = iocs.get(key) or []
        for item in items[:_MAX_ROWS]:
            value = item.get(value_key)
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            rows.append(
                [
                    _text((item.get("ioc_type") or key).upper()),
                    _code(value) if value else "—",
                    _verdict(item.get("verdict")) if item.get("verdict") else "—",
                ]
            )
        omitted += max(0, len(items) - _MAX_ROWS)
    if not rows:
        return []
    table = [
        *_header(["Type", "Value", "Verdict"], {"Type": 120, "Verdict": 95}),
        *("| " + " | ".join(row) + " |" for row in rows),
    ]
    if omitted:
        table.append(f"| _…and {omitted} more_ | | |")
    return _section("Indicators of Compromise", table)


def _analyses(analyses: list[dict[str, Any]]) -> list[str]:
    if not analyses:
        return []
    rows = [
        [
            _text(a.get("analysis_analyzer_name") or "—"),
            _text(a.get("analysis_vm_description") or "—"),
            _nowrap(_text(_date(a["analysis_created"]))) if a.get("analysis_created") else "—",
            _verdict(a.get("analysis_verdict")),
        ]
        for a in sorted(analyses, key=lambda a: a.get("analysis_created") or "", reverse=True)
    ]
    table = _table(
        ["Analysis", "Target Environment", "Created", "Verdict"], rows, {"Analysis": 85, "Created": 145, "Verdict": 95}
    )
    return _section("Analyses", table)


def _screenshot_rows(analysis: dict[str, Any]) -> list[str]:
    """One list entry per screenshot: a toggle named after the screenshot that reveals the image at the
    comment's full width (a table cell would squeeze it)."""
    rows = []
    for shot in analysis.get("analysis_screenshots") or []:
        if not (isinstance(shot.get("data"), str) and _BASE64.fullmatch(shot["data"])):
            continue
        name = _h(shot.get("name") or "screenshot")
        image = f'<img src="data:image/jpeg;base64,{shot["data"]}" alt="{name}" width="{_SCREENSHOT_WIDTH}">'
        rows.append(f"<details><summary>📷 {name}</summary>{image}</details>")
    return rows


def _screenshots(sample: dict[str, Any]) -> list[str]:
    """The main comment only points at the screenshots: the images themselves go in separate comments
    (render_screenshot_comments), since all of them together exceed Sekoia's playbook argument limit."""
    count = sum(len(_screenshot_rows(a)) for a in sample.get("sample_analyses") or [])
    if not count:
        return []
    return _section(
        "Screenshots", [f"**{count} screenshot(s)** - posted in the separate _VMRay Screenshots_ comment(s)."]
    )


def _screenshot_groups(report: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """(heading, tiles) per analysis with screenshots, for every sample and child sample, in report order."""
    groups: list[tuple[str, list[str]]] = []

    def walk(sample: dict[str, Any]) -> None:
        for analysis in sample.get("sample_analyses") or []:
            tiles = _screenshot_rows(analysis)
            if not tiles:
                continue
            heading = (
                f"{_code(_sample_name(sample))} · **{_text(analysis.get('analysis_analyzer_name') or 'Analysis')}**"
            )
            if analysis.get("analysis_vm_description"):
                heading += f" — {_text(analysis['analysis_vm_description'])}"
            groups.append((heading, tiles))
        for child in sample.get("sample_child_samples") or []:
            walk(child)

    for sample in report.get("samples") or []:
        walk(sample)
    return groups


_COMMENT_HEADER_RESERVE = 96  # room for the "VMRay Screenshots (i/N)" title line


def render_screenshot_comments(report: dict[str, Any], max_bytes: int) -> list[str]:
    """Pack every screenshot row, in order, into as few comments as fit under max_bytes each. A row is
    never split; one bigger than the limit still gets a comment of its own."""
    budget = max(max_bytes - _COMMENT_HEADER_RESERVE, 1)
    chunks: list[list[tuple[str, list[str]]]] = []
    current: list[tuple[str, list[str]]] = []
    size = 0
    for heading, tiles in _screenshot_groups(report):
        for tile in tiles:
            group_cost = len(heading) + 2  # heading and the blank line around it
            opens_group = not current or current[-1][0] != heading
            cost = len(tile) + (group_cost if opens_group else 0)
            if current and size + cost > budget:
                chunks.append(current)
                current, size = [], 0
                opens_group, cost = True, len(tile) + group_cost
            if opens_group:
                current.append((heading, []))
            current[-1][1].append(tile)
            size += cost
    if current:
        chunks.append(current)

    return [
        "\n".join(
            [_heading(f"VMRay Screenshots ({index}/{len(chunks)})", 5)]
            # an analysis's entries on one line, like the child-sample tree: no blank lines to space them out
            + [line for heading, rows in chunk for line in ("", heading, "", "".join(rows))]
        )
        for index, chunk in enumerate(chunks, start=1)
    ]


_TREE_MAX_DEPTH = 10  # long.html's cap, so a deep chain still renders


def _tree_row(child: dict[str, Any], count: int) -> str:
    """One long.html tree row: verdict, name, type, child count and report link. No detail sections."""
    parts = [_verdict(child.get("sample_verdict")), f"<b>{_h(_sample_name(child))}</b>"]
    if child.get("sample_type"):
        parts.append(_h(child["sample_type"]))
    if count:
        parts.append(f"({count} {'child' if count == 1 else 'children'})")
    if child.get("sample_webif_url"):
        parts.append(f'<a href="{_h(child["sample_webif_url"])}">View in VMRay</a>')
    return " · ".join(parts)


def _child_tree(children: list[dict[str, Any]], depth: int = 1) -> list[str]:
    """long.html's child-sample hierarchy: a sample with children is a collapsed toggle whose summary is
    its row, its children indented below in a <dd> (a <blockquote> adds a line of space above and below);
    a leaf is a plain row, padded to line up."""
    lines = []
    for child in children:
        grandchildren = child.get("sample_child_samples") or []
        count = len(grandchildren) or len(child.get("sample_child_sample_ids") or [])
        if grandchildren and depth < _TREE_MAX_DEPTH:
            lines.append(f"<details><summary>{_tree_row(child, count)}</summary><dd>")
            lines += _child_tree(grandchildren, depth + 1)
            lines.append("</dd></details>")
        else:
            lines.append(f"<div>&emsp;{_tree_row(child, count)}</div>")
    return lines


def _child_samples(sample: dict[str, Any]) -> list[str]:
    children = sample.get("sample_child_samples") or []
    if children:
        # one line: a single HTML block markdown cannot split, with no newlines to become line breaks
        return _section(f"Child Samples ({len(children)})", ["".join(_child_tree(children))])
    if sample.get("sample_child_sample_ids"):
        count = len(sample["sample_child_sample_ids"])
        return _section(f"Child Samples ({count})", ["_Not expanded — see the VMRay report._"])
    return []


def _render_sample(sample: dict[str, Any]) -> list[str]:
    iocs = (sample.get("sample_iocs") or {}).get("iocs") or {}
    lines = [
        *_overview(sample),
        *_detections(sample),
        *_ioc_summary(iocs),
        *_threat_indicators((sample.get("sample_threat_indicators") or {}).get("threat_indicators") or []),
        *_mitre((sample.get("sample_mitre_attack") or {}).get("mitre_attack_techniques") or []),
        *_iocs(iocs),
        *_analyses(sample.get("sample_analyses") or []),
        *_screenshots(sample),
        *_child_samples(sample),
    ]
    if sample.get("errors"):
        failed = ", ".join(_h(e) for e in sorted(sample["errors"]))
        lines += ["", f"⚠️ _Partial data — these sections failed to load: {failed}._"]
    return lines


def render_report(report: dict[str, Any]) -> str:
    samples = report.get("samples") or []
    lines = [_heading("VMRay Report", 5)]
    if not samples:
        lines += ["", "**No matches found for this observable.**"]
    for index, sample in enumerate(samples, start=1):
        if len(samples) > 1:
            lines += ["", "---", "", _heading(f"Sample {index} of {len(samples)}", 4)]
        lines += _render_sample(sample)
    if report.get("errors"):
        failed = ", ".join(_h(e) for e in sorted(report["errors"]))
        lines += ["", f"⚠️ _These samples could not be fetched from VMRay: {failed}._"]
    return "\n".join(lines)


class RenderReport(VMRayAction):
    name = "Render report"
    description = (
        "Render a Build report result into one alert comment laid out like the VMRay TheHive report: "
        "overview, detections, IOC summary, threat identifiers, MITRE ATT&CK, IOCs, analyses, screenshots and "
        "child samples."
    )
    results_model = RenderReportResults

    def run(self, arguments: RenderReportArguments) -> RenderReportResults:
        if arguments.report is not None:
            report = arguments.report
        elif arguments.report_path:
            report = orjson.loads(self.data_path.joinpath(arguments.report_path).read_bytes())
        else:
            raise MissingActionArgumentError("report")
        return RenderReportResults(
            content=render_report(report),
            screenshot_comments=render_screenshot_comments(report, arguments.max_comment_kb * 1024),
        )

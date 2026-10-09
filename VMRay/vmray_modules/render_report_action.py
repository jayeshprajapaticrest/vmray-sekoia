"""RenderReport — pure transform: a BuildReport result -> one alert comment.

Mirrors the Cortex-Analyzers TheHive template (VMRay_4_1/long.html): same
sections, order, columns and colours. Sekoia renders comments as GitHub-flavoured
markdown with Angular's HTML sanitizer, so the template's visual elements map to:
coloured labels and score badges -> `<font color>`; section headings and their
Toggle buttons -> one `<details open>` per section whose summary is the bold
heading, each written on one line of HTML so markdown adds no space around it;
MITRE's Details button -> a collapsed `<details>`; the overview
definition list -> a Property | Value table, and detections -> a table of their
own; every table is HTML, so short columns can be kept from wrapping (`nowrap`)
and cells aligned (`valign`/`align`) — attributes Sekoia keeps; titles ->
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

import base64
import html
import json
import re
from datetime import datetime
from typing import Any

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


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _one_line(value: Any) -> str:
    """The value as one line of text. A line break in a value would end the one-line HTML block it sits in and
    let markdown run on what follows — a crafted file name could then inject a link or a remote image."""
    return _CONTROL.sub(" ", "" if value is None else str(value))


def _text(value: Any) -> str:
    """Plain text for a markdown paragraph: markdown and HTML neutralised, and GFM's bare-URL/email autolinking
    broken (the escapes still render as the original characters)."""
    text = _one_line(value)
    for char in _MARKDOWN_SPECIALS:
        text = text.replace(char, "\\" + char)
    text = re.sub(r"(?i)(www)\.", r"\1\\.", text.replace("://", ":\\/\\/").replace("@", "\\@"))
    return html.escape(text, quote=False)


def _code(value: Any) -> str:
    """A markdown code span. Code spans are rendered literally, so no markdown, HTML, link or image inside the
    value can take effect."""
    return "`" + _one_line(value).replace("`", "'") + "`"


def _h(value: Any) -> str:
    """Text for use inside an HTML block (markdown is not parsed there)."""
    return html.escape(_one_line(value), quote=True)


# -- tolerant readers: report fields are VMRay data, and an odd shape must not crash the comment ------------


def _str(value: Any) -> str:
    return "" if value is None else str(value)


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strs(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    return [str(item) for item in value if item is not None] if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_SAFE_LINK = re.compile(r"https?://", re.IGNORECASE)


def _link(url: Any, label: str) -> str:
    """A link to a VMRay page. Only an http(s) URL becomes a link — anything else is never put in an href."""
    url = _str(url)
    return f'<a href="{_h(url)}">{_h(label)}</a>' if _SAFE_LINK.match(url) else "—"


# -- badges -------------------------------------------------------------------


def _font(text: str, color: str) -> str:
    return f'<font color="{color}"><b>{_h(text)}</b></font>'


def _verdict(verdict: Any) -> str:
    verdict = _str(verdict)
    if not verdict:
        return _font("N/A", _GREY)
    return _font(verdict.upper(), _VERDICT_COLORS.get(verdict.lower(), _GREY))


def _score(score: Any) -> str:
    value = _int(score)
    if value is None:
        return "—"
    return _font(f"{value}/5", _SCORE_COLORS.get(value, _GREY))


def _date(value: Any) -> str:
    text = _str(value)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text


# -- layout helpers -------------------------------------------------------------


_BREAK_EVERY = 16  # characters between optional line breaks in a long token (hash, URL, registry key)


def _code_html(value: Any) -> str:
    """A value shown as code inside an HTML table. A long token gets an optional break (<wbr>) every few
    characters, so a SHA256 or URL wraps inside its own cell instead of squeezing the other columns."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    chunks = [text[k : k + _BREAK_EVERY] for k in range(0, len(text), _BREAK_EVERY)] or [""]
    return "<code>" + "<wbr>".join(_h(chunk) for chunk in chunks) + "</code>"


def _row(cells: list[str], nowrap: frozenset[int], tag: str = "td") -> str:
    attrs = ' align="left" valign="top"'
    return (
        "<tr>"
        + "".join(f"<{tag}{attrs}{' nowrap' if k in nowrap else ''}>{cell}</{tag}>" for k, cell in enumerate(cells))
        + "</tr>"
    )


def _table(
    headers: list[str],
    rows: list[list[str]],
    nowrap: frozenset[int] = frozenset(),
    limit: int | None = _MAX_ROWS,
    omitted: int = 0,
) -> list[str]:
    """An HTML table, on one line so markdown leaves it alone. HTML rather than a markdown table because only
    HTML cells take the attributes Sekoia keeps once it strips `style`: `nowrap` on the short columns
    (`nowrap` = their indexes — labels, types, verdicts, dates) so they never wrap whatever the zoom, and
    `valign="top"` / `align="left"` on every cell so headings and values line up the same in every table.
    Cell contents are HTML: escape them with _h or _code_html."""
    shown = rows if limit is None else rows[:limit]
    omitted += len(rows) - len(shown)
    html = ['<table width="100%">', _row([_h(h) for h in headers], nowrap, "th")]
    html += [_row(row, nowrap) for row in shown]
    if omitted:
        html.append(f'<tr><td colspan="{len(headers)}"><i>…and {omitted} more</i></td></tr>')
    html.append("</table>")
    return ["".join(html)]


def _toggle(body: list[str], label: str, expanded: bool = True) -> str:
    """A collapsible block, on one line of HTML: no blank lines, so markdown adds no paragraphs — and so no
    extra vertical space — around its content. The content must be HTML."""
    return f"<details{' open' if expanded else ''}><summary>{label}</summary>{''.join(body)}</details>"


def _heading(text: str, size: int) -> str:
    """A title line. <font size> rather than a markdown heading, so the comment title, the per-sample
    header and the section headings all step down on one scale: 5, 4, then bold body text."""
    return f'<font size="{size}"><b>{_h(text)}</b></font>'


def _section(title: str, body: list[str]) -> list[str]:
    """A long.html section whose heading is its own toggle (open by default) — no separate Toggle button.
    Bold text, not an <h4>: a heading tag inside <summary> pushes the disclosure triangle onto its own
    line, and Sekoia strips the CSS that would fix it."""
    return [_toggle(body, label=f"<b>{_h(title)}</b>")]


def _sample_name(sample: dict[str, Any]) -> str:
    if sample.get("sample_type") == "URL":
        name = sample.get("sample_url") or sample.get("sample_display_url")
    else:
        name = sample.get("sample_filename")
    return _str(name or sample.get("sample_sha256hash") or "Sample")


_TECHNIQUE_ID = re.compile(r"T\d{4}(\.\d{3})?")


def _mitre_link(technique_id: Any) -> str:
    """A technique ID linked to attack.mitre.org. An ID not shaped like Txxxx[.yyy] is only shown, never
    put into a URL."""
    technique_id = _str(technique_id)
    if not _TECHNIQUE_ID.fullmatch(technique_id):
        return _code_html(technique_id)
    return f'<a href="https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/">{technique_id}</a>'


# -- sections (long.html 1-7) -------------------------------------------------------


def _overview(sample: dict[str, Any]) -> list[str]:
    """long.html's overview, as a Property | Value table styled like every other section."""
    rows = [["Verdict", _verdict(sample.get("sample_verdict"))]]
    if sample.get("sample_verdict_reason_description"):
        rows.append(["Reason", _h(sample["sample_verdict_reason_description"])])
    url = sample.get("sample_url") or sample.get("sample_display_url")
    if sample.get("sample_type") == "URL" and url:
        rows.append(["URL", _code_html(url)])
    elif sample.get("sample_filename"):
        rows.append(["Filename", _code_html(sample["sample_filename"])])
    if sample.get("sample_type"):
        rows.append(["Type", _h(sample["sample_type"])])
    if sample.get("sample_created"):
        rows.append(["Created", _h(_date(sample["sample_created"]))])
    for key, label in (("sample_md5hash", "MD5"), ("sample_sha1hash", "SHA1"), ("sample_sha256hash", "SHA256")):
        if sample.get(key):
            rows.append([label, _code_html(sample[key])])
    if sample.get("sample_webif_url"):
        rows.append(["Report", _link(sample["sample_webif_url"], "View in VMRay")])
    table = _table(["Property", "Value"], [[f"<b>{label}</b>", value] for label, value in rows], frozenset({0}))
    return _section("Overview", table)


def _detections(sample: dict[str, Any]) -> list[str]:
    rows = [
        [f"<b>{label}</b>", " ".join(_code_html(v) for v in _strs(sample.get(key)))]
        for key, label in (("sample_threat_names", "Threat Names"), ("sample_classifications", "Classifications"))
        if _strs(sample.get(key))
    ]
    return _section("Detections", _table(["Detection", "Values"], rows, frozenset({0}))) if rows else []


def _ioc_summary(iocs: dict[str, Any]) -> list[str]:
    present = [(label, len(_dicts(iocs.get(key)))) for key, _value_key, label in _IOC_TYPES if _dicts(iocs.get(key))]
    if not present:
        return []
    every_column = frozenset(range(len(present)))
    return _section(
        "IOC Summary", _table([label for label, _ in present], [[f"<b>{n}</b>" for _, n in present]], every_column)
    )


def _threat_indicators(vtis: Any) -> list[str]:
    vtis = _dicts(vtis)
    if not vtis:
        return []
    rows = [
        [
            _score(vti.get("score")),
            _h(vti.get("category") or "—"),
            _h(vti.get("operation") or "—"),
            _h(", ".join(_strs(vti.get("classifications"))) or "—"),
        ]
        for vti in sorted(vtis, key=lambda v: _int(v.get("score")) or 0, reverse=True)
    ]
    table = _table(["Score", "Category", "Operation", "Classification"], rows, frozenset({0, 1}))
    return _section("VMRay Threat Identifiers", table)


def _mitre(techniques: Any) -> list[str]:
    techniques = _dicts(techniques)
    if not techniques:
        return []
    ids = [t["technique_id"] for t in techniques if t.get("technique_id")]
    buttons = " · ".join(_mitre_link(i) for i in ids)
    rows = [
        [
            _mitre_link(t["technique_id"]) if t.get("technique_id") else "—",
            _h(t.get("technique") or "—"),
            _h(", ".join(_strs(t.get("tactics"))) or "—"),
        ]
        for t in techniques
    ]
    details = _toggle(_table(["ID", "Technique", "Tactics"], rows, frozenset({0})), label="Details", expanded=False)
    return _section("MITRE ATT&CK", [f"<div>{buttons}</div>", details])


def _iocs(iocs: dict[str, Any]) -> list[str]:
    rows: list[list[str]] = []
    omitted = 0
    for key, value_key, _label in _IOC_TYPES:
        items = _dicts(iocs.get(key))
        for item in items[:_MAX_ROWS]:
            value = item.get(value_key)
            if isinstance(value, list):
                value = ", ".join(_strs(value))
            rows.append(
                [
                    _h(_str(item.get("ioc_type") or key).upper()),
                    _code_html(value) if value else "—",
                    _verdict(item.get("verdict")) if item.get("verdict") else "—",
                ]
            )
        omitted += max(0, len(items) - _MAX_ROWS)
    if not rows:
        return []
    # capped per IOC type above, so every type shows up; not capped again overall
    table = _table(["Type", "Value", "Verdict"], rows, frozenset({0, 2}), limit=None, omitted=omitted)
    return _section("Indicators of Compromise", table)


def _analyses(analyses: Any) -> list[str]:
    analyses = _dicts(analyses)
    if not analyses:
        return []
    rows = [
        [
            _h(a.get("analysis_analyzer_name") or "—"),
            _h(a.get("analysis_vm_description") or "—"),
            _h(_date(a["analysis_created"])) if a.get("analysis_created") else "—",
            _verdict(a.get("analysis_verdict")),
        ]
        for a in sorted(analyses, key=lambda a: _str(a.get("analysis_created")), reverse=True)
    ]
    table = _table(["Analysis", "Target Environment", "Created", "Verdict"], rows, frozenset({0, 2, 3}))
    return _section("Analyses", table)


def _screenshot_rows(analysis: dict[str, Any]) -> list[str]:
    """One list entry per screenshot: a toggle named after the screenshot that reveals the image at the
    comment's full width (a table cell would squeeze it)."""
    rows = []
    for shot in _dicts(analysis.get("analysis_screenshots")):
        if not _is_base64(shot.get("data")):
            continue
        name = _h(shot.get("name") or "screenshot")
        image = f'<img src="data:image/jpeg;base64,{shot["data"]}" alt="{name}" width="{_SCREENSHOT_WIDTH}">'
        rows.append(f"<details><summary>📷 {name}</summary>{image}</details>")
    return rows


def _is_base64(data: Any) -> bool:
    """Only well-formed base64 goes into an image's src — anything else could break out of the attribute."""
    if not isinstance(data, str) or not data or not _BASE64.fullmatch(data) or len(data) % 4:
        return False
    try:
        base64.b64decode(data, validate=True)
    except ValueError:
        return False
    return True


def _screenshots(sample: dict[str, Any]) -> list[str]:
    """The main comment only points at the screenshots: the images themselves go in separate comments
    (render_screenshot_comments), since all of them together exceed Sekoia's playbook argument limit."""
    count = sum(len(_screenshot_rows(a)) for a in _dicts(sample.get("sample_analyses")))
    if not count:
        return []
    return _section(
        "Screenshots",
        [f"<div><b>{count} screenshot(s)</b> - posted in the separate <i>VMRay Screenshots</i> comment(s).</div>"],
    )


def _screenshot_groups(report: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """(heading, tiles) per analysis with screenshots, for every sample and child sample, in report order."""
    groups: list[tuple[str, list[str]]] = []

    def walk(sample: dict[str, Any], depth: int = 0) -> None:
        for analysis in _dicts(sample.get("sample_analyses")):
            tiles = _screenshot_rows(analysis)
            if not tiles:
                continue
            heading = (
                f"{_code(_sample_name(sample))} · **{_text(analysis.get('analysis_analyzer_name') or 'Analysis')}**"
            )
            if analysis.get("analysis_vm_description"):
                heading += f" — {_text(analysis['analysis_vm_description'])}"
            groups.append((heading, tiles))
        if depth < _TREE_MAX_DEPTH:
            for child in _dicts(sample.get("sample_child_samples")):
                walk(child, depth + 1)

    for sample in _dicts(report.get("samples")):
        walk(sample)
    return groups


_TOO_LARGE = "<div><i>📷 {name}: too large for a comment — see the VMRay report.</i></div>"


def _size(text: str) -> int:
    """What a comment costs against Sekoia's limit: its UTF-8 bytes once JSON-encoded as the action's input
    (quotes and non-ASCII characters are escaped there, so they count for more)."""
    return len(json.dumps(text).encode())


def _assemble(chunk: list[tuple[str, list[str]]], index: int, total: int) -> str:
    return "\n".join(
        [_heading(f"VMRay Screenshots ({index}/{total})", 5)]
        # an analysis's entries on one line, like the child-sample tree: no blank lines to space them out
        + [line for heading, rows in chunk for line in ("", heading, "", "".join(rows))]
    )


def render_screenshot_comments(report: dict[str, Any], max_bytes: int) -> list[str]:
    """Pack every screenshot row, in order, into as few comments as fit under max_bytes each, measured as
    Sekoia receives them. A row is never split; a single screenshot too large for any comment is replaced by
    a note pointing at the VMRay report, so no comment can exceed the limit."""
    worst_total = 999  # the title's (i/N) is sized for up to 999 comments while packing
    chunks: list[list[tuple[str, list[str]]]] = []
    current: list[tuple[str, list[str]]] = []
    for heading, tiles in _screenshot_groups(report):
        for tile in tiles:
            for attempt in (current, []):  # first try the current comment, then a fresh one
                candidate = [(h, list(rows)) for h, rows in attempt]
                if candidate and candidate[-1][0] == heading:
                    candidate[-1][1].append(tile)
                else:
                    candidate.append((heading, [tile]))
                if _size(_assemble(candidate, worst_total, worst_total)) <= max_bytes:
                    if attempt is not current and current:
                        chunks.append(current)
                    current = candidate
                    break
            else:  # does not fit even alone: keep a note in its place
                name = re.search(r"<summary>📷 (.*?)</summary>", tile)
                note = _TOO_LARGE.format(name=name.group(1) if name else "screenshot")
                if current and current[-1][0] == heading:
                    current[-1][1].append(note)
                else:
                    current.append((heading, [note]))

    if current:
        chunks.append(current)
    return [_assemble(chunk, index, len(chunks)) for index, chunk in enumerate(chunks, start=1)]


_TREE_MAX_DEPTH = 10  # long.html's cap, so a deep chain still renders


def _tree_row(child: dict[str, Any], count: int) -> str:
    """One long.html tree row: verdict, name, type, child count and report link. No detail sections."""
    parts = [_verdict(child.get("sample_verdict")), f"<b>{_h(_sample_name(child))}</b>"]
    if child.get("sample_type"):
        parts.append(_h(child["sample_type"]))
    if count:
        parts.append(f"({count} {'child' if count == 1 else 'children'})")
    if _SAFE_LINK.match(_str(child.get("sample_webif_url"))):
        parts.append(_link(child["sample_webif_url"], "View in VMRay"))
    return " · ".join(parts)


def _child_tree(children: Any, depth: int = 1) -> list[str]:
    """long.html's child-sample hierarchy: a sample with children is a collapsed toggle whose summary is
    its row, its children indented below in a <dd> (a <blockquote> adds a line of space above and below);
    a leaf is a plain row, padded to line up."""
    lines = []
    for child in _dicts(children):
        grandchildren = _dicts(child.get("sample_child_samples"))
        count = len(grandchildren) or len(child.get("sample_child_sample_ids") or [])
        if grandchildren and depth < _TREE_MAX_DEPTH:
            lines.append(f"<details><summary>{_tree_row(child, count)}</summary><dd>")
            lines += _child_tree(grandchildren, depth + 1)
            lines.append("</dd></details>")
        else:
            lines.append(f"<div>&emsp;{_tree_row(child, count)}</div>")
    return lines


def _child_samples(sample: dict[str, Any]) -> list[str]:
    children = _dicts(sample.get("sample_child_samples"))
    if children:
        # one line: a single HTML block markdown cannot split, with no newlines to become line breaks
        return _section(f"Child Samples ({len(children)})", ["".join(_child_tree(children))])
    if isinstance(sample.get("sample_child_sample_ids"), list) and sample["sample_child_sample_ids"]:
        count = len(sample["sample_child_sample_ids"])
        return _section(f"Child Samples ({count})", ["<div><i>Not expanded — see the VMRay report.</i></div>"])
    return []


def _render_sample(sample: dict[str, Any]) -> list[str]:
    iocs = _dict(_dict(sample.get("sample_iocs")).get("iocs"))
    lines = [
        *_overview(sample),
        *_detections(sample),
        *_ioc_summary(iocs),
        *_threat_indicators(_dict(sample.get("sample_threat_indicators")).get("threat_indicators")),
        *_mitre(_dict(sample.get("sample_mitre_attack")).get("mitre_attack_techniques")),
        *_iocs(iocs),
        *_analyses(sample.get("sample_analyses")),
        *_screenshots(sample),
        *_child_samples(sample),
    ]
    if _dict(sample.get("errors")):
        # a markdown paragraph, not an HTML block: escaped as markdown text
        failed = ", ".join(_text(e) for e in sorted(map(str, sample["errors"])))
        lines += ["", f"⚠️ _Partial data — these sections failed to load: {failed}._"]
    return lines


def render_report(report: dict[str, Any]) -> str:
    samples = _dicts(report.get("samples"))
    lines = [_heading("VMRay Report", 5)]
    if not samples:
        lines += ["", "**No matches found for this sample.**"]
    for index, sample in enumerate(samples, start=1):
        if len(samples) > 1:
            lines += ["", "---", "", _heading(f"Sample {index} of {len(samples)}", 4)]
        # one line per section, with no blank line between them: together they form one HTML block
        lines += ["", *_render_sample(sample)]
    if _dict(report.get("errors")):
        failed = ", ".join(_text(e) for e in sorted(map(str, report["errors"])))
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
        report = self.load_report(arguments)
        return RenderReportResults(
            content=render_report(report),
            screenshot_comments=render_screenshot_comments(report, arguments.max_comment_kb * 1024),
        )

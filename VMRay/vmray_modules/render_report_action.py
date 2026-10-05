"""RenderReport — pure transform: a BuildReport result -> one alert comment.

Mirrors the Cortex-Analyzers TheHive template (VMRay_4_1/long.html): same
sections, order, columns and colours. Sekoia renders comments as GitHub-flavoured
markdown with Angular's HTML sanitizer, so the template's visual elements map to:
coloured labels and score badges -> `<font color>`; Toggle/Details buttons ->
`<details>` (`open` where the template starts expanded); the overview
definition list -> an HTML table; screenshots -> long.html's list mode, a Name |
Action table whose View toggle holds the one inline `data:` image (shown on click,
so no separate thumbnail copy is embedded).

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

_SCREENSHOT_WIDTH = 600  # width of an opened screenshot (images are stored up to 800px wide)
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


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(row) + " |" for row in rows[:_MAX_ROWS]]
    if len(rows) > _MAX_ROWS:
        lines.append("| " + " | ".join([f"_…and {len(rows) - _MAX_ROWS} more_"] + [""] * (len(headers) - 1)) + " |")
    return lines


def _title(title: str) -> list[str]:
    return ["", f"#### {title.upper()}"]


def _toggle(body: list[str], label: str = "Toggle", expanded: bool = True) -> list[str]:
    """long.html's Toggle/Details button. The blank lines let markdown (tables) render inside."""
    return ["", f"<details{' open' if expanded else ''}><summary>{label}</summary>", "", *body, "", "</details>"]


def _sample_name(sample: dict[str, Any]) -> str:
    if sample.get("sample_type") == "URL":
        name = sample.get("sample_url") or sample.get("sample_display_url")
    else:
        name = sample.get("sample_filename")
    return name or sample.get("sample_sha256hash") or "Sample"


def _mitre_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


# -- sections (long.html 1-7) -------------------------------------------------------


def _overview(sample: dict[str, Any]) -> list[str]:
    rows = [("Verdict", _verdict(sample.get("sample_verdict")))]
    if sample.get("sample_vti_score") is not None:
        rows.append(("VTI Score", f"{_h(sample['sample_vti_score'])}/100"))
    if sample.get("sample_verdict_reason_description"):
        rows.append(("Reason", _h(sample["sample_verdict_reason_description"])))
    url = sample.get("sample_url") or sample.get("sample_display_url")
    if sample.get("sample_type") == "URL" and url:
        rows.append(("URL", f"<code>{_h(url)}</code>"))
    elif sample.get("sample_filename"):
        rows.append(("Filename", _h(sample["sample_filename"])))
    if sample.get("sample_type"):
        rows.append(("Type", _h(sample["sample_type"])))
    if sample.get("sample_created"):
        rows.append(("Created", _h(_date(sample["sample_created"]))))
    for key, label in (("sample_md5hash", "MD5"), ("sample_sha1hash", "SHA1"), ("sample_sha256hash", "SHA256")):
        if sample.get(key):
            rows.append((label, f"<code>{_h(sample[key])}</code>"))
    if sample.get("sample_webif_url"):
        rows.append(("Report Link", f'<a href="{_h(sample["sample_webif_url"])}">View in VMRay</a>'))
    body = "".join(f"<tr><td><b>{label}</b></td><td>{value}</td></tr>" for label, value in rows)
    return [*_title("Overview"), "", f"<table>{body}</table>"]


def _detections(sample: dict[str, Any]) -> list[str]:
    lines = []
    for key, label in (("sample_threat_names", "Threat Names"), ("sample_classifications", "Classifications")):
        if sample.get(key):
            lines.append(f"**{label}:** " + " ".join(_code(v) for v in sample[key]) + "  ")
    return [*_title("Detections"), "", *lines] if lines else []


def _ioc_summary(iocs: dict[str, Any]) -> list[str]:
    present = [(label, len(iocs.get(key) or [])) for key, _value_key, label in _IOC_TYPES if iocs.get(key)]
    if not present:
        return []
    return [*_title("IOC Summary"), "", *_table([label for label, _ in present], [[f"**{n}**" for _, n in present]])]


def _threat_indicators(vtis: list[dict[str, Any]]) -> list[str]:
    if not vtis:
        return []
    rows = [
        [
            _score(vti.get("score")),
            _text(vti.get("category") or "—"),
            _text(vti.get("operation") or "—"),
            _text(", ".join(vti.get("classifications") or []) or "—"),
        ]
        for vti in sorted(vtis, key=lambda v: v.get("score") or 0, reverse=True)
    ]
    table = _table(["Score", "Category", "Operation", "Classification"], rows)
    return [*_title("VMRay Threat Identifiers"), *_toggle(table)]


def _mitre(techniques: list[dict[str, Any]]) -> list[str]:
    if not techniques:
        return []
    ids = [t["technique_id"] for t in techniques if t.get("technique_id")]
    buttons = " ".join(f"[{_code(i)}]({_mitre_url(i)})" for i in ids)
    rows = [
        [
            f"[{_code(t['technique_id'])}]({_mitre_url(t['technique_id'])})" if t.get("technique_id") else "—",
            _text(t.get("technique") or "—"),
            _text(", ".join(t.get("tactics") or []) or "—"),
        ]
        for t in techniques
    ]
    details = _toggle(_table(["ID", "Technique", "Tactics"], rows), label="Details", expanded=False)
    return [*_title("MITRE ATT&CK"), "", buttons, *details]


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
    table = ["| Type | Value | Verdict |", "|---|---|---|", *("| " + " | ".join(row) + " |" for row in rows)]
    if omitted:
        table.append(f"| _…and {omitted} more_ | | |")
    return [*_title("Indicators of Compromise"), *_toggle(table)]


def _analyses(analyses: list[dict[str, Any]]) -> list[str]:
    if not analyses:
        return []
    rows = [
        [
            _text(a.get("analysis_analyzer_name") or "—"),
            _text(a.get("analysis_vm_description") or "—"),
            _code(_date(a["analysis_created"])) if a.get("analysis_created") else "—",
            _verdict(a.get("analysis_verdict")),
        ]
        for a in sorted(analyses, key=lambda a: a.get("analysis_created") or "", reverse=True)
    ]
    table = _table(["Analysis", "Target Environment", "Created", "Verdict"], rows)
    return [*_title("Analyses"), *_toggle(table)]


def _screenshot_rows(analysis: dict[str, Any]) -> list[str]:
    """One list-mode table row per screenshot: its name, and a View toggle that reveals the image."""
    rows = []
    for shot in analysis.get("analysis_screenshots") or []:
        if not (isinstance(shot.get("data"), str) and _BASE64.fullmatch(shot["data"])):
            continue
        name = _h(shot.get("name") or "screenshot")
        image = f'<img src="data:image/jpeg;base64,{shot["data"]}" alt="{name}" width="{_SCREENSHOT_WIDTH}">'
        rows.append(f"<tr><td>{name}</td><td><details><summary>View</summary>{image}</details></td></tr>")
    return rows


def _screenshots(sample: dict[str, Any]) -> list[str]:
    """The main comment only points at the screenshots: the images themselves go in separate comments
    (render_screenshot_comments), since all of them together exceed Sekoia's playbook argument limit."""
    count = sum(len(_screenshot_rows(a)) for a in sample.get("sample_analyses") or [])
    if not (count or sample.get("screenshots_truncated")):
        return []
    body = []
    if count:
        body.append(f"**{count} screenshot(s)** — posted in the separate _VMRay Screenshots_ comment(s).")
    if sample.get("screenshots_truncated"):
        body += [
            "",
            "⚠️ _Some analysis screenshots have been excluded from this report due to size limitations. "
            "The complete set of screenshots is available on the VMRay platform._",
        ]
    return [*_title("Screenshots"), "", *body]


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


_COMMENT_HEADER_RESERVE = 64  # room for the "## VMRay Screenshots (i/N)" line
_TABLE_OPEN = "<table><tr><th>Name</th><th>Action</th></tr>"
_TABLE_CLOSE = "</table>"


def render_screenshot_comments(report: dict[str, Any], max_bytes: int) -> list[str]:
    """Pack every screenshot row, in order, into as few comments as fit under max_bytes each. A row is
    never split; one bigger than the limit still gets a comment of its own."""
    budget = max(max_bytes - _COMMENT_HEADER_RESERVE, 1)
    chunks: list[list[tuple[str, list[str]]]] = []
    current: list[tuple[str, list[str]]] = []
    size = 0
    for heading, tiles in _screenshot_groups(report):
        for tile in tiles:
            group_cost = len(heading) + len(_TABLE_OPEN) + len(_TABLE_CLOSE) + 4
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
            [f"## VMRay Screenshots ({index}/{len(chunks)})"]
            + [
                line
                for heading, rows in chunk
                for line in ("", heading, "", _TABLE_OPEN + "".join(rows) + _TABLE_CLOSE)
            ]
        )
        for index, chunk in enumerate(chunks, start=1)
    ]


def _child_rows(children: list[dict[str, Any]], depth: int = 0) -> list[list[str]]:
    rows = []
    for child in children:
        grandchildren = child.get("sample_child_samples") or []
        count = len(grandchildren) or len(child.get("sample_child_sample_ids") or [])
        rows.append(
            [
                _verdict(child.get("sample_verdict")),
                ("↳ " * depth) + _code(_sample_name(child)),
                _text(child.get("sample_type") or "—"),
                str(count) if count else "—",
                f"[View in VMRay]({child['sample_webif_url']})" if child.get("sample_webif_url") else "—",
            ]
        )
        rows += _child_rows(grandchildren, depth + 1)
    return rows


def _child_samples(sample: dict[str, Any]) -> list[str]:
    children = sample.get("sample_child_samples") or []
    if children:
        table = _table(["Verdict", "Sample", "Type", "Children", "Report"], _child_rows(children))
        return [*_title(f"Child Samples ({len(children)})"), *_toggle(table)]
    if sample.get("sample_child_sample_ids"):
        count = len(sample["sample_child_sample_ids"])
        return [*_title(f"Child Samples ({count})"), "", "_Not expanded — see the VMRay report._"]
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
    lines = ["## VMRay Report"]
    if not samples:
        lines += ["", "**No matches found for this observable.**"]
    for index, sample in enumerate(samples, start=1):
        if len(samples) > 1:
            lines += ["", "---", "", f"### SAMPLE ({index}/{len(samples)})"]
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

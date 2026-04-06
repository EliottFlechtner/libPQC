"""Generate in-repo coverage assets from coverage JSON output."""

import json
from datetime import datetime, timezone
from pathlib import Path


def coverage_color(pct: float) -> str:
    if pct >= 95:
        return "#4c1"
    if pct >= 90:
        return "#97CA00"
    if pct >= 80:
        return "#a4a61d"
    if pct >= 70:
        return "#dfb317"
    return "#e05d44"


def build_badge_svg(pct: float) -> str:
    label = "coverage"
    value = f"{pct}%"
    label_w = 66
    value_w = max(46, 8 * len(value) + 14)
    total_w = label_w + value_w
    color = coverage_color(pct)

    return f"""<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{total_w}\" height=\"20\" role=\"img\" aria-label=\"coverage: {value}\">\n<linearGradient id=\"s\" x2=\"0\" y2=\"100%\">\n<stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>\n<stop offset=\"1\" stop-opacity=\".1\"/>\n</linearGradient>\n<clipPath id=\"r\">\n<rect width=\"{total_w}\" height=\"20\" rx=\"3\" fill=\"#fff\"/>\n</clipPath>\n<g clip-path=\"url(#r)\">\n<rect width=\"{label_w}\" height=\"20\" fill=\"#555\"/>\n<rect x=\"{label_w}\" width=\"{value_w}\" height=\"20\" fill=\"{color}\"/>\n<rect width=\"{total_w}\" height=\"20\" fill=\"url(#s)\"/>\n</g>\n<g fill=\"#fff\" text-anchor=\"middle\" font-family=\"DejaVu Sans,Verdana,Geneva,sans-serif\" font-size=\"11\">\n<text x=\"{label_w / 2}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{label}</text>\n<text x=\"{label_w / 2}\" y=\"14\">{label}</text>\n<text x=\"{label_w + value_w / 2}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{value}</text>\n<text x=\"{label_w + value_w / 2}\" y=\"14\">{value}</text>\n</g>\n</svg>\n"""


def main() -> None:
    coverage_json = Path("coverage/coverage.json")
    badge_svg = Path("coverage/badge.svg")
    summary_md = Path("coverage/summary.md")

    data = json.loads(coverage_json.read_text())
    pct = round(float(data["totals"]["percent_covered"]), 2)

    badge_svg.write_text(build_badge_svg(pct))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary_md.write_text(
        "# Coverage Report\n\n"
        f"- **Total coverage:** `{pct}%`\n"
        f"- **Updated:** `{now}`\n\n"
        "## Files\n\n"
        "- `coverage/coverage.xml`\n"
        "- `coverage/coverage.json`\n"
        "- HTML report is generated as a CI artifact or locally via `coverage html`\n"
    )


if __name__ == "__main__":
    main()

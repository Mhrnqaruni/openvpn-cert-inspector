"""Build the README figures from data committed to the repository.

* ``docs/figures/field-timeline-{light,dark}.svg`` from ``results/field-timeline.csv``
  and ``results/field-milestones.json`` (anonymised client log, relative times only);
* ``docs/figures/teaser.svg`` from ``results/transcripts/*.txt`` (real CLI output
  recorded by the lab against a real OpenVPN server).

Usage: ``python tools/make_figures.py`` (needs the ``figures`` extra: matplotlib).
Colours: blue/red pair validated for colour-vision deficiency in both themes;
lanes and marker shapes carry the same information without colour.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
FIGURES = ROOT / "docs" / "figures"
RESULTS = ROOT / "results"
PNG = "--png" in sys.argv  # also write PNG previews (not committed)

plt.rcParams.update(
    {
        "svg.fonttype": "path",
        "svg.hashsalt": "ovpncert",
        "font.family": "DejaVu Sans",
        "font.size": 9,
    }
)

THEMES = {
    "light": {
        "surface": "#fcfcfb",
        "text": "#0b0b0b",
        "muted": "#52514e",
        "grid": "#e4e3df",
        "band": "#f0efec",
        "accepted": "#2a78d6",
        "rejected": "#d03b3b",
    },
    "dark": {
        "surface": "#1a1a19",
        "text": "#f0efec",
        "muted": "#c3c2b7",
        "grid": "#383835",
        "band": "#262624",
        "accepted": "#3987e5",
        "rejected": "#d03b3b",
    },
}


def field_timeline(theme_name: str) -> Path:
    theme = THEMES[theme_name]
    with (RESULTS / "field-timeline.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    milestones = json.loads((RESULTS / "field-milestones.json").read_text(encoding="utf-8"))
    accepted = [
        float(r["minutes_from_expiry"]) / 60 for r in rows if r["event"] in ("handshake-ok", "connected")
    ]
    rejected = [float(r["minutes_from_expiry"]) / 60 for r in rows if r["event"] == "cert-failure"]
    pinned = milestones["pinned_profile_connected"] / 60
    renewed = milestones["operator_renewed_server_a"] / 60

    fig, ax = plt.subplots(figsize=(10, 3.4))
    fig.patch.set_facecolor(theme["surface"])
    ax.set_facecolor(theme["surface"])
    ax.axvspan(0, pinned, color=theme["band"], zorder=0, linewidth=0)

    ax.scatter(
        accepted,
        [1] * len(accepted),
        marker="o",
        s=34,
        color=theme["accepted"],
        edgecolors=theme["surface"],
        linewidths=1.0,
        zorder=3,
    )
    ax.scatter(
        rejected,
        [0] * len(rejected),
        marker="X",
        s=60,
        color=theme["rejected"],
        edgecolors=theme["surface"],
        linewidths=1.0,
        zorder=3,
    )

    marks = [
        (0.0, 1.62, "right", "server certificates expire\n(A at T0, B at T0 + 5 min)"),
        (pinned, 1.62, "right", "profile pinned with\novpncert pin connects"),
        (renewed, 2.22, "right", "operator renews server A:\nthe pin stops matching (fails closed)"),
    ]
    for x, y, align, label in marks:
        ax.plot([x, x], [-0.45, y - 0.06], color=theme["muted"], linewidth=1, linestyle=(0, (3, 3)), zorder=1)
        ax.text(
            x + (0.08 if align == "left" else -0.08 if align == "right" else 0),
            y,
            label,
            ha=align,
            va="bottom",
            color=theme["text"],
            fontsize=8.5,
            linespacing=1.25,
        )

    for x, label in [
        (-5.2, "normal operation"),
        (pinned / 2, "outage: every client\nrejects the server"),
        ((pinned + renewed) / 2 + 0.05, "pinned"),
    ]:
        ax.text(x, -0.62, label, ha="center", va="top", color=theme["muted"], fontsize=8, linespacing=1.2)

    ax.set_yticks([0, 1], ["certificate\nrejected", "handshake\naccepted"], color=theme["text"])
    ax.set_xlim(-10.6, 4.7)
    ax.set_ylim(-1.15, 2.95)
    ax.set_xticks(range(-10, 5, 2))
    ax.set_xticklabels([f"{h:+d} h" if h else "T0" for h in range(-10, 5, 2)], color=theme["muted"])
    ax.set_xlabel("time relative to the first server-certificate expiry", color=theme["muted"], labelpad=6)
    ax.tick_params(axis="both", length=0, pad=6)
    ax.grid(axis="x", color=theme["grid"], linewidth=0.8, zorder=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.text(
        0.012,
        0.965,
        "Field validation: expiry, outage, pinned recovery, renewal",
        color=theme["text"],
        fontsize=11,
        fontweight="bold",
        va="top",
    )
    fig.text(
        0.012,
        0.895,
        "Two-server production OpenVPN service (anonymised). Every mark is one TLS handshake in the client "
        "log; the client renegotiates every 14.6 minutes.",
        color=theme["muted"],
        fontsize=8.5,
        va="top",
    )
    fig.subplots_adjust(left=0.105, right=0.985, top=0.80, bottom=0.17)
    path = FIGURES / f"field-timeline-{theme_name}.svg"
    fig.savefig(path, facecolor=theme["surface"], metadata={"Date": None})
    if PNG:
        fig.savefig(path.with_suffix(".png"), facecolor=theme["surface"], dpi=110)
    plt.close(fig)
    return path


# -- teaser: real CLI output rendered as a terminal ---------------------------------

TERM = {
    "bg": "#1a1a19",
    "bar": "#262624",
    "text": "#f0efec",
    "muted": "#9b9a92",
    "good": "#4cc04c",
    "bad": "#ef6b6b",
    "accent": "#6aa9f0",
    "warn": "#fab219",
}

_RULES = [
    (re.compile(r"\bPASS\b|\baccepts\b|\d+ days? left|\d+ hours? left"), TERM["good"]),
    (re.compile(r"\bFAIL\b|\brejects\b|EXPIRED [^|]*?ago|NOT YET VALID|CRITICAL"), TERM["bad"]),
    (re.compile(r"^DIAGNOSIS\b|What to do|Evidence|Server certificate|Other findings"), TERM["text"]),
]


def _segments(line: str) -> list[tuple[str, str, bool]]:
    """Split a line into (text, colour, bold) segments by the highlight rules."""
    if line.startswith("$ "):
        return [("$ ", TERM["muted"], False), (line[2:], TERM["text"], True)]
    spans = []
    for pattern, colour in _RULES:
        for match in pattern.finditer(line):
            spans.append((match.start(), match.end(), colour))
    spans.sort()
    segments, cursor = [], 0
    base = TERM["text"]
    bold_line = line.startswith(("* ", "x ", "DIAGNOSIS"))
    dim = re.match(r"^\s{2,}(subject|issuer|validity|sha256|serial|key|usage|chain|result|clients)\b", line)
    for start, end, colour in spans:
        if start < cursor:
            continue
        if start > cursor:
            segments.append((line[cursor:start], TERM["muted"] if dim and cursor == 0 else base, bold_line))
        segments.append((line[start:end], colour, True))
        cursor = end
    if cursor < len(line):
        segments.append((line[cursor:], base, bold_line))
    if dim and segments:
        label = dim.group(0)
        first_text, first_colour, first_bold = segments[0]
        if first_text.startswith(label):
            segments[0:1] = [
                (label, TERM["muted"], False),
                (first_text[len(label) :], first_colour, first_bold),
            ]
    return segments


def teaser(transcripts: list[str], title: str) -> Path:
    lines: list[str] = []
    for name in transcripts:
        text = (RESULTS / "transcripts" / name).read_text(encoding="utf-8")
        body = [line for line in text.splitlines() if not line.startswith("[exit status")]
        lines += [*body, ""]
    while lines and not lines[-1].strip():
        lines.pop()
    width_chars = max(len(line) for line in lines)
    char_w, line_h = 0.0725, 0.205  # inches, DejaVu Sans Mono at 8.6 pt
    fig_w = width_chars * char_w + 0.6
    fig_h = len(lines) * line_h + 0.95
    fig = plt.figure(figsize=(fig_w, fig_h))
    fig.patch.set_alpha(0)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, fig_w)
    ax.set_ylim(0, fig_h)
    ax.axis("off")
    ax.add_patch(
        FancyBboxPatch(
            (0.04, 0.04),
            fig_w - 0.08,
            fig_h - 0.08,
            boxstyle="round,pad=0,rounding_size=0.12",
            color=TERM["bg"],
        )
    )
    ax.add_patch(
        FancyBboxPatch(
            (0.04, fig_h - 0.42),
            fig_w - 0.08,
            0.38,
            boxstyle="round,pad=0,rounding_size=0.12",
            color=TERM["bar"],
        )
    )
    ax.add_patch(plt.Rectangle((0.04, fig_h - 0.42), fig_w - 0.08, 0.14, color=TERM["bar"]))
    for i, colour in enumerate(("#ef6b6b", "#fab219", "#4cc04c")):
        ax.add_patch(plt.Circle((0.3 + i * 0.22, fig_h - 0.23), 0.06, color=colour))
    ax.text(
        fig_w / 2,
        fig_h - 0.23,
        title,
        ha="center",
        va="center",
        color=TERM["muted"],
        family="DejaVu Sans",
        fontsize=8.5,
    )
    y = fig_h - 0.72
    for line in lines:
        x = 0.3
        for text, colour, bold in _segments(line):
            ax.text(
                x,
                y,
                text,
                ha="left",
                va="baseline",
                color=colour,
                family="DejaVu Sans Mono",
                fontsize=8.6,
                fontweight="bold" if bold else "normal",
            )
            x += len(text) * char_w
        y -= line_h
    path = FIGURES / "teaser.svg"
    fig.savefig(path, transparent=True, metadata={"Date": None})
    if PNG:
        fig.savefig(path.with_suffix(".png"), transparent=True, dpi=110)
    plt.close(fig)
    return path


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        print("wrote", field_timeline(theme).relative_to(ROOT))
    if (RESULTS / "transcripts" / "inspect.txt").exists():
        print(
            "wrote",
            teaser(
                ["diagnose.txt", "inspect-pinned.txt"],
                "ovpncert against a real OpenVPN 2.6 server whose certificate expired",
            ).relative_to(ROOT),
        )


if __name__ == "__main__":
    main()

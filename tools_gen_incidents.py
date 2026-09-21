#!/usr/bin/env python3
"""Render docs/incidents/INCIDENT-CATALOG.md from docs/incidents/incidents.json.

The JSON is the source of truth; this is the published view. Run:
    python3 tools_gen_incidents.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "docs", "incidents", "incidents.json")
OUT = os.path.join(HERE, "docs", "incidents", "INCIDENT-CATALOG.md")

CATEGORY_ORDER = [
    "parser_rce_chain",
    "registry_worm",
    "agent_injection",
    "oauth_identity_chain",
    "autonomous_agent",
    "ai_autofix",
    "edge_primitives",
]

PRIORITY_LABEL = {1: "P1 now", 2: "P2 next", 3: "P3 backlog"}


def anchor(s):
    return s.lower().replace(" ", "-").replace("/", "").replace(":", "")


def table_of_incidents(incidents):
    rows = ["| id | date | category | priority | one line |", "|---|---|---|---|---|"]
    for inc in incidents:
        cat = inc["category"]
        rows.append(
            f"| [`{inc['id']}`](#{anchor(inc['id']).replace('.', '')}) | {inc.get('date','')} "
            f"| {cat} | {PRIORITY_LABEL.get(inc.get('test_priority'), '?')} | {inc['one_line']} |"
        )
    return "\n".join(rows)


def render_incident(inc):
    L = []
    L.append(f"### `{inc['id']}` - {inc['title']}")
    L.append("")
    meta = [
        f"**Date:** {inc.get('date','?')}",
        f"**Actor:** {inc.get('actor','n/a')}",
        f"**Pattern:** `{inc['category']}`",
        f"**AI-agent role:** `{inc.get('ai_agent','none')}`",
        f"**Test priority:** {PRIORITY_LABEL.get(inc.get('test_priority'), '?')}",
        f"**Status:** {inc.get('status','candidate')}",
    ]
    L.append(" · ".join(meta))
    L.append("")
    L.append(inc["one_line"])
    L.append("")
    src = inc.get("source")
    extras = inc.get("extra_sources", [])
    links = [f"[primary source]({src})"] if src else []
    links += [f"[{u}]({u})" for u in extras]
    if links:
        L.append("Sources: " + " · ".join(links))
        L.append("")
    chain = inc.get("chain", {})
    if chain:
        L.append("**Chain**")
        for k in ("initial_access", "identity", "pivot", "impact"):
            if chain.get(k):
                L.append(f"- **{k.replace('_', ' ')}:** {chain[k]}")
        L.append("")
    if inc.get("deception"):
        L.append("**Deception / canary opportunities**")
        for d in inc["deception"]:
            L.append(f"- {d}")
        L.append("")
    if inc.get("rak_fit"):
        L.append("**rak-agent containment fit**")
        for r in inc["rak_fit"]:
            L.append(f"- {r}")
        L.append("")
    if inc.get("other_prevention"):
        L.append("**Other prevention:** " + "; ".join(inc["other_prevention"]))
        L.append("")
    if inc.get("maps_to"):
        L.append("**Maps to estate stages:** " + ", ".join(inc["maps_to"]))
        L.append("")
    if inc.get("cve_backlog"):
        L.append("| CVE | product | class | KEV added |")
        L.append("|---|---|---|---|")
        for c in inc["cve_backlog"]:
            L.append(f"| `{c['cve']}` | {c['product']} | {c['class']} | {c['added']} |")
        L.append("")
    if inc.get("notes"):
        L.append(f"**Notes:** {inc['notes']}")
        L.append("")
    return "\n".join(L)


def main():
    with open(SRC, encoding="utf-8") as f:
        doc = json.load(f)
    incidents = doc["incidents"]
    incidents.sort(key=lambda i: (i.get("test_priority", 9), i.get("date", ""), i["id"]))

    L = []
    L.append(f"# {doc['title']}")
    L.append("")
    L.append(f"_Updated {doc.get('updated','')}. Source of truth: `incidents.json`; this file is generated._")
    L.append("")
    L.append(doc["purpose"])
    L.append("")

    L.append("## How to use")
    L.append("")
    for h in doc.get("how_to_use", []):
        L.append(f"- {h}")
    L.append("")

    L.append("## Legend")
    L.append("")
    for k, v in doc.get("legend", {}).items():
        L.append(f"- **{k}:** {v}")
    L.append("")

    L.append("## Patterns")
    L.append("")
    for k in CATEGORY_ORDER:
        if k in doc.get("patterns", {}):
            L.append(f"- `{k}`: {doc['patterns'][k]}")
    L.append("")

    L.append("## Catalog at a glance")
    L.append("")
    L.append(table_of_incidents(incidents))
    L.append("")

    # group by category, preserving priority order within
    for cat in CATEGORY_ORDER:
        group = [i for i in incidents if i["category"] == cat]
        if not group:
            continue
        L.append(f"## {cat.replace('_', ' ').title()}")
        L.append("")
        if cat in doc.get("patterns", {}):
            L.append(f"> {doc['patterns'][cat]}")
            L.append("")
        for inc in group:
            L.append(render_incident(inc))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L).rstrip() + "\n")
    print(f"wrote {OUT}: {len(incidents)} incidents")
    return 0


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""Render docs/integrations/INTEGRATION-CATALOG.md from docs/integrations/integrations.json.

The JSON is the source of truth; this is the published view. Run:
    python3 tools_gen_integrations.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "docs", "integrations", "integrations.json")
OUT = os.path.join(HERE, "docs", "integrations", "INTEGRATION-CATALOG.md")

TIER_LABEL = {0: "P0 day one", 1: "P1 first ninety days", 2: "P2 later"}
TIER_ORDER = [0, 1, 2]


def priority_table(items):
    rows = ["| id | tier | category | detect | act | ground truth | effort |", "|---|---|---|---|:--:|:--:|---|"]
    for it in items:
        caps = {c.lower() for c in it.get("blue_capabilities", [])}
        rows.append(
            f"| [`{it['id']}`](#{it['id']}) | {TIER_LABEL[it['priority']]} | `{it['category']}` "
            f"| {'yes' if ('detection' in caps or 'diversion' in caps) else 'no'} "
            f"| {'yes' if it.get('enforcement') else 'no'} "
            f"| {'yes' if it.get('direction') and 'telemetry' in it['direction'] else 'no'} "
            f"| {it.get('effort','?')} |")
    return "\n".join(rows)


def render(it):
    L = []
    L.append(f"### `{it['id']}` - {it['name']}")
    L.append("")
    meta = [f"**Tier:** {TIER_LABEL[it['priority']]}", f"**Category:** `{it['category']}`",
            f"**Effort:** {it.get('effort','?')}", f"**Direction:** {', '.join(it.get('direction', []))}"]
    L.append(" · ".join(meta))
    L.append("")
    if it.get("examples"):
        L.append("**Examples:** " + ", ".join(it["examples"]) + ".")
        L.append("")
    L.append(f"**Why here in the order.** {it['why_priority']}")
    L.append("")
    data = it.get("data", {})
    if data:
        L.append("**Data we want**")
        for k, label in (("events", "Events"), ("fields", "Fields"), ("apis", "APIs"), ("join_keys", "Join keys")):
            if data.get(k):
                L.append(f"- {label}")
                for item in data[k]:
                    L.append(f"  - {item}")
        L.append("")
    L.append("**Blue capability.** " + ", ".join(it.get("blue_capabilities", [])) + ".")
    L.append("")
    if it.get("enforcement"):
        L.append("**Actions it unlocks**")
        for e in it["enforcement"]:
            L.append(f"- {e}")
        L.append("")
    demo = it.get("demo", {})
    if demo:
        L.append("**How we demo it**")
        L.append("")
        L.append(f"Drawn from {demo.get('incident','')}. "
                 f"{demo.get('run','')} "
                 f"What it proves: {demo.get('proves','')}")
        L.append("")
    if it.get("risks"):
        L.append("**Risks.** " + "; ".join(it["risks"]) + ".")
        L.append("")
    if it.get("fallback"):
        L.append(f"**Fallback.** {it['fallback']}")
        L.append("")
    return "\n".join(L)


def main():
    doc = json.load(open(SRC, encoding="utf-8"))
    items = doc["integrations"]
    items.sort(key=lambda i: (i.get("priority", 9), i.get("category", ""), i["id"]))

    L = [f"# {doc['title']}", ""]
    L.append(f"_Updated {doc.get('updated','')}. Source of truth: `integrations.json`; this file is generated._")
    L.append("")
    L.append(doc["purpose"])
    L.append("")

    pr = doc["prioritization"]
    L.append("## How we ranked these")
    L.append("")
    L.append(pr["principle"])
    L.append("")
    L.append("| criterion | question | why it matters |")
    L.append("|---|---|---|")
    for c in pr["criteria"]:
        L.append(f"| {c['name']} | {c['question']} | {c['why']} |")
    L.append("")
    for tier, label in TIER_LABEL.items():
        if str(tier) in pr["tiers"]:
            L.append(f"- **{label}:** {pr['tiers'][str(tier)]}")
    L.append("")
    L.append(f"**Smallest day-one demo.** {pr['day1_demo']}")
    L.append("")

    L.append("## At a glance")
    L.append("")
    L.append(priority_table(items))
    L.append("")

    corr = doc.get("correlation", {})
    if corr:
        L.append("## The keys that make it hang together")
        L.append("")
        L.append(corr["note"])
        L.append("")
        L.append("| key | what it joins |")
        L.append("|---|---|")
        for k in corr["join_keys"]:
            L.append(f"| `{k['key']}` | {k['used_for']} |")
        L.append("")

    if doc.get("guardrails"):
        L.append("## Guardrails for every connector")
        L.append("")
        for g in doc["guardrails"]:
            L.append(f"- {g}")
        L.append("")

    for tier in TIER_ORDER:
        group = [i for i in items if i["priority"] == tier]
        if not group:
            continue
        L.append(f"## {TIER_LABEL[tier]}")
        L.append("")
        for it in group:
            L.append(render(it))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "w", encoding="utf-8").write("\n".join(L).rstrip() + "\n")
    print(f"wrote {OUT}: {len(items)} integrations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
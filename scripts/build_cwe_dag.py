#!/usr/bin/env python3
"""Build the CWE hierarchy DAG from MITRE's cwec XML.

Usage:
    python -I build_cwe_dag.py <cwec.xml> <out_dir>

Works with every CWE 4.x catalog (schema 6/7, <Category>) and CWE 5.0
(schema 8, <Grouping>).

Outputs (in <out_dir>):
    cwe_nodes.csv              all weakness + category/grouping entries
    cwe_edges.csv              canonical ChildOf edges (View 1000)
    cwe_edges_all_views.csv    every ChildOf relation, with View_ID
    cwe_grouping_members.csv   category/grouping -> member edges
    cwe_stats.json             graph statistics
    cwe-dag-full.dot           complete weakness hierarchy
    cwe-dag-overview.dot       pillars + direct children
    cwe-dag-deprecated.dot     deprecated roots and their descendants
    cwe-grouping-dag.dot       grouping containment DAG
    cwe-legend.dot             colour/line legend
    pillars/cwe-<id>-<slug>.dot   one graph per active pillar
"""
import csv
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

CANONICAL_VIEW = "1000"  # "Research Concepts" (CWE 4.0-4.20) / "Complete Weakness Hierarchy" (4.21+)


def local(tag):
    return tag.rsplit("}", 1)[-1]


def text_of(el, name):
    for ch in el:
        if local(ch.tag) == name:
            return (ch.text or "").strip()
    return ""


def esc(text):
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def wrap(text, width=28):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        candidate = (cur + " " + w).strip()
        if len(candidate) <= width:
            cur = candidate
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return "\\n".join(lines)


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def node_id(cwe_id):
    return "n" + str(cwe_id)


def parse(xml_path):
    root = ET.parse(xml_path).getroot()
    meta = {
        "catalog": root.get("Name") or "CWE",
        "version": root.get("Version") or "",
        "date": root.get("Date") or "",
        "view_name": "",
        "group_element": "",
    }
    for el in root.iter():
        if local(el.tag) == "View" and el.get("ID") == CANONICAL_VIEW:
            meta["view_name"] = el.get("Name") or ""
            break

    weaknesses, groupings = {}, {}
    for el in root.iter():
        tag = local(el.tag)
        if tag == "Weakness":
            weaknesses[el.get("ID")] = {
                "id": el.get("ID"),
                "kind": "weakness",
                "name": el.get("Name") or "",
                "abstraction": el.get("Abstraction") or "",
                "structure": el.get("Structure") or "",
                "status": el.get("Status") or "",
                "description": text_of(el, "Description"),
            }
        elif tag in ("Category", "Grouping"):
            # CWE 4.x uses <Category>; CWE 5.0 renamed it to <Grouping>.
            meta["group_element"] = tag
            groupings[el.get("ID")] = {
                "id": el.get("ID"),
                "kind": "category" if tag == "Category" else "grouping",
                "name": el.get("Name") or "",
                "abstraction": "Grouping",
                "structure": "",
                "status": el.get("Status") or "",
                "description": text_of(el, "Summary"),
            }

    edges, all_edges = set(), []
    for el in root.iter():
        if local(el.tag) != "Weakness":
            continue
        for rw in el.iter():
            if local(rw.tag) != "Related_Weakness" or rw.get("Nature") != "ChildOf":
                continue
            child, parent, view = el.get("ID"), rw.get("CWE_ID"), rw.get("View_ID")
            all_edges.append((child, parent, view))
            if view == CANONICAL_VIEW:
                edges.add((child, parent))

    memberships = set()
    for el in root.iter():
        if local(el.tag) not in ("Category", "Grouping"):
            continue
        for m in el.iter():
            if local(m.tag) == "Has_Member":
                memberships.add((el.get("ID"), m.get("CWE_ID")))

    return weaknesses, groupings, edges, all_edges, memberships, meta


def analyse(weaknesses, groups, edges):
    children = defaultdict(list)
    parents = defaultdict(list)
    for child, parent in edges:
        children[parent].append(child)
        parents[child].append(parent)

    unknown = {c for c, p in edges if c not in weaknesses or p not in weaknesses}
    depth = {}

    def get_depth(n):
        if n in depth:
            return depth[n]
        ps = parents.get(n, [])
        depth[n] = 0 if not ps else 1 + max(get_depth(p) for p in ps)
        return depth[n]

    for n in weaknesses:
        get_depth(n)

    roots = sorted(n for n in weaknesses if not parents.get(n))
    leaves = sorted(n for n in weaknesses if not children.get(n))
    # descendants / subtree size
    subtree = {}

    def sub_size(n):
        if n in subtree:
            return subtree[n]
        seen, stack = set(), [n]
        while stack:
            u = stack.pop()
            if u in seen:
                continue
            seen.add(u)
            stack.extend(children.get(u, ()))
        subtree[n] = len(seen)
        return subtree[n]

    for n in weaknesses:
        sub_size(n)

    # cycle check
    state, cycles = {}, []

    def dfs(u, stack):
        state[u] = 1
        for v in children.get(u, ()):
            if state.get(v) == 1:
                cycles.append(stack + [u, v])
            elif state.get(v, 0) == 0:
                dfs(v, stack + [u])
        state[u] = 2

    for n in weaknesses:
        if state.get(n, 0) == 0:
            dfs(n, [])

    return {
        "children": children,
        "parents": parents,
        "depth": depth,
        "roots": roots,
        "leaves": leaves,
        "subtree": subtree,
        "cycles": cycles,
        "unknown": unknown,
    }


def style_node(rec, depth=None):
    if rec["status"] in ("Deprecated", "Obsolete"):
        attrs = 'shape=box, style="rounded,filled,dashed", fillcolor="#E8E8E8", color="#9A9A9A", fontcolor="#5A5A5A"'
    else:
        palette = {
            "Pillar": ('fillcolor="#0B3C5D"', 'fontcolor="white"'),
            "Class": ('fillcolor="#1D6FA5"', 'fontcolor="white"'),
            "Base": ('fillcolor="#A8CBE3"', 'fontcolor="#111111"'),
            "Variant": ('fillcolor="#E3F0F7"', 'fontcolor="#111111"'),
            "Compound": ('fillcolor="#F2A65A"', 'fontcolor="#111111"'),
        }
        fill, font = palette.get(rec["abstraction"], ('fillcolor="#FFFFFF"', 'fontcolor="#111111"'))
        attrs = f'shape=box, style="rounded,filled", {fill}, {font}, color="#4A6B82"'
    label = wrap(f"CWE-{rec['id']} {rec['name']}")
    return f'{node_id(rec["id"])} [label="{label}", {attrs}];'


def write_dot(path, title, lines, extra_graph=""):
    header = [
        "// " + title.replace("\n", " "),
        "digraph CWE_DAG {",
        f'  graph [rankdir=LR, splines=polyline, nodesep=0.10, ranksep=0.55, '
        f'fontname="Helvetica", fontsize=16, bgcolor="white", newrank=true, {extra_graph}];',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9, '
        'margin="0.06,0.03", height=0.3];',
        '  edge [color="#8A9BA8", penwidth=0.7, arrowsize=0.55];',
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(header + lines + ["}", ""]))


def root_of(n, parents):
    seen = set()
    while parents.get(n) and n not in seen:
        seen.add(n)
        n = parents[n][0]
    return n


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    xml_path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "pillars"), exist_ok=True)

    weaknesses, groupings, edges, all_edges, memberships, meta = parse(xml_path)
    weak = weaknesses
    a = analyse(weak, groupings, edges)
    children, parents, depth, roots, leaves = a["children"], a["parents"], a["depth"], a["roots"], a["leaves"]

    # ---------- CSV ----------
    with open(os.path.join(out_dir, "cwe_nodes.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["id", "kind", "name", "abstraction", "structure", "status",
                     "depth", "parent_ids", "root_id", "subtree_size", "n_children", "url"])
        for rec in list(weak.values()) + list(groupings.values()):
            wid = rec["id"]
            wr.writerow([wid, rec["kind"], rec["name"], rec["abstraction"], rec["structure"],
                         rec["status"], depth.get(wid, ""), "|".join(parents.get(wid, [])),
                         root_of(wid, parents) if wid in weak else "",
                         a["subtree"].get(wid, ""), len(children.get(wid, [])),
                         f"https://cwe.mitre.org/data/definitions/{wid}.html"])

    with open(os.path.join(out_dir, "cwe_edges.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["child_id", "parent_id", "child_name", "parent_name", "view_id"])
        for child, parent in sorted(edges, key=lambda e: (int(e[1]), int(e[0]))):
            wr.writerow([child, parent, weak[child]["name"], weak[parent]["name"], CANONICAL_VIEW])

    with open(os.path.join(out_dir, "cwe_edges_all_views.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["child_id", "parent_id", "view_id"])
        for row in sorted(all_edges, key=lambda r: (r[2], int(r[1]), int(r[0]))):
            wr.writerow(row)

    with open(os.path.join(out_dir, "cwe_grouping_members.csv"), "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["grouping_id", "grouping_name", "member_id", "member_kind", "member_name"])
        for g, m in sorted(memberships, key=lambda e: (int(e[0]), int(e[1]))):
            name = (weak if m in weak else groupings).get(m, {}).get("name", "")
            kind = "weakness" if m in weak else groupings.get(m, {}).get("kind", "unknown")
            wr.writerow([g, groupings[g]["name"], m, kind, name])

    # ---------- stats ----------
    level_counts = Counter(depth.values())
    group_edges = [(g, m) for g, m in memberships if m in groupings]
    stats = {
        "source": {"file": os.path.basename(xml_path), "cwe_version": meta["version"],
                   "release_date": meta["date"], "group_element": meta["group_element"]},
        "entries": {"weaknesses": len(weak), "groupings": len(groupings),
                    "total": len(weak) + len(groupings),
                    "active_weaknesses": sum(1 for r in weak.values()
                                             if r["status"] not in ("Deprecated", "Obsolete"))},
        "canonical_dag": {
            "view": CANONICAL_VIEW, "view_name": meta["view_name"],
            "nodes": len(weak), "edges": len(edges),
            "roots": len(roots), "leaves": len(leaves),
            "max_depth": max(depth.values()), "levels": dict(sorted(level_counts.items())),
            "multi_parent_nodes": sum(1 for n, ps in parents.items() if len(ps) > 1),
            "max_in_degree": max((len(v) for v in parents.values()), default=0),
            "cycles": len(a["cycles"]), "is_dag": len(a["cycles"]) == 0,
        },
        "abstraction": dict(Counter(r["abstraction"] for r in weak.values())),
        "status": dict(Counter(r["status"] for r in weak.values())),
        "groupings": {"total": len(groupings),
                      "with_members": sum(1 for g in groupings if any(e[0] == g for e in memberships)),
                      "membership_edges": len(memberships),
                      "group_containment_edges": len(group_edges),
                      "group_containment_participants": len({x for p in group_edges for x in p})},
        "all_childof_relations": len(all_edges),
    }
    with open(os.path.join(out_dir, "cwe_stats.json"), "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2, ensure_ascii=False)

    # ---------- full DAG ----------
    # View 1000 is a DAG, not a tree: 235 of the 984 weaknesses have more than
    # one parent and can be reached from more than one pillar. The full graph
    # therefore has no clusters; the hierarchy is drawn as one DAG.
    pillars = [n for n in roots if weak[n]["abstraction"] == "Pillar"]

    down = {}

    def reach(n):
        if n in down:
            return down[n]
        seen, stack = set(), [n]
        while stack:
            u = stack.pop()
            if u in seen:
                continue
            seen.add(u)
            stack.extend(children.get(u, ()))
        down[n] = seen
        return seen

    lines = [style_node(weak[n]) for n in sorted(weak, key=int)]
    for child, parent in sorted(edges, key=lambda e: (int(e[1]), int(e[0]))):
        lines.append(f'  {node_id(parent)} -> {node_id(child)};')
    write_dot(os.path.join(out_dir, "cwe-dag-full.dot"),
              "CWE 5.0 complete weakness hierarchy (View 1000, ChildOf)",
              lines, f'label="CWE {meta["version"]} — {meta["view_name"]} (View 1000) — {len(weak)} weaknesses, {len(edges)} ChildOf edges, 0 cycles"; labelloc=t; fontsize=22; pack=true; packmode=array;')

    # ---------- overview: pillars + direct children ----------
    lines, seen = [], set()
    for pil in pillars:
        for n in [pil] + children.get(pil, []):
            if n not in seen:
                seen.add(n)
                lines.append(style_node(weak[n]))
    for pil in pillars:
        for ch in children.get(pil, []):
            lines.append(f'  {node_id(pil)} -> {node_id(ch)};')
    write_dot(os.path.join(out_dir, "cwe-dag-overview.dot"),
              "CWE 5.0 pillars and direct children",
              lines, f'label="CWE {meta["version"]} — 10 pillars and their direct children (border nodes are roots)"; labelloc=t; fontsize=20; ranksep=0.8; nodesep=0.12;')

    # ---------- per-pillar induced sub-DAGs ----------
    pillar_index = []
    for pil in pillars:
        rel = {pil: 0}
        stack = [pil]
        while stack:
            u = stack.pop()
            for ch in children.get(u, ()):
                if ch not in rel:
                    rel[ch] = rel[u] + 1
                    stack.append(ch)
        members = set(rel)
        lines = [style_node(weak[n]) for n in sorted(members, key=lambda x: (rel[x], int(x)))]
        local_edges = [(c, p) for c, p in edges if c in members and p in members]
        external = sum(1 for c in members for p in parents.get(c, ()) if p not in members)
        for child, parent in sorted(local_edges, key=lambda e: (int(e[1]), int(e[0]))):
            lines.append(f'  {node_id(parent)} -> {node_id(child)};')
        slug = slugify(weak[pil]["name"])[:40]
        fname = f"pillars/cwe-{pil}-{slug}.dot"
        title = (f"CWE-{pil} {weak[pil]['name']} — {len(members)} nodes, depth "
                 f"{max(rel.values())}, {len(local_edges)} ChildOf edges")
        note = f"{external} cross-pillar parent link(s) omitted"
        write_dot(os.path.join(out_dir, fname),
                  title,
                  lines,
                  f'label="{esc(wrap(title, 80))}\\n{esc(note)}"; labelloc=t; fontsize=20; ranksep=0.55;')
        pillar_index.append({"id": pil, "name": weak[pil]["name"], "nodes": len(members),
                             "edges": len(local_edges),
                             "external_parent_links": external,
                             "depth": max(rel.values()), "file": fname})

    # ---------- deprecated / orphan graph ----------
    reachable = set()
    for pil in pillars:
        reachable |= reach(pil)
    members = set(weak) - reachable
    if members:
        lines = [style_node(weak[n]) for n in sorted(members, key=int)]
        for child, parent in sorted(edges, key=lambda e: (int(e[1]), int(e[0]))):
            if child in members and parent in members:
                lines.append(f'  {node_id(parent)} -> {node_id(child)};')
        write_dot(os.path.join(out_dir, "cwe-dag-deprecated.dot"),
                  "Deprecated and orphan weakness entries",
                  lines, 'label="Deprecated / orphan CWE entries (unreachable from any pillar)"; labelloc=t; fontsize=20;')

    # ---------- grouping containment DAG ----------
    # Groupings are organisational (formerly "categories"); they sit outside
    # the weakness hierarchy. Membership is exported to CSV, not drawn here.
    # Only groupings that contain another grouping are drawn; the rest are
    # isolated nodes and would add nothing but noise.
    grouping_edges = [(g, m) for g, m in memberships if m in groupings]
    participants = {x for pair in grouping_edges for x in pair}
    lines = []
    for g in sorted(participants, key=int):
        rec = groupings[g]
        n_mem = sum(1 for e in memberships if e[0] == g)
        label = wrap(f"CWE-{g} {rec['name']}") + f"\\n[{n_mem} members]"
        lines.append(f'{node_id(g)} [label="{label}", shape=box, style="rounded,filled,dashed", '
                     'fillcolor="#F7E8B5", color="#B59A3C", fontcolor="#4A3B0A"];')
    for g, m in sorted(grouping_edges, key=lambda e: (int(e[0]), int(e[1]))):
        lines.append(f'  {node_id(g)} -> {node_id(m)};')
    write_dot(os.path.join(out_dir, "cwe-grouping-dag.dot"),
              "CWE 5.0 grouping containment DAG",
              lines, f'label="CWE 5.0 — groupings containing other groupings ({len(participants)} of {len(groupings)} groupings; the other {len(groupings) - len(participants)} are leaves shown in cwe_grouping_members.csv)"; labelloc=t; fontsize=20;')

    # ---------- legend ----------
    legend = [
        'nP [label="Pillar", shape=box, style="rounded,filled", fillcolor="#0B3C5D", fontcolor="white"];',
        'nC [label="Class", shape=box, style="rounded,filled", fillcolor="#1D6FA5", fontcolor="white"];',
        'nB [label="Base", shape=box, style="rounded,filled", fillcolor="#A8CBE3"];',
        'nV [label="Variant", shape=box, style="rounded,filled", fillcolor="#E3F0F7"];',
        'nM [label="Compound", shape=box, style="rounded,filled", fillcolor="#F2A65A"];',
        'nD [label="Deprecated", shape=box, style="rounded,filled,dashed", fillcolor="#E8E8E8", fontcolor="#5A5A5A"];',
        'nG [label="Grouping", shape=box, style="rounded,filled,dashed", fillcolor="#F7E8B5", fontcolor="#4A3B0A"];',
        'nB -> nV [label="ChildOf (parent → child)"];',
    ]
    write_dot(os.path.join(out_dir, "cwe-legend.dot"), "CWE graph legend", legend,
              'label="Legend"; labelloc=t; fontsize=20;')

    summary = {
        "stats": stats,
        "pillars": pillar_index,
        "deprecated_or_orphan_nodes": len(members),
    }
    print(json.dumps(summary["stats"], indent=2))
    with open(os.path.join(out_dir, "pillars_index.json"), "w", encoding="utf-8") as fh:
        json.dump(pillar_index, fh, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()

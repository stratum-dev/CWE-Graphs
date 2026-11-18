#!/usr/bin/env python3
"""Draw the full heterogeneous CWE graph from the merged catalog.

Input files (``data/merged``, or a generated ``out/merged`` directory):
    cwe_nodes.csv                 weakness + grouping entries
    cwe_edges.csv                 canonical View 1000 ChildOf edges
    cwe_grouping_members.csv      grouping Has_Member relations

Node types:
    weakness Pillar / Class / Base / Variant / Compound
    grouping

Edge types:
    ChildOf      parent weakness -> child weakness (solid dark blue)
    Has_Member   grouping -> member (dashed orange; member may be another grouping)

Seven CWE IDs occur both as weakness and grouping; they are represented as two
separate typed nodes (``w<id>`` and ``g<id>``).

Two layouts are rendered by default:
    dot   hierarchical (large, for tracing the hierarchy)
    sfdp  compact force-directed overview

Usage:
    python -I scripts/cwe_heterogeneous_graph.py \
        --data-dir data/merged \
        --out-dir out/merged/heterogeneous
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

try:
    import pygraphviz as pgv
except ImportError:  # pragma: no cover
    sys.exit("pygraphviz is required: python -m pip install pygraphviz")


ABSTRACTION_STYLE = {
    "Pillar": ("#0B3C5D", "#FFFFFF"),
    "Class": ("#1D6FA5", "#FFFFFF"),
    "Base": ("#A8CBE3", "#111111"),
    "Variant": ("#E3F0F7", "#111111"),
    "Compound": ("#F2A65A", "#111111"),
}
GROUPING_FILL = "#FBE7D2"
GROUPING_LINE = "#C07A2C"
GROUPING_FONT = "#5A3A12"
CHILDOF_EDGE = "#4A6B82"
HAS_MEMBER_EDGE = "#D08C3C"


def wrap(text: str, width: int = 24) -> str:
    words = text.split()
    lines, current = [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return "\n".join(lines)


def read_data(data_dir: Path):
    nodes = {}
    nodes_rows = []
    with open(data_dir / "cwe_nodes.csv", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row["kind"], row["id"])
            nodes[key] = row
            nodes_rows.append(row)

    childof = []
    with open(data_dir / "cwe_edges.csv", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            childof.append((row["parent_id"], row["child_id"]))

    members = []
    with open(data_dir / "cwe_grouping_members.csv", newline="",
              encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            members.append((row["grouping_id"], row["member_id"],
                            row["member_kind"]))
    return nodes, nodes_rows, childof, members


def typed_key(kind: str, cwe_id: str) -> str:
    return ("w" if kind == "weakness" else "g") + cwe_id


def build_edges(nodes, childof, members):
    edge_types = {}
    for parent_id, child_id in childof:
        if (("weakness", parent_id) not in nodes
                or ("weakness", child_id) not in nodes):
            continue
        source = typed_key("weakness", parent_id)
        target = typed_key("weakness", child_id)
        edge_types[(source, target)] = "ChildOf"
    for grouping_id, member_id, member_kind in members:
        if (("grouping", grouping_id) not in nodes
                or (member_kind, member_id) not in nodes):
            continue
        source = typed_key("grouping", grouping_id)
        target = typed_key(member_kind, member_id)
        # Duplicate membership rows are deduplicated.
        if (source, target) not in edge_types:
            edge_types[(source, target)] = "Has_Member"
    return edge_types


def node_attrs(node: dict) -> dict:
    kind = node["kind"]
    name = node["name"]
    status = node.get("status", "")
    if kind == "grouping":
        style = "filled,dashed" if status in ("Deprecated", "Obsolete") else "filled"
        return {
            "label": f"CWE-{node['id']}\n{wrap(name)}",
            "shape": "hexagon",
            "style": style,
            "fillcolor": GROUPING_FILL,
            "color": GROUPING_LINE,
            "fontcolor": GROUPING_FONT,
            "fontname": "Helvetica",
            "fontsize": "8",
            "margin": "0.03,0.02",
            "tooltip": f"[grouping] CWE-{node['id']} {name} ({status})",
        }
    abstraction = node.get("abstraction", "")
    fill, font = ABSTRACTION_STYLE.get(abstraction, ("#FFFFFF", "#111111"))
    style = "rounded,filled"
    if status in ("Deprecated", "Obsolete"):
        style += ",dashed"
    return {
        "label": f"CWE-{node['id']}\n{wrap(name)}",
        "shape": "box",
        "style": style,
        "fillcolor": fill,
        "color": CHILDOF_EDGE,
        "fontcolor": font,
        "fontname": "Helvetica",
        "fontsize": "8",
        "margin": "0.04,0.02",
        "tooltip": f"[{abstraction or 'weakness'}] CWE-{node['id']} {name} ({status})",
    }


def weak_components(node_ids: set[str], edge_types: dict) -> list[int]:
    adjacency = defaultdict(set)
    for source, target in edge_types:
        adjacency[source].add(target)
        adjacency[target].add(source)
    seen = set()
    sizes = []
    for node in sorted(node_ids):
        if node in seen:
            continue
        stack = [node]
        seen.add(node)
        size = 0
        while stack:
            current = stack.pop()
            size += 1
            for neighbor in adjacency.get(current, ()):
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        sizes.append(size)
    return sizes


def build_graph(nodes, nodes_rows, edge_types, layout: str, dpi: int) -> pgv.AGraph:
    graph = pgv.AGraph(strict=True, directed=True, name="CWE_heterogeneous")
    graph.graph_attr.update({
        "fontname": "Helvetica",
        "fontsize": "32",
        "fontcolor": "#1F2933",
        "bgcolor": "white",
        "pad": "0.2",
        "outputorder": "edgesfirst",
        "dpi": str(dpi),
        "label": (f"CWE 1.0–5.0 merged — full heterogeneous graph "
                  f"({len(nodes)} nodes, {len(edge_types)} edges)"),
        "labelloc": "t",
    })
    if layout == "dot":
        graph.graph_attr.update({
            "rankdir": "LR",
            "splines": "line",
            "nodesep": "0.10",
            "ranksep": "0.55",
            "newrank": "true",
            "pack": "true",
            "packmode": "array",
        })
    else:
        graph.graph_attr.update({
            "overlap": "scale",
            "splines": "line",
        })

    for row in nodes_rows:
        key = typed_key(row["kind"], row["id"])
        graph.add_node(key, **node_attrs(row))

    for (source, target), edge_type in sorted(edge_types.items()):
        if edge_type == "ChildOf":
            graph.add_edge(source, target, color=CHILDOF_EDGE,
                           penwidth="0.70", arrowsize="0.45",
                           tooltip="ChildOf")
        else:
            graph.add_edge(source, target, color=HAS_MEMBER_EDGE,
                           penwidth="0.55", arrowsize="0.35",
                           style="dashed", tooltip="Has_Member")
    return graph


def render_legend(out_dir: Path, svg: bool, png: bool) -> None:
    graph = pgv.AGraph(strict=True, directed=True, name="CWE_heterogeneous_legend")
    graph.graph_attr.update({
        "rankdir": "TB",
        "fontname": "Helvetica",
        "fontsize": "16",
        "bgcolor": "white",
        "label": "CWE heterogeneous graph legend",
        "labelloc": "t",
        "pad": "0.3",
        "nodesep": "0.24",
        "ranksep": "0.35",
    })
    graph.node_attr.update({"shape": "box", "fontname": "Helvetica",
                            "fontsize": "9", "margin": "0.08,0.04"})
    graph.edge_attr.update({"fontname": "Helvetica", "fontsize": "9",
                            "arrowsize": "0.6"})

    def section(name, label):
        graph.add_node(name, label=label, shape="plaintext", style="",
                       fontcolor="#1F2933", fontsize="13",
                       margin="0.02,0.02")
    section("sec_nodes", "Node types — weakness abstraction colour, grouping hexagon")
    for abstraction in ("Pillar", "Class", "Base", "Variant", "Compound"):
        fill, font = ABSTRACTION_STYLE[abstraction]
        graph.add_node(f"leg_{abstraction}", label=abstraction,
                       style="rounded,filled", fillcolor=fill, fontcolor=font,
                       color=CHILDOF_EDGE, penwidth="1.3")
    graph.add_node("leg_grouping", label="Grouping", shape="hexagon",
                   style="filled", fillcolor=GROUPING_FILL,
                   color=GROUPING_LINE, fontcolor=GROUPING_FONT,
                   penwidth="1.3")
    graph.add_node("leg_overlap", label="Same ID as weakness + grouping\n"
                                       "is drawn twice",
                   shape="plaintext", style="", fontcolor="#52606D",
                   fontsize="9")

    section("sec_edges", "Edge types")
    graph.add_node("leg_parent", label="parent CWE", style="rounded,filled",
                   fillcolor="#FFFFFF", color=CHILDOF_EDGE)
    graph.add_node("leg_child", label="child CWE", style="rounded,filled",
                   fillcolor="#FFFFFF", color=CHILDOF_EDGE)
    graph.add_node("leg_group", label="grouping", shape="hexagon",
                   style="filled", fillcolor=GROUPING_FILL,
                   color=GROUPING_LINE, fontcolor=GROUPING_FONT)
    graph.add_node("leg_member", label="member", style="rounded,filled",
                   fillcolor="#FFFFFF", color=CHILDOF_EDGE)
    graph.add_edge("leg_parent", "leg_child", label="ChildOf",
                   color=CHILDOF_EDGE, penwidth="1.4")
    graph.add_edge("leg_group", "leg_member", label="Has_Member",
                   color=HAS_MEMBER_EDGE, penwidth="1.2", style="dashed")

    # Rows and vertical stacking.
    abstraction_nodes = [f"leg_{a}" for a in
                         ("Pillar", "Class", "Base", "Variant", "Compound")]
    graph.add_subgraph(abstraction_nodes + ["leg_grouping"],
                       name="legend_node_row", rank="same")
    graph.add_subgraph(["leg_parent", "leg_child"],
                       name="legend_edge_row1", rank="same")
    graph.add_subgraph(["leg_group", "leg_member"],
                       name="legend_edge_row2", rank="same")
    real_edge_rows = {
        ("leg_parent", "leg_child"),
        ("leg_group", "leg_member"),
    }
    for row in (abstraction_nodes + ["leg_grouping"],
                ["leg_parent", "leg_child"], ["leg_group", "leg_member"]):
        for a, b in zip(row, row[1:]):
            if (a, b) in real_edge_rows:
                continue
            graph.add_edge(a, b, style="invis")
    for source, target in [
        ("sec_nodes", abstraction_nodes[0]),
        ("leg_grouping", "sec_edges"),
        ("sec_edges", "leg_parent"),
        ("leg_child", "leg_group"),
        ("leg_member", "leg_overlap"),
    ]:
        graph.add_edge(source, target, style="invis")

    stem = out_dir / "cwe-heterogeneous-legend"
    graph.write(f"{stem}.dot")
    graph.layout(prog="dot")
    if svg:
        graph.draw(f"{stem}.svg", format="svg")
    if png:
        graph.draw(f"{stem}.png", format="png")


def write_typed_csvs(out_dir: Path, nodes, nodes_rows, edge_types) -> None:
    with open(out_dir / "cwe-heterogeneous-nodes.csv", "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["node_id", "cwe_id", "node_type", "abstraction",
                         "status", "name", "url"])
        for row in nodes_rows:
            writer.writerow([
                typed_key(row["kind"], row["id"]), row["id"], row["kind"],
                row.get("abstraction", ""), row.get("status", ""),
                row["name"], row.get("url", ""),
            ])
    with open(out_dir / "cwe-heterogeneous-edges.csv", "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["source_node", "source_cwe", "source_type",
                         "target_node", "target_cwe", "target_type",
                         "edge_type"])
        for (source, target), edge_type in sorted(edge_types.items()):
            sk = nodes[("weakness", source[1:])] if source.startswith("w") \
                else nodes[("grouping", source[1:])]
            tk = nodes[("weakness", target[1:])] if target.startswith("w") \
                else nodes[("grouping", target[1:])]
            writer.writerow([source, sk["id"], sk["kind"],
                             target, tk["id"], tk["kind"], edge_type])


def write_index(out_dir: Path, stats: dict, formats: list[str],
                layouts: list[str], layout_files: dict[str, list[str]]) -> None:
    sections = []
    for layout in layouts:
        links = []
        for fmt in layout_files.get(layout, []):
            links.append(f'<a href="cwe-heterogeneous-{layout}.{fmt}">'
                         f'{layout}.{fmt}</a>')
        links.append(f'<a href="cwe-heterogeneous-{layout}.dot">'
                     f'{layout}.dot</a>')
        desc = ("hierarchical Graphviz dot layout; large but suitable for "
                "tracing parent/child paths" if layout == "dot"
                else "compact force-directed sfdp overview")
        if "png" not in layout_files.get(layout, []):
            desc += (". PNG was skipped because the bitmap is too large; "
                     "use the SVG")
        sections.append(f"""
  <section><h2>{layout}</h2>
  <p class="meta">{desc}.</p>
  <p class="links">{' · '.join(links)}</p></section>""")

    legend_links = [f'<a href="cwe-heterogeneous-legend.{fmt}">'
                    f'legend.{fmt}</a>' for fmt in formats]
    legend_links.append('<a href="cwe-heterogeneous-legend.dot">legend.dot</a>')
    legend_img = ""
    if "png" in formats:
        legend_img = ('<img src="cwe-heterogeneous-legend.png" '
                      'alt="CWE heterogeneous graph legend" loading="lazy">')
    elif "svg" in formats:
        legend_img = ('<img src="cwe-heterogeneous-legend.svg" '
                      'alt="CWE heterogeneous graph legend" loading="lazy">')

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CWE heterogeneous graph</title>
<style>
 body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        margin: 2rem auto; max-width: 1200px; padding: 0 1rem; color: #1f2933; }}
 h1 {{ margin-bottom: .2rem; }} h2 {{ margin-bottom: .2rem; }}
 .sub {{ color: #52606d; margin-top: 0; }}
 section {{ border-top: 1px solid #d9e2ec; padding: 1rem 0 2rem; }}
 .meta {{ color: #52606d; }}
 .links a {{ color: #1d6fa5; text-decoration: none; }}
 .links a:hover {{ text-decoration: underline; }}
 img {{ max-width: 100%; border: 1px solid #d9e2ec; }}
 code {{ background: #f0f4f8; padding: .1rem .3rem; border-radius: 3px; }}
</style></head><body>
  <h1>CWE 1.0–5.0 merged — full heterogeneous graph</h1>
  <p class="sub">{stats['nodes']} nodes
  ({stats['node_types']['weakness']} weaknesses + {stats['node_types']['grouping']} groupings),
  {stats['edges']} edges
  ({stats['edge_types'].get('ChildOf', 0)} ChildOf +
  {stats['edge_types'].get('Has_Member', 0)} Has_Member).
  Weakness nodes are coloured by abstraction; groupings are hexagons.
  The seven IDs that exist as both weakness and grouping are drawn as two
  typed nodes (<code>w&lt;id&gt;</code> and <code>g&lt;id&gt;</code>).</p>
  <section><h2>Legend</h2>
  <p class="links">{' · '.join(legend_links)}</p>{legend_img}</section>
  {''.join(sections)}
  <section><h2>Data and statistics</h2>
  <p class="links">
    <a href="cwe-heterogeneous-nodes.csv">nodes.csv</a> ·
    <a href="cwe-heterogeneous-edges.csv">edges.csv</a> ·
    <a href="stats.json">stats.json</a>
  </p>
  <p class="meta">Components: {stats['components']}; isolated nodes:
  {stats['isolated']}.</p></section>
</body></html>"""
    (out_dir / "index.html").write_text(doc, encoding="utf-8")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Draw the full heterogeneous CWE graph.")
    parser.add_argument("--data-dir", default="data/merged",
                        help="merged data directory (default: %(default)s)")
    parser.add_argument("--out-dir",
                        default="out/merged/heterogeneous",
                        help="output directory (default: %(default)s)")
    parser.add_argument("--layouts", default="dot,sfdp",
                        help="comma-separated layouts: dot,sfdp "
                             "(default: %(default)s)")
    parser.add_argument("--formats", default="svg,png",
                        help="rendered formats in addition to .dot "
                             "(default: %(default)s)")
    parser.add_argument("--png-layouts", default="dot",
                        help="layouts for which PNG is rendered; the sfdp "
                             "bitmap is too large for cairo on this setup "
                             "(default: %(default)s)")
    parser.add_argument("--dpi", type=int, default=48,
                        help="PNG resolution (default: %(default)s)")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    if not data_dir.is_dir():
        sys.exit(f"data directory not found: {data_dir}")

    layouts = [x.strip() for x in args.layouts.split(",") if x.strip()]
    bad = set(layouts) - {"dot", "sfdp"}
    if bad:
        sys.exit(f"unknown layout(s): {', '.join(sorted(bad))}")
    formats = [x.strip().lower() for x in args.formats.split(",") if x.strip()]
    bad = set(formats) - {"svg", "png"}
    if bad:
        sys.exit(f"unknown format(s): {', '.join(sorted(bad))}")
    if "dot" in formats:
        formats.remove("dot")
    png_layouts = {x.strip() for x in args.png_layouts.split(",") if x.strip()}
    bad = png_layouts - set(layouts)
    if bad:
        sys.exit(f"png layout(s) not in layouts: {', '.join(sorted(bad))}")

    nodes, nodes_rows, childof, members = read_data(data_dir)
    edge_types = build_edges(nodes, childof, members)
    node_ids = {typed_key(row["kind"], row["id"]) for row in nodes_rows}
    components = weak_components(node_ids, edge_types)

    node_types = Counter(row["kind"] for row in nodes_rows)
    abstraction_counts = Counter(row.get("abstraction", "")
                                 for row in nodes_rows
                                 if row["kind"] == "weakness")
    edge_counts = Counter(edge_types.values())
    overlap_ids = sorted(
        {row["id"] for row in nodes_rows
         if sum(1 for r in nodes_rows if r["id"] == row["id"]) > 1},
        key=lambda x: (int(x) if x.isdigit() else 10 ** 12, x))

    out_dir.mkdir(parents=True, exist_ok=True)
    write_typed_csvs(out_dir, nodes, nodes_rows, edge_types)

    layout_stats = {}
    layout_files = {}
    for layout in layouts:
        print(f"\nBuilding {layout} graph...")
        started = time.time()
        graph = build_graph(nodes, nodes_rows, edge_types, layout, args.dpi)
        stem = out_dir / f"cwe-heterogeneous-{layout}"
        graph.write(f"{stem}.dot")
        print(f"  layout with {layout} ...")
        graph.layout(prog=layout)
        graph.graph_attr["overlap"] = "true"
        files = []
        for fmt in formats:
            if fmt == "png" and layout not in png_layouts:
                print("  png: skipped (use SVG; bitmap too large for cairo)")
                stale = Path(f"{stem}.png")
                if stale.exists():
                    stale.unlink()
                continue
            t0 = time.time()
            graph.draw(f"{stem}.{fmt}", format=fmt)
            files.append(fmt)
            print(f"  {fmt}: {time.time() - t0:.1f}s")
        layout_files[layout] = files
        layout_stats[layout] = round(time.time() - started, 2)
        print(f"  total: {layout_stats[layout]}s")

    if formats:
        render_legend(out_dir, svg="svg" in formats, png="png" in formats)

    stats = {
        "data_dir": str(data_dir),
        "nodes": len(nodes),
        "node_types": dict(node_types),
        "abstraction": dict(abstraction_counts),
        "edges": len(edge_types),
        "edge_types": dict(edge_counts),
        "raw_childof_rows": len(childof),
        "raw_membership_rows": len(members),
        "components": len(components),
        "isolated": sum(1 for size in components if size == 1),
        "overlap_ids": overlap_ids,
        "layouts": layout_stats,
        "layout_files": layout_files,
        "formats": formats,
        "png_layouts": sorted(png_layouts),
    }
    (out_dir / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    write_index(out_dir, stats, formats, layouts, layout_files)

    print(f"\nNodes: {stats['nodes']} ({node_types['weakness']} weakness + "
          f"{node_types['grouping']} grouping)")
    print(f"Edges: {stats['edges']} ({edge_counts.get('ChildOf', 0)} ChildOf + "
          f"{edge_counts.get('Has_Member', 0)} Has_Member)")
    print(f"Components: {stats['components']}; isolated: {stats['isolated']}")
    print(f"Overlap IDs: {overlap_ids}")
    print(f"Wrote graphs to {out_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

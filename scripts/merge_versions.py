#!/usr/bin/env python3
"""Merge every CWE catalog (1.0-5.0) into one catalog and build a total DAG.

Usage:
    python -I merge_versions.py [--data DIR] [--out DIR] [--skip-render]
                                [--no-sfdp] [--require-all]

Merge policy:
  * Nodes: union of every weakness and grouping ID.
  * Metadata (name, abstraction, status, description) comes from the newest
    catalog containing the entry.
  * Relationships: union of every View 1000 ChildOf relation and every
    grouping membership. Version provenance is not kept; all relationships
    are treated uniformly.
  * If the union contains a cycle, older edges are added only when they do not
    create one.

Outputs:
    data/merged/cwec_merged.xml     merged catalog (parseable by build_cwe_dag.py)
    out/merged/                      standard graph/data outputs for that XML
"""
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from xml.sax.saxutils import escape, quoteattr

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from build_cwe_dag import parse as parse_catalog  # noqa: E402
from fetch_cwe import KNOWN_VERSIONS  # noqa: E402

CANONICAL_VIEW = "1000"


def version_key(version):
    return tuple(int(p) for p in version.split("."))


def find_catalogs(data_dir):
    found = []
    for name in os.listdir(data_dir):
        if not name.startswith("v"):
            continue
        vdir = os.path.join(data_dir, name)
        if not os.path.isdir(vdir):
            continue
        xmls = sorted(f for f in os.listdir(vdir) if f.endswith(".xml"))
        if xmls:
            found.append((name[1:], os.path.join(vdir, xmls[0])))
    return sorted(found, key=lambda item: version_key(item[0]))


def newest_metadata(records):
    merged = {}
    for cid, by_version in records.items():
        merged[cid] = dict(by_version[max(by_version, key=version_key)])
    return merged


def acyclic_union(edge_versions):
    """Return a cycle-free subset of the union; report dropped edges."""
    latest = max((max(vs, key=version_key) for vs in edge_versions.values()), default=None)
    latest_edges = {e for e, vs in edge_versions.items() if latest in vs}
    accepted = set(latest_edges)
    adj = defaultdict(set)
    for child, parent in accepted:
        adj[parent].add(child)

    def reaches(start, target):
        stack, seen = [start], set()
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(adj.get(node, ()))
        return False

    dropped = []
    for child, parent in sorted((e for e in edge_versions if e not in accepted),
                                key=lambda e: (int(e[1]), int(e[0]))):
        if reaches(child, parent):
            dropped.append((child, parent))
        else:
            accepted.add((child, parent))
            adj[parent].add(child)
    return accepted, dropped


def write_merged_xml(path, weak, groups, edges, memberships, version, date):
    span = version.removesuffix("-merged")
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Name="CWE" '
        f'Version={quoteattr(version)} Date={quoteattr(date)}>',
        "  <Weaknesses>",
    ]
    by_child = defaultdict(list)
    for child, parent in edges:
        by_child[child].append(parent)
    for wid in sorted(weak, key=int):
        rec = weak[wid]
        lines.append(
            f'    <Weakness ID={quoteattr(wid)} Name={quoteattr(rec["name"])} '
            f'Abstraction={quoteattr(rec["abstraction"])} '
            f'Structure={quoteattr(rec["structure"])} '
            f'Status={quoteattr(rec["status"])}>')
        lines.append(f'      <Description>{escape(rec["description"])}</Description>')
        lines.append("      <Related_Weaknesses>")
        for parent in sorted(by_child.get(wid, ()), key=int):
            lines.append(
                f'        <Related_Weakness Nature="ChildOf" CWE_ID={quoteattr(parent)} '
                'View_ID="1000" Ordinal="Primary"/>')
        lines.append("      </Related_Weaknesses>")
        lines.append("    </Weakness>")
    lines.append("  </Weaknesses>")
    lines.append("  <Groupings>")

    by_group = defaultdict(list)
    for group, member in memberships:
        by_group[group].append(member)
    for gid in sorted(groups, key=int):
        rec = groups[gid]
        lines.append(
            f'    <Grouping ID={quoteattr(gid)} Name={quoteattr(rec["name"])} '
            f'Status={quoteattr(rec["status"])}>')
        lines.append(f'      <Summary>{escape(rec["description"])}</Summary>')
        lines.append("      <Relationships>")
        for member in sorted(by_group.get(gid, ()), key=int):
            lines.append(
                f'        <Has_Member CWE_ID={quoteattr(member)} View_ID="699"/>')
        lines.append("      </Relationships>")
        lines.append("    </Grouping>")
    lines.append("  </Groupings>")
    lines.append("  <Views>")
    lines.append(f'    <View ID="1000" Name={quoteattr("Merged " + span)} '
                 'Type="Graph" Status="Draft">')
    lines.append(f"      <Objective>Union of every CWE {span} catalog, with all "
                 "view 1000 ChildOf relationships merged.</Objective>")
    lines.append("      <Members>")
    for wid in sorted(weak, key=int):
        lines.append(f'        <Has_Member CWE_ID={quoteattr(wid)} View_ID="1000"/>')
    lines.append("      </Members>")
    lines.append("    </View>")
    lines.append("  </Views>")
    lines.append("</Weakness_Catalog>")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    args = sys.argv[1:]
    data_dir = os.path.join(ROOT, "data")
    out_dir = os.path.join(ROOT, "out", "merged")
    if "--data" in args:
        data_dir = os.path.abspath(args[args.index("--data") + 1])
    if "--out" in args:
        out_dir = os.path.abspath(args[args.index("--out") + 1])
    skip_render = "--skip-render" in args
    with_sfdp = "--no-sfdp" not in args
    require_all = "--require-all" in args

    catalogs = find_catalogs(data_dir)
    if not catalogs:
        sys.exit(f"no catalogs found under {data_dir}")
    versions = [version for version, _path in catalogs]
    missing = [v for v in KNOWN_VERSIONS if v not in versions]
    if missing:
        print("warning: missing catalogs for " + ", ".join(missing), flush=True)
        if require_all:
            sys.exit("--require-all was requested but catalogs are missing")

    weak_records = defaultdict(dict)
    group_records = defaultdict(dict)
    edge_versions = defaultdict(set)
    member_versions = defaultdict(set)
    dates = {}
    for version, path in catalogs:
        weaknesses, groupings, edges, _all_edges, memberships, meta = parse_catalog(path)
        dates[version] = meta["date"]
        for cid, rec in weaknesses.items():
            weak_records[cid][version] = rec
        for gid, rec in groupings.items():
            group_records[gid][version] = rec
        for edge in edges:
            edge_versions[edge].add(version)
        for link in memberships:
            member_versions[link].add(version)

    weak = newest_metadata(weak_records)
    groups = newest_metadata(group_records)
    valid_edges = {e for e in edge_versions if e[0] in weak and e[1] in weak}
    invalid = len(edge_versions) - len(valid_edges)
    edges, dropped = acyclic_union({e: edge_versions[e] for e in valid_edges})
    memberships = {m for m in member_versions if m[1] in weak or m[1] in groups}

    max_date = max((d for d in dates.values() if d), default="")
    merged_version = f"{versions[0]}-{versions[-1]}-merged"
    xml_path = os.path.join(data_dir, "merged", "cwec_merged.xml")
    os.makedirs(os.path.dirname(xml_path), exist_ok=True)
    write_merged_xml(xml_path, weak, groups, edges, memberships, merged_version, max_date)

    shutil.rmtree(out_dir, ignore_errors=True)
    subprocess.run([sys.executable, "-I", os.path.join(HERE, "build_cwe_dag.py"),
                    xml_path, out_dir], check=True)

    stats_path = os.path.join(out_dir, "cwe_stats.json")
    with open(stats_path, encoding="utf-8") as fh:
        stats = json.load(fh)
    stats["source"]["cwe_version"] = f"{versions[0]}-{versions[-1]} merged"
    stats["source"]["release_date"] = max_date
    stats["merge"] = {
        "source_versions": versions,
        "version_count": len(versions),
        "dropped_cyclic_edges": len(dropped),
        "dropped_invalid_edges": invalid,
    }
    with open(stats_path, "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2, ensure_ascii=False)

    shutil.copyfile(xml_path, os.path.join(out_dir, "cwec_merged.xml"))

    dag = stats["canonical_dag"]
    with open(os.path.join(out_dir, "MERGE.md"), "w", encoding="utf-8") as fh:
        fh.write(f"""# Merged CWE catalog ({versions[0]}–{versions[-1]})

Generated from {len(catalogs)} MITRE CWE catalogs. This is a single, uniform
catalog: every relationship from every version is included once, with no
per-version provenance and no historical-edge styling.

- {dag['nodes']} weaknesses and {stats['entries']['groupings']} groupings.
- {dag['edges']} View 1000 `ChildOf` relationships in the union.
- {len(memberships)} grouping membership relationships.
- Metadata (name, abstraction, status, description) comes from the newest
  catalog containing the entry.
- {dag['cycles']} cycles; {len(dropped)} edges were dropped to preserve
  acyclicity.

The merged catalog is `data/merged/cwec_merged.xml`; a copy is included as
`cwec_merged.xml` next to this file.
""")

    print(f"Merged {len(catalogs)} catalogs: {dag['nodes']} weaknesses, "
          f"{dag['edges']} ChildOf edges, {dag['cycles']} cycles", flush=True)
    print(f"XML: {os.path.relpath(xml_path, ROOT)}", flush=True)

    if not skip_render:
        cmd = [sys.executable, "-I", os.path.join(HERE, "render_graphs.py"), out_dir]
        if with_sfdp:
            cmd.append("--sfdp")
        subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()

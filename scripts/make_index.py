#!/usr/bin/env python3
"""Generate HTML index pages for the per-version CWE graph directories.

Usage:
    python -I make_index.py <out_root>

Writes <out_root>/index.html (all versions) and <out_root>/v<version>/index.html.
Run it after build_cwe_dag.py and render_graphs.py.
"""
import html
import json
import os
import sys

CSS = """
:root { --ink:#16232e; --muted:#66788a; --line:#d8e0e7; --bg:#f6f8fa; --accent:#0b3c5d; }
* { box-sizing:border-box; }
body { margin:0; font:15px/1.6 -apple-system,"Segoe UI",Helvetica,Arial,"Noto Sans SC",sans-serif; color:var(--ink); background:var(--bg); }
header { background:var(--accent); color:#fff; padding:32px; }
header h1 { margin:0 0 6px; font-size:26px; font-weight:600; }
header p { margin:0; color:#c9dbe8; max-width:920px; }
header a { color:#d9ecf7; }
main { max-width:1180px; margin:0 auto; padding:24px 24px 60px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); gap:12px; margin:0 0 26px; }
.tile { background:#fff; border:1px solid var(--line); border-radius:8px; padding:13px 15px; }
.tile b { display:block; font-size:25px; font-weight:600; color:var(--accent); line-height:1.2; }
.tile span { color:var(--muted); font-size:13px; }
section { margin-top:32px; }
h2 { font-size:18px; font-weight:600; margin:0 0 8px; padding-bottom:6px; border-bottom:1px solid var(--line); }
h2 small { font-weight:400; color:var(--muted); font-size:13px; margin-left:8px; }
p.note { color:var(--muted); font-size:13px; margin:8px 0 14px; }
figure { margin:0; background:#fff; border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; max-height:620px; }
figure img { display:block; max-width:none; height:auto; }
figcaption { color:var(--muted); font-size:13px; margin-top:8px; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(330px,1fr)); gap:16px; }
.card { background:#fff; border:1px solid var(--line); border-radius:8px; padding:14px; display:flex; flex-direction:column; }
.card h3 { margin:0 0 4px; font-size:15px; }
.card .meta { color:var(--muted); font-size:12px; margin-bottom:10px; }
.card .thumb { border:1px solid var(--line); border-radius:6px; overflow:hidden; max-height:220px; background:#fafcfd; }
.card .thumb img { width:100%; display:block; }
.card .links { margin-top:auto; padding-top:10px; font-size:13px; }
.tabs { display:flex; gap:8px; margin:0 0 10px; flex-wrap:wrap; }
.tab { border:1px solid var(--line); background:#fff; color:var(--ink); padding:6px 12px; border-radius:6px; cursor:pointer; font:inherit; font-size:13px; }
.tab.active { background:var(--accent); color:#fff; border-color:var(--accent); }
.tab:focus-visible { outline:2px solid #1d6fa5; outline-offset:2px; }
.viewer-note { color:var(--muted); font-size:13px; margin:8px 0 0; }
a { color:#1d6fa5; text-decoration:none; }
a:hover { text-decoration:underline; }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line); border-radius:8px; overflow:hidden; }
th,td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); font-size:13px; white-space:nowrap; }
th { background:#eef3f7; font-weight:600; }
tr:last-child td { border-bottom:0; }
code { background:#eef3f7; padding:1px 5px; border-radius:4px; font-size:13px; }
footer { color:var(--muted); font-size:12px; margin-top:38px; }
"""


def esc(value):
    return html.escape(str(value))


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def version_index(vdir):
    stats = load(os.path.join(vdir, "cwe_stats.json"))
    pillars = load(os.path.join(vdir, "pillars_index.json"))
    src = stats["source"]
    dag = stats["canonical_dag"]
    version = src["cwe_version"]
    group_word = "Categories" if src.get("group_element") == "Category" else "Groupings"
    has_layered = os.path.exists(os.path.join(vdir, "cwe-dag-full.svg"))
    has_sfdp = os.path.exists(os.path.join(vdir, "cwe-dag-full-sfdp.svg"))

    cards = []
    for p in pillars:
        slug = os.path.basename(p["file"])[:-4]
        cards.append(f"""
      <div class="card">
        <h3>CWE-{esc(p['id'])} {esc(p['name'])}</h3>
        <div class="meta">{p['nodes']} nodes · {p['edges']} edges · depth {p['depth']} · {p['external_parent_links']} cross-pillar links omitted</div>
        <div class="thumb"><a href="pillars/{slug}.svg"><img src="pillars/{slug}.svg" alt=""></a></div>
        <div class="links"><a href="pillars/{slug}.svg">SVG</a> · <a href="pillars/{slug}.dot">DOT</a></div>
      </div>""")

    if has_layered and has_sfdp:
        tabs = """
      <div class="tabs" role="tablist" aria-label="Complete DAG layout">
        <button type="button" class="tab active" role="tab" aria-selected="true" data-view="layered">Layered</button>
        <button type="button" class="tab" role="tab" aria-selected="false" data-view="force">Force-directed</button>
      </div>"""
        default_src, default_label = "cwe-dag-full.svg", "Layered complete DAG"
        viewer_js = """
<script>
(function () {
  var views = {
    layered: { src: "cwe-dag-full.svg", label: "Layered complete DAG" },
    force:   { src: "cwe-dag-full-sfdp.svg", label: "Force-directed overview" }
  };
  var img = document.getElementById("dag-img");
  var link = document.getElementById("dag-link");
  var cap = document.getElementById("dag-caption");
  var tabs = document.querySelectorAll(".tab");
  tabs.forEach(function (btn) {
    btn.addEventListener("click", function () {
      tabs.forEach(function (b) { b.classList.remove("active"); b.setAttribute("aria-selected", "false"); });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      var v = views[btn.dataset.view];
      img.src = v.src;
      link.href = v.src;
      cap.textContent = v.label + " — open the SVG for full resolution.";
    });
  });
})();
</script>"""
    else:
        tabs = ""
        viewer_js = ""
        if has_layered:
            default_src, default_label = "cwe-dag-full.svg", "Layered complete DAG"
        else:
            default_src, default_label = "cwe-dag-full-sfdp.svg", "Force-directed overview"

    full_graph = f"""
      {tabs}
      <figure>
        <a id="dag-link" href="{default_src}" target="_blank" rel="noopener"><img id="dag-img" src="{default_src}" alt="CWE complete DAG"></a>
        <figcaption id="dag-caption">{default_label} — open the SVG for full resolution.</figcaption>
      </figure>
      <p class="viewer-note">Also: <a href="cwe-dag-overview.svg">cwe-dag-overview.svg</a> (pillars + direct children).</p>
      {viewer_js}"""

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CWE {esc(version)} — Numbering Hierarchy as a DAG</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>CWE {esc(version)} — Numbering Hierarchy as a DAG</h1>
  <p>{src['file']} · released {esc(src['release_date'])} · View {esc(dag['view'])} "{esc(dag['view_name'])}".
  Edge direction is parent → child (<code>ChildOf</code>). <a href="../index.html">← All versions</a></p>
</header>
<main>
  <div class="tiles">
    <div class="tile"><b>{dag['nodes']}</b><span>Weaknesses</span></div>
    <div class="tile"><b>{dag['edges']}</b><span>ChildOf edges</span></div>
    <div class="tile"><b>{dag['cycles']}</b><span>Cycles (DAG)</span></div>
    <div class="tile"><b>{dag['roots']}</b><span>Roots</span></div>
    <div class="tile"><b>{dag['multi_parent_nodes']}</b><span>Multi-parent nodes</span></div>
    <div class="tile"><b>{dag['max_depth']}</b><span>Max depth</span></div>
    <div class="tile"><b>{stats['entries']['groupings']}</b><span>{group_word}</span></div>
  </div>

  <section>
    <h2>Complete DAG <small>{dag['nodes']} nodes / {dag['edges']} edges</small></h2>
    <p class="note">Switch between the layered hierarchy (direction preserved) and the force-directed overview (compact, direction not preserved). The layered graph is large; open the SVG directly to zoom.</p>
    {full_graph}
  </section>

  <section>
    <h2>Pillar subgraphs <small>induced sub-DAGs rooted at each pillar</small></h2>
    <p class="note">Shared nodes appear in several pillar subgraphs. Titles state how many cross-pillar parent links each subgraph omits; the complete graph has every edge.</p>
    <div class="grid">{''.join(cards)}
    </div>
  </section>

  <section>
    <h2>Other figures and data</h2>
    <p class="note">Deprecated/orphan entries: <a href="cwe-dag-deprecated.svg">cwe-dag-deprecated.svg</a> ·
    grouping containment: <a href="cwe-grouping-dag.svg">cwe-grouping-dag.svg</a> ·
    legend: <a href="cwe-legend.svg">cwe-legend.svg</a>.</p>
    <table>
      <tr><th>File</th><th>Contents</th></tr>
      <tr><td><a href="cwe_nodes.csv">cwe_nodes.csv</a></td><td>{stats['entries']['total']} entries with depth, parents, root and subtree size</td></tr>
      <tr><td><a href="cwe_edges.csv">cwe_edges.csv</a></td><td>{dag['edges']} canonical ChildOf edges (View {esc(dag['view'])})</td></tr>
      <tr><td><a href="cwe_edges_all_views.csv">cwe_edges_all_views.csv</a></td><td>{stats['all_childof_relations']} ChildOf relations across all views, with View_ID</td></tr>
      <tr><td><a href="cwe_grouping_members.csv">cwe_grouping_members.csv</a></td><td>{stats['groupings']['membership_edges']} grouping membership relations</td></tr>
      <tr><td><a href="cwe_stats.json">cwe_stats.json</a></td><td>All statistics</td></tr>
      <tr><td><a href="pillars_index.json">pillars_index.json</a></td><td>Pillar subgraph index</td></tr>
    </table>
  </section>

  <footer>Source: MITRE CWE {esc(version)} ({esc(src['release_date'])}) · rendered with Graphviz · scripts in <code>../../scripts/</code></footer>
</main>
</body>
</html>
"""
    with open(os.path.join(vdir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)


def root_index(out_root):
    rows = []
    versions = []
    for name in os.listdir(out_root):
        stats_path = os.path.join(out_root, name, "cwe_stats.json")
        if name.startswith("v") and os.path.exists(stats_path):
            versions.append((stats_path, name))
    def key(item):
        path, name = item
        parts = name[1:].split(".")
        return tuple(int(p) for p in parts)
    for stats_path, dirname in sorted(versions, key=key, reverse=True):
        s = load(stats_path)
        d = s["canonical_dag"]
        g = "Categories" if s["source"].get("group_element") == "Category" else "Groupings"
        rows.append(
            f"<tr><td><a href=\"{dirname}/index.html\">CWE {esc(s['source']['cwe_version'])}</a></td>"
            f"<td>{esc(s['source']['release_date'])}</td>"
            f"<td>{esc(d['view_name'])}</td>"
            f"<td>{d['nodes']}</td><td>{d['edges']}</td><td>{d['roots']}</td>"
            f"<td>{d['max_depth']}</td><td>{d['multi_parent_nodes']}</td>"
            f"<td>{s['entries']['groupings']} {g.lower()}</td>"
            f"<td><a href=\"{dirname}/cwe-dag-full.svg\">SVG</a></td></tr>")
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CWE Numbering Hierarchy as a DAG — all versions</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>CWE Numbering Hierarchy as a DAG</h1>
  <p>Every CWE 4.x catalog plus CWE 5.0, parsed from MITRE's official XML. Each version has its own directory with the complete DAG, per-pillar subgraphs and CSV data.</p>
</header>
<main>
  <section>
    <h2>Versions <small>latest first</small></h2>
    <table>
      <tr><th>Version</th><th>Released</th><th>View 1000 name</th><th>Weaknesses</th><th>ChildOf edges</th><th>Roots</th><th>Depth</th><th>Multi-parent</th><th>Grouping layer</th><th>Full DAG</th></tr>
      {''.join(rows)}
    </table>
  </section>
  <p class="note">CWE 4.x uses <code>&lt;Category&gt;</code>; CWE 5.0 renamed the same layer to <code>&lt;Grouping&gt;</code>. Source archives: <code>data/v&lt;version&gt;/</code>. Build with <code>python -I scripts/build_all.py</code>.</p>
  <footer>Data: MITRE CWE · rendered with Graphviz · see <code>README.md</code></footer>
</main>
</body>
</html>
"""
    with open(os.path.join(out_root, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out_root = os.path.abspath(sys.argv[1])
    for name in sorted(os.listdir(out_root)):
        vdir = os.path.join(out_root, name)
        if name.startswith("v") and os.path.exists(os.path.join(vdir, "cwe_stats.json")):
            version_index(vdir)
    root_index(out_root)


if __name__ == "__main__":
    main()

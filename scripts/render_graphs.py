#!/usr/bin/env python3
"""Render every .dot under <out_dir> with pygraphviz.

Usage:
    python -I render_graphs.py <out_dir> [--png-all] [--sfdp]

PyGraphviz 2.0+ wheels bundle the Graphviz libraries and layout plugins
(dot, neato, sfdp, fdp, ...), so no system Graphviz installation and no
external `dot`/`sfdp` executables are required. Install with:

    python -m pip install -r requirements.txt

SVG is produced for every graph. PNG is produced for the overview, the
per-pillar graphs and the smaller graphs (the layered complete graph is too
large for a useful PNG). Pass --png-all to force PNG for everything.

Pass --sfdp to additionally render a compact force-directed variant of the
complete DAG (slow: roughly 1-3 minutes per version).
"""
import os
import sys
import time

try:
    import pygraphviz as pgv
except ImportError:
    sys.exit("pygraphviz is required: python -m pip install -r requirements.txt")

SKIP_PNG = {"cwe-dag-full.dot"}


def check_sfdp():
    """Fail early if the bundled Graphviz has no sfdp layout engine."""
    graph = pgv.AGraph()
    graph.add_edge("a", "b")
    try:
        graph.layout(prog="sfdp")
    except Exception as exc:
        sys.exit("sfdp layout is not available in this pygraphviz build: "
                 f"{exc}\nReinstall pygraphviz from a binary wheel "
                 "(python -m pip install --force-reinstall -r requirements.txt).")


def draw_layered(dot, stem, png):
    graph = pgv.AGraph(dot)
    graph.layout(prog="dot")
    graph.draw(stem + ".svg", format="svg")
    if png:
        graph.graph_attr["dpi"] = "110"
        graph.draw(stem + ".png", format="png")


def draw_force_directed(dot, stem):
    """Render sfdp SVG/PNG, retrying without overlap removal.

    Some Graphviz builds lack GTS; `overlap=false` then fails while a plain
    sfdp layout still works. Each attempt starts from a fresh graph because
    layout mutates node positions.
    """
    attempts = [
        {"overlap": "false", "splines": "true"},
        {"splines": "true"},
        {},
    ]
    last_error = None
    for attrs in attempts:
        graph = pgv.AGraph(dot)
        for key, value in attrs.items():
            graph.graph_attr[key] = value
        try:
            graph.layout(prog="sfdp")
            graph.draw(stem + "-sfdp.svg", format="svg")
            graph.graph_attr["dpi"] = "96"
            graph.draw(stem + "-sfdp.png", format="png")
            return
        except Exception as exc:  # try the next overlap setting
            last_error = exc
    sys.exit(f"sfdp rendering failed for {dot}: {last_error}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out_dir = os.path.abspath(sys.argv[1])
    png_all = "--png-all" in sys.argv
    with_sfdp = "--sfdp" in sys.argv
    if with_sfdp:
        check_sfdp()

    dots = []
    for base, _dirs, files in os.walk(out_dir):
        for name in sorted(files):
            if name.endswith(".dot"):
                dots.append(os.path.join(base, name))

    for dot in dots:
        stem = dot[:-4]
        t0 = time.time()
        png = png_all or os.path.basename(dot) not in SKIP_PNG
        draw_layered(dot, stem, png)
        print(f"SVG  {os.path.relpath(stem + '.svg', out_dir)}  ({time.time() - t0:.1f}s)")
        if png:
            print(f"PNG  {os.path.relpath(stem + '.png', out_dir)}")

        if with_sfdp and os.path.basename(dot) == "cwe-dag-full.dot":
            t0 = time.time()
            draw_force_directed(dot, stem)
            print(f"SFDP {os.path.relpath(stem + '-sfdp.svg', out_dir)}  ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()

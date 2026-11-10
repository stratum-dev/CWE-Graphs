#!/usr/bin/env python3
"""Render every .dot under <out_dir> with Graphviz.

Usage:
    python -I render_graphs.py <out_dir> [--png-all] [--sfdp]

SVG is produced for every graph. PNG is produced for the overview, the
per-pillar graphs and the smaller graphs (the layered complete graph is too
large for a useful PNG). Pass --png-all to force PNG for everything.

Pass --sfdp to additionally render a compact force-directed variant of the
complete DAG (slow: roughly 1-2 minutes per version).
"""
import os
import subprocess
import sys
import time

SKIP_PNG = {"cwe-dag-full.dot"}


def check_sfdp():
    """Fail early with a useful message if the neato layout plugin is missing.

    `sfdp -V` only prints the version and does not load a layout engine, so
    the check has to render a tiny graph.
    """
    try:
        result = subprocess.run(
            ["sfdp", "-Tsvg", "-o", os.devnull],
            input=b"digraph { a -> b }",
            capture_output=True,
        )
    except FileNotFoundError:
        sys.exit("sfdp was not found. Install Graphviz with its layout plugins "
                 "(on Debian/Ubuntu: graphviz + libgvplugin-neato-layout*).")
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        sys.exit("sfdp is not usable; the Graphviz neato layout plugin is probably "
                 "missing (on Debian/Ubuntu: apt install libgvplugin-neato-layout*). "
                 "If `dot -P` lists only 'dot', run `sudo dot -c` to register the "
                 "layout plugins.\n" + detail)


def render_sfdp(dot, stem):
    """Render the force-directed SVG/PNG, retrying without overlap removal.

    Some Ubuntu builds compile Graphviz without GTS, so `-Goverlap=false`
    fails with "not built with triangulation library" while the plain sfdp
    layout still works. In that case fall back to no overlap removal.
    """
    attempts = [
        ["-Goverlap=false", "-Gsplines=true"],
        ["-Gsplines=true"],
        [],
    ]
    last_error = ""
    for extra in attempts:
        svg = subprocess.run(
            ["sfdp", "-Tsvg", *extra, "-o", stem + "-sfdp.svg", dot],
            capture_output=True, text=True)
        if svg.returncode:
            last_error = svg.stderr
            continue
        png = subprocess.run(
            ["sfdp", "-Tpng", "-Gdpi=96", *extra, "-o", stem + "-sfdp.png", dot],
            capture_output=True, text=True)
        if png.returncode:
            last_error = png.stderr
            continue
        return extra
    sys.exit("sfdp failed with every overlap setting:\n" + last_error.strip())


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
        for f in sorted(files):
            if f.endswith(".dot"):
                dots.append(os.path.join(base, f))
    for dot in dots:
        stem = dot[:-4]
        t0 = time.time()
        subprocess.run(["dot", "-Tsvg", "-o", stem + ".svg", dot], check=True)
        print(f"SVG  {os.path.relpath(stem + '.svg', out_dir)}  ({time.time() - t0:.1f}s)")
        if png_all or os.path.basename(dot) not in SKIP_PNG:
            t0 = time.time()
            subprocess.run(["dot", "-Tpng", "-Gdpi=110", "-o", stem + ".png", dot], check=True)
            print(f"PNG  {os.path.relpath(stem + '.png', out_dir)}  ({time.time() - t0:.1f}s)")
        if with_sfdp and os.path.basename(dot) == "cwe-dag-full.dot":
            # Compact force-directed variant: shows the overall shape of the
            # DAG in one poster-sized image (direction is not preserved).
            t0 = time.time()
            render_sfdp(dot, stem)
            print(f"SFDP {os.path.relpath(stem + '-sfdp.svg', out_dir)}  ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()

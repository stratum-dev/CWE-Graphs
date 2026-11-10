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


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out_dir = os.path.abspath(sys.argv[1])
    png_all = "--png-all" in sys.argv
    with_sfdp = "--sfdp" in sys.argv
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
            subprocess.run(["sfdp", "-Tsvg", "-Goverlap=false", "-Gsplines=true",
                            "-o", stem + "-sfdp.svg", dot], check=True)
            subprocess.run(["sfdp", "-Tpng", "-Gdpi=96", "-Goverlap=false", "-Gsplines=true",
                            "-o", stem + "-sfdp.png", dot], check=True)
            print(f"SFDP {os.path.relpath(stem + '-sfdp.svg', out_dir)}  ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()

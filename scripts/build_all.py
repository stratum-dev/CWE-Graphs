#!/usr/bin/env python3
"""Build and render every CWE catalog found under data/v<version>/.

Usage:
    python -I build_all.py [--only 4.0,4.21,5.0] [--offline] [--force-download]
                           [--skip-render] [--no-sfdp]

By default, missing catalogs are fetched from MITRE over the network before
building (see fetch_cwe.py). Pass --offline to use only local data, or
--force-download to refresh every selected catalog.

Each version is written to out/v<version>/. Existing output directories for
the selected versions are replaced. Afterwards out/index.html and one
index.html per version are generated.

Both complete-DAG layouts are produced by default: the layered `dot` graph
(cwe-dag-full.svg) and the force-directed `sfdp` poster
(cwe-dag-full-sfdp.svg/.png). Pass --no-sfdp to skip the slow sfdp pass.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)          # cwe-graphs/


def version_key(path):
    name = os.path.basename(path)     # v4.19
    return tuple(int(p) for p in name[1:].split("."))


def find_catalogs():
    data = os.path.join(ROOT, "data")
    if not os.path.isdir(data):
        return []
    found = []
    for name in os.listdir(data):
        if not name.startswith("v"):
            continue
        vdir = os.path.join(data, name)
        if not os.path.isdir(vdir):
            continue
        xml = [f for f in os.listdir(vdir) if f.endswith(".xml")]
        if xml:
            found.append((name, os.path.join(vdir, xml[0])))
    return sorted(found, key=lambda item: version_key(item[0]))


def main():
    args = sys.argv[1:]
    only = None
    if "--only" in args:
        only = set(args[args.index("--only") + 1].split(","))
    skip_render = "--skip-render" in args
    with_sfdp = "--no-sfdp" not in args
    offline = "--offline" in args
    force_download = "--force-download" in args

    if not offline:
        spec = ",".join(sorted(only, key=lambda v: tuple(int(p) for p in v.split(".")))) if only else "all"
        cmd = [sys.executable, "-I", os.path.join(HERE, "fetch_cwe.py"),
               "--versions", spec, "--quiet"]
        if force_download:
            cmd.append("--force")
        if subprocess.run(cmd).returncode:
            sys.exit("failed to fetch one or more catalogs; rerun, or use --offline")

    catalogs = find_catalogs()
    if only:
        catalogs = [c for c in catalogs if c[0][1:] in only]
    if not catalogs:
        hint = ("local catalogs (network disabled by --offline)" if offline
                else "catalogs")
        sys.exit(f"no {hint} found under data/v*/")

    out_root = os.path.join(ROOT, "out")
    os.makedirs(out_root, exist_ok=True)
    for dirname, xml_path in catalogs:
        out_dir = os.path.join(out_root, dirname)
        if os.path.isdir(out_dir):
            shutil.rmtree(out_dir)
        print(f"\n=== {dirname}  ({os.path.basename(xml_path)}) ===", flush=True)
        subprocess.run([sys.executable, "-I", os.path.join(HERE, "build_cwe_dag.py"),
                        xml_path, out_dir], check=True)
        if not skip_render:
            cmd = [sys.executable, "-I", os.path.join(HERE, "render_graphs.py"), out_dir]
            if with_sfdp:
                cmd.append("--sfdp")
            subprocess.run(cmd, check=True)

    subprocess.run([sys.executable, "-I", os.path.join(HERE, "make_index.py"), out_root],
                   check=True)
    print("\nDone: out/index.html")


if __name__ == "__main__":
    main()

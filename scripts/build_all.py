#!/usr/bin/env python3
"""Build and render every CWE catalog found under data/v<version>/.

Usage:
    python -I build_all.py [--only 4.0,4.21,5.0] [--jobs N] [--offline]
                           [--force-download] [--skip-render] [--no-sfdp]

By default, missing catalogs are fetched from MITRE over the network before
building (see fetch_cwe.py). Pass --offline to use only local data, or
--force-download to refresh every selected catalog.

Versions are built in parallel. --jobs defaults to min(4, CPU count); use
--jobs 1 for the old sequential behavior.

Each version is written to out/v<version>/. Existing output directories for
the selected versions are replaced. Afterwards out/index.html and one
index.html per version are generated.

Both complete-DAG layouts are produced by default: the layered `dot` graph
(cwe-dag-full.svg) and the force-directed `sfdp` poster
(cwe-dag-full-sfdp.svg/.png). Pass --no-sfdp to skip the slow sfdp pass.
"""
import concurrent.futures
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time

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


def build_one(dirname, xml_path, out_root, skip_render, with_sfdp):
    """Build and render one catalog. Returns (dirname, seconds, ok, log, stats)."""
    started = time.time()
    out_dir = os.path.join(out_root, dirname)
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)

    commands = [[sys.executable, "-I", os.path.join(HERE, "build_cwe_dag.py"),
                 xml_path, out_dir]]
    if not skip_render:
        cmd = [sys.executable, "-I", os.path.join(HERE, "render_graphs.py"), out_dir]
        if with_sfdp:
            cmd.append("--sfdp")
        commands.append(cmd)

    chunks = []
    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True)
        chunks.append(result.stdout)
        if result.returncode:
            chunks.append(result.stderr)
            return dirname, time.time() - started, False, "".join(chunks), None

    stats = None
    stats_path = os.path.join(out_dir, "cwe_stats.json")
    if os.path.exists(stats_path):
        with open(stats_path, encoding="utf-8") as fh:
            data = json.load(fh)
        stats = data.get("canonical_dag", {})
    return dirname, time.time() - started, True, "".join(chunks), stats


def main():
    args = sys.argv[1:]
    only = None
    if "--only" in args:
        only = set(args[args.index("--only") + 1].split(","))
    skip_render = "--skip-render" in args
    with_sfdp = "--no-sfdp" not in args
    offline = "--offline" in args
    force_download = "--force-download" in args

    jobs = min(4, os.cpu_count() or 1)
    if "--jobs" in args:
        try:
            jobs = max(1, int(args[args.index("--jobs") + 1]))
        except (IndexError, ValueError):
            sys.exit("--jobs expects a positive integer")

    if not skip_render and importlib.util.find_spec("pygraphviz") is None:
        sys.exit("pygraphviz is required for rendering: "
                 "python -m pip install -r requirements.txt")

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

    print(f"Building {len(catalogs)} catalog(s) with {min(jobs, len(catalogs))} job(s)",
          flush=True)
    for dirname, _xml in catalogs:
        print(f"  queued {dirname}", flush=True)

    failures = []
    workers = min(jobs, len(catalogs))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(build_one, dirname, xml_path, out_root, skip_render, with_sfdp): dirname
            for dirname, xml_path in catalogs
        }
        for future in concurrent.futures.as_completed(futures):
            dirname = futures[future]
            try:
                dirname, elapsed, ok, log, stats = future.result()
            except Exception as exc:  # filesystem errors, unexpected crashes
                print(f"[FAIL] {dirname}: {exc}", flush=True)
                failures.append(dirname)
                continue
            if ok:
                if stats:
                    print(f"[done] {dirname}  {stats.get('nodes')} nodes / "
                          f"{stats.get('edges')} edges / {stats.get('cycles')} cycles  "
                          f"({elapsed:.1f}s)", flush=True)
                else:
                    print(f"[done] {dirname}  ({elapsed:.1f}s)", flush=True)
            else:
                print(f"[FAIL] {dirname}  ({elapsed:.1f}s)", flush=True)
                print(log)
                failures.append(dirname)

    if failures:
        sys.exit(f"\n{len(failures)} version(s) failed: {', '.join(failures)}")

    subprocess.run([sys.executable, "-I", os.path.join(HERE, "make_index.py"), out_root],
                   check=True)
    print("\nDone: out/index.html")


if __name__ == "__main__":
    main()

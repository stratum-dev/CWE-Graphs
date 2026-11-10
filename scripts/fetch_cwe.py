#!/usr/bin/env python3
"""Download CWE catalog XML from MITRE over the network.

Usage:
    python -I fetch_cwe.py [--out DIR] [--versions SPEC] [--force] [--quiet]

SPEC:
    all            every known catalog: 4.0 ... 4.21, 5.0   (default)
    4.x            4.0 ... 4.21
    5.x            every known 5.x catalog (currently 5.0)
    4.0,4.21,5.0   explicit comma-separated list

Each catalog is downloaded from
    https://cwe.mitre.org/data/xml/cwec_v<version>.xml.zip
and stored as
    <out>/v<version>/cwec_v<version>.xml       (+ the zip, kept as a cache)

Existing XML files are skipped unless --force is given.
"""
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

BASE_URL = "https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip"
KNOWN_VERSIONS = [f"4.{i}" for i in range(0, 22)] + ["5.0"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def version_key(version):
    return tuple(int(p) for p in version.split("."))


def resolve_versions(spec):
    spec = (spec or "all").strip()
    if spec == "all":
        versions = list(KNOWN_VERSIONS)
    elif spec == "4.x":
        versions = [v for v in KNOWN_VERSIONS if v.startswith("4.")]
    elif spec == "5.x":
        versions = [v for v in KNOWN_VERSIONS if v.startswith("5.")]
    else:
        versions = []
        for item in spec.split(","):
            item = item.strip().lstrip("vV")
            if item:
                versions.append(item)
    return sorted(set(versions), key=version_key)


def existing_xml(out_dir, version):
    vdir = os.path.join(out_dir, f"v{version}")
    if not os.path.isdir(vdir):
        return None
    for name in sorted(os.listdir(vdir)):
        if name.endswith(".xml"):
            return os.path.join(vdir, name)
    return None


def download(url, dest, timeout=180):
    request = urllib.request.Request(url, headers={"User-Agent": "cwe-graphs/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        with open(dest, "wb") as fh:
            shutil.copyfileobj(response, fh)


def extract_catalog(zip_path, out_dir, requested_version):
    with zipfile.ZipFile(zip_path) as archive:
        members = [n for n in archive.namelist()
                   if n.lower().endswith(".xml") and not n.startswith("__MACOSX")]
        if len(members) != 1:
            raise ValueError(f"expected exactly one XML in {zip_path}, found {len(members)}")
        payload = archive.read(members[0])

    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError(f"downloaded file is not valid XML: {exc}")

    detected = root.get("Version") or requested_version
    if requested_version and detected != requested_version:
        raise ValueError(f"requested {requested_version}, but the archive contains CWE {detected}")

    vdir = os.path.join(out_dir, f"v{detected}")
    os.makedirs(vdir, exist_ok=True)
    xml_path = os.path.join(vdir, f"cwec_v{detected}.xml")
    tmp_path = xml_path + ".part"
    with open(tmp_path, "wb") as fh:
        fh.write(payload)
    os.replace(tmp_path, xml_path)

    zip_dest = os.path.join(vdir, f"cwec_v{detected}.xml.zip")
    if os.path.exists(zip_dest):
        os.remove(zip_dest)
    shutil.move(zip_path, zip_dest)
    return detected, xml_path


def fetch_one(out_dir, version, force=False, quiet=False):
    if not force:
        xml_path = existing_xml(out_dir, version)
        if xml_path:
            if not quiet:
                print(f"  CWE {version:>5}  skip (exists: {os.path.relpath(xml_path, ROOT)})")
            return None

    url = BASE_URL.format(version=version)
    vdir = os.path.join(out_dir, f"v{version}")
    os.makedirs(vdir, exist_ok=True)
    fd, tmp_zip = tempfile.mkstemp(prefix=f"cwec_v{version}_", suffix=".zip")
    os.close(fd)
    try:
        print(f"  CWE {version:>5}  downloading {url}", flush=True)
        download(url, tmp_zip)
        detected, xml_path = extract_catalog(tmp_zip, out_dir, version)
        size_mb = os.path.getsize(xml_path) / (1024 * 1024)
        print(f"  CWE {detected:>5}  saved {os.path.relpath(xml_path, ROOT)} ({size_mb:.1f} MB)")
        return xml_path
    finally:
        if os.path.exists(tmp_zip):
            os.remove(tmp_zip)


def main():
    args = sys.argv[1:]
    out_dir = os.path.join(ROOT, "data")
    if "--out" in args:
        out_dir = os.path.abspath(args[args.index("--out") + 1])
    spec = "all"
    if "--versions" in args:
        spec = args[args.index("--versions") + 1]
    force = "--force" in args
    quiet = "--quiet" in args

    versions = resolve_versions(spec)
    os.makedirs(out_dir, exist_ok=True)
    print(f"Fetching {len(versions)} CWE catalog(s) into {os.path.relpath(out_dir, ROOT)}"
          f"{' (force)' if force else ''}")

    failures = []
    saved = skipped = 0
    for version in versions:
        try:
            result = fetch_one(out_dir, version, force=force, quiet=quiet)
            if result:
                saved += 1
            else:
                skipped += 1
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            failures.append((version, f"network error: {exc}"))
        except (ValueError, zipfile.BadZipFile) as exc:
            failures.append((version, str(exc)))
        except Exception as exc:  # keep going; report at the end
            failures.append((version, f"{type(exc).__name__}: {exc}"))

    print(f"\nDone: {saved} downloaded, {skipped} skipped, {len(failures)} failed")
    for version, message in failures:
        print(f"  FAILED {version}: {message}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

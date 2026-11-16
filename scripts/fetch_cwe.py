#!/usr/bin/env python3
"""Download CWE catalog XML from MITRE over the network.

Usage:
    python -I fetch_cwe.py [--out DIR] [--versions SPEC] [--force] [--quiet] [--list]

--list prints the resolved version list as JSON and exits (used by CI).

SPEC:
    all            1.0 ... 5.0                              (default)
    1.x            1.0 ... 1.13
    2.x            2.0 ... 2.12
    3.x            3.0 ... 3.4
    4.x            4.0 ... 4.21
    5.x            every known 5.x catalog (currently 5.0)
    1.0,4.21,5.0   explicit comma-separated list

Each catalog is downloaded from
    https://cwe.mitre.org/data/xml/cwec_v<version>.xml.zip
and stored as
    <out>/v<version>/cwec_v<version>.xml       (+ the zip, kept as a cache)

Existing XML files are skipped unless --force is given.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

BASE_URL = "https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip"
KNOWN_VERSIONS = (
    [f"1.{i}" for i in range(0, 14)]
    + [f"2.{i}" for i in range(0, 13)]
    + [f"3.{i}" for i in range(0, 5)]
    + [f"4.{i}" for i in range(0, 22)]
    + ["5.0"]
)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def version_key(version):
    return tuple(int(p) for p in version.split("."))


def resolve_versions(spec):
    spec = (spec or "all").strip()
    if spec == "all":
        versions = list(KNOWN_VERSIONS)
    elif spec.endswith(".x") and spec[:-2].isdigit():
        prefix = spec[:-2] + "."
        versions = [v for v in KNOWN_VERSIONS if v.startswith(prefix)]
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


def parse_payload(payload):
    """Parse catalog XML, repairing undeclared namespace prefixes.

    CWE 2.11 uses <xhtml:div> without declaring xmlns:xhtml. The same repair
    is used by build_cwe_dag.py; doing it here lets the downloader accept the
    catalog instead of rejecting it before it reaches the tolerant builder.
    """
    try:
        return ET.fromstring(payload)
    except ET.ParseError:
        text = payload.decode("utf-8-sig", errors="replace")
        declared = set(re.findall(r"xmlns:([A-Za-z_][\w.-]*)\s*=", text))
        used = set(re.findall(r"<([A-Za-z_][\w.-]*):", text))
        missing = sorted(used - declared - {"xml", "xmlns"})
        if not missing:
            raise
        additions = "".join(f' xmlns:{prefix}="urn:cwe:undeclared:{prefix}"'
                            for prefix in missing)
        text = re.sub(r"(<Weakness_Catalog\b)", r"\1" + additions, text, count=1)
        return ET.fromstring(text)


def extract_catalog(zip_path, out_dir, requested_version):
    with zipfile.ZipFile(zip_path) as archive:
        members = [n for n in archive.namelist()
                   if n.lower().endswith(".xml") and not n.startswith("__MACOSX")]
        if len(members) != 1:
            raise ValueError(f"expected exactly one XML in {zip_path}, found {len(members)}")
        payload = archive.read(members[0])

    try:
        root = parse_payload(payload)
    except ET.ParseError as exc:
        raise ValueError(f"downloaded file is not valid XML: {exc}")

    detected = root.get("Version") or root.get("Catalog_Version") or requested_version
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
    if "--list" in args:
        print(json.dumps(versions))
        return 0

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

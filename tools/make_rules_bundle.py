#!/usr/bin/env python3
"""Build a DocScan Android rules update: one ZIP with the rule files in sub-folders and manifest.json.

  make_rules_bundle.py --version 2026.11.17-1 \\
      --critical /path/to/yara_sender_critical_rules.yar \\
      [--detection-dir yara-docscan/docscan-project/rules --detection-index docscan-index.yar] \\
      [--chunk 700,120] [--description "..."] -o docscan-rules-2026.11.17-1.zip

--critical (repeatable): rule files for pass 3 (critical information) -> critical/<name>
--detection-dir + --detection-index: a whole detection rule tree (with its includes) -> detection/...,
    replaces the docscan rules built into the app
Every file gets its sha256 in manifest.json ("files"); the app refuses an archive that does not match.
In the app: Захист -> Правила -> "З файлу" (this ZIP) or "За URL" (where it is published; checked daily).
"""
import argparse
import hashlib
import json
import os
import sys
import zipfile


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", required=True)
    ap.add_argument("--description", default="")
    ap.add_argument("--critical", action="append", default=[], help="critical-information rule file (repeatable)")
    ap.add_argument("--detection-dir", help="detection rules folder (its include tree goes in as it is)")
    ap.add_argument("--detection-index", help="the index file inside --detection-dir")
    ap.add_argument("--chunk", help="default chunking for pass 3: SIZE,OVERLAP (size 200..1500, overlap 0..size/2)")
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    if not a.critical and not a.detection_dir:
        sys.exit("nothing to pack: give --critical and/or --detection-dir")
    if bool(a.detection_dir) != bool(a.detection_index):
        sys.exit("--detection-dir and --detection-index go together")

    entries = []                       # (archive name, source path)
    manifest = {"bundle": "docscan-rules", "version": a.version}
    if a.description:
        manifest["description"] = a.description
    if a.critical:
        names = []
        for c in a.critical:
            n = "critical/" + os.path.basename(c)
            if n in names:
                sys.exit("two critical files named " + os.path.basename(c))
            names.append(n)
            entries.append((n, c))
        manifest["critical_information"] = names[0] if len(names) == 1 else names
    if a.detection_dir:
        for root, dirs, files in os.walk(a.detection_dir):
            dirs[:] = [d for d in dirs if d != "tools" and not d.startswith(".")]
            for f in files:
                if f.endswith((".yar", ".yara")):
                    src = os.path.join(root, f)
                    rel = os.path.relpath(src, a.detection_dir).replace(os.sep, "/")
                    entries.append(("detection/" + rel, src))
        idx = "detection/" + a.detection_index.replace(os.sep, "/")
        if idx not in [e[0] for e in entries]:
            sys.exit("the index is not in --detection-dir: " + a.detection_index)
        manifest["detection"] = idx
    if a.chunk:
        size, overlap = (int(x) for x in a.chunk.split(","))
        if not (200 <= size <= 1500 and 0 <= overlap <= size // 2):
            sys.exit("--chunk: size 200..1500, overlap 0..size/2")
        manifest["critical_chunk"] = {"size": size, "overlap": overlap}
    manifest["files"] = {n: sha256(p) for n, p in entries}

    with zipfile.ZipFile(a.output, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        for n, p in entries:
            z.write(p, n)
    print("%s: %d rule files, version %s" % (a.output, len(entries), a.version))


if __name__ == "__main__":
    main()

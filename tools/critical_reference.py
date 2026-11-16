#!/usr/bin/env python3
"""Reference results of pass 3 (critical information) from the PC yara, for CriticalCorpusTest.

Runs the yara-docscan CLI (`yara --critical-rules`) over a folder of documents and writes one TSV row
per file: status (queued / nomatch / skipped), matched rules, fragment count, total chars and a hash
of the fragments (sha256 of "start:end:text\\n" per fragment, first 16 hex). The Android test computes
the same values from the queue line the app produced and compares them file by file.

usage: critical_reference.py <yara> <critical-rules.yar> <docs_dir> <out.tsv>
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile


def fragments_hash(fragments):
    h = hashlib.sha256()
    for f in fragments:
        h.update(("%d:%d:%s\n" % (f["start"], f["end"], f["text"])).encode("utf-8"))
    return h.hexdigest()[:16]


def main():
    yara, rules, docs, out = sys.argv[1:5]
    work = tempfile.mkdtemp()
    never = os.path.join(work, "never.yar")
    with open(never, "w") as fh:
        fh.write("rule never { condition: false }\n")
    rows = []
    for fn in sorted(os.listdir(docs)):
        q = os.path.join(work, "q.json")
        if os.path.exists(q):
            os.remove(q)
        p = subprocess.run([yara, "--critical-rules=" + rules, "--critical-out=" + q, never, os.path.join(docs, fn)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        objs = []
        if os.path.exists(q):
            objs = [json.loads(l) for l in open(q, encoding="utf-8").read().split("\n") if l]
        if objs:
            o = objs[0]
            rows.append([fn, "queued", ",".join(o["metadata"]["yara_matches"]), str(o["text_info"]["fragment_count"]),
                         str(o["text_info"]["total_chars"]), fragments_hash(o["fragments"])])
        else:
            rows.append([fn, "skipped" if "skipped" in p.stderr else "nomatch", "", "", "", ""])
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# file\tstatus\trules\tfragments\ttotal_chars\tfragments_hash\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")


if __name__ == "__main__":
    main()

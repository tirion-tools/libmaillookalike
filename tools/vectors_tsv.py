#!/usr/bin/env python3
"""Converts the reference engine's JSONL output (urls.jsonl, links.jsonl) into the TSV vectors the tests read.

Fields are escaped: backslash as \\\\, tab as \\t, LF as \\n, CR as \\r; list elements are joined by the two characters
\\| (a backslash and a bar). Usage: vectors_tsv.py <in-dir> <out-dir>"""
import json
import os
import sys


def esc(s):
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def lst(xs):
    return "\\|".join(esc(x) for x in xs)


def b(v):
    return "1" if v else "0"


src, dst = sys.argv[1], sys.argv[2]
with open(os.path.join(dst, "urls.tsv"), "w", encoding="utf-8") as out:
    out.write("# raw\tok\tscheme\thost\tpath\tquery\tcanonical\tmailto_domain\tflags\tparams (key\\|value\\|...)\n")
    for line in open(os.path.join(src, "urls.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        if not r["ok"]:
            out.write(f"{esc(r['raw'])}\t0\t\t\t\t\t\t\t0\t\n")
            continue
        params = [x for kv in (r["params"] or []) for x in kv]
        out.write("\t".join([esc(r["raw"]), "1", esc(r["scheme"]), esc(r["host"]), esc(r["path"]), esc(r["query"]),
                             esc(r["canonical"]), esc(r["mailto_domain"]), str(r["flags"]), lst(params)]) + "\n")
with open(os.path.join(dst, "links.tsv"), "w", encoding="utf-8") as out:
    out.write("# href\ttexts\tsource\treg\tinner_reg\tflags\ttext_domain\ttext_mismatch\tredirector\tesp\tshortener"
              "\tuser_content\tdevice\toauth (provider\\|client_id\\|scope, or empty)\n")
    for line in open(os.path.join(src, "links.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        out.write("\t".join([esc(r["href"]), lst(r["texts"]), str(r["source"]), esc(r["reg"]), esc(r["inner_reg"]),
                             str(r["flags"]), esc(r["text_domain"]), b(r["text_mismatch"]), b(r["redirector"]),
                             esc(r["esp"]), b(r["shortener"]), b(r["user_content"]), b(r["device"]),
                             lst(r["oauth"]) if r["oauth"] else ""]) + "\n")

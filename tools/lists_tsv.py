#!/usr/bin/env python3
"""Turns a mail client's link-list JSON (redirectors, generic_redirect_params, esp_trackers, shorteners,
user_content_hosts, oauth_endpoints, device_login) into tests/data/lists.tsv, the fixture the tests load.

Rows: `rule<TAB>section<TAB>kind<TAB>host_re<TAB>path_re<TAB>params,comma,separated<TAB>decode` or
`item<TAB>section<TAB>value`."""
import json
import sys

d = json.load(open(sys.argv[1], encoding="utf-8"))
out = []
for sec, key in (("redirectors", "kind"), ("oauth_endpoints", "provider"), ("device_login", "provider")):
    for r in d[sec]:
        out.append("\t".join(["rule", sec, r[key], r["host_re"], r["path_re"], ",".join(r.get("params", [])), r.get("decode", "")]))
for sec in ("generic_redirect_params", "esp_trackers", "shorteners", "user_content_hosts"):
    for v in d[sec]:
        out.append("\t".join(["item", sec, v]))
sys.stdout.write("".join(l + "\n" for l in out))

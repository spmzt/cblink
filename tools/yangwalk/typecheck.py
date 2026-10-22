#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The types of a walk (yangwalk, or cblink-gen -d) against yanglint -f
# info, which prints the compiled schema: for every leaf and leaf-list of
# every module of a directory compiled together, the same base type,
# range or length, number of patterns, enumeration values or bit
# positions, fraction digits, units and defaults, module by module (the
# module whose tree the node is in), as many times.  Union members and a
# leafref's target type are not compared here; treecheck.sh does the
# nodes.
#
#	typecheck.py walker dir

import collections
import glob
import os
import re
import subprocess
import sys

BASES = {"binary", "bits", "boolean", "decimal64", "empty", "enumeration",
         "identityref", "instance-identifier", "int8", "int16", "int32",
         "int64", "leafref", "string", "uint8", "uint16", "uint32", "uint64",
         "union"}


def info_rows(text):
    """(module, row) for every leaf and leaf-list in yanglint -f info."""
    rows = []
    mod = None
    stack = []          # (kind, name, depth) of open blocks
    leaf = None         # the leaf being read: dict
    depth = 0
    instr = False
    skip = 0            # depth of an extension instance being skipped
    for line in text.split("\n"):
        # Braces count outside quoted text, which may span lines.
        began_in_string = instr
        opens = closes = 0
        esc = False
        for ch in line:
            if instr:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    instr = False
            elif ch == '"':
                instr = True
            elif ch == "{":
                opens += 1
            elif ch == "}":
                closes += 1
        s = line.strip()
        m = re.match(r'^module (\S+) \{$', line)
        if m:
            # Each module starts at column 0: begin it afresh.
            if leaf is not None:
                rows.append((mod, row_of(leaf)))
            mod, depth, leaf, instr, skip = m.group(1), 1, None, False, 0
            continue
        if began_in_string:
            depth += opens - closes
            if leaf is not None and depth < leaf["depth"]:
                rows.append((mod, row_of(leaf)))
                leaf = None
            continue
        opens = s.endswith("{")
        if skip == 0 and re.match(r'^[a-z0-9-]+:[a-z-]+ "[^"]*" \{$', s):
            skip = depth + 1
        if skip == 0 and leaf is None:
            m = re.match(r'^(leaf|leaf-list) (\S+) \{$', s)
            if m:
                leaf = {"kind": m.group(1), "name": m.group(2), "base": None,
                        "range": "", "npat": 0, "items": [], "fd": "",
                        "units": None, "dflt": [], "depth": depth + 1,
                        "tdepth": None}
        elif skip == 0 and leaf is not None:
            d = depth
            if leaf["base"] is None and d == leaf["depth"]:
                m = re.match(r'^type (\S+?)( \{|;)$', s)
                if m:
                    leaf["base"] = m.group(1)
                    if m.group(2) == " {":
                        leaf["tdepth"] = d + 1
            elif leaf["tdepth"] is not None and d == leaf["tdepth"]:
                m = re.match(r'^(range|length) "(.*)";$', s)
                if m and not leaf["range"]:
                    leaf["range"] = m.group(2).replace(" ", "")
                if s.startswith("pattern "):
                    leaf["npat"] += 1
                m = re.match(r'^fraction-digits (\d+);$', s)
                if m:
                    leaf["fd"] = m.group(1)
                m = re.match(r'^(enum|bit) "?([^" ]+)"? \{$', s) or \
                    re.match(r'^(enum|bit) "?([^" ]+)"?;$', s)
                if m:
                    leaf["items"].append([m.group(2), None])
            elif leaf["tdepth"] is not None and d == leaf["tdepth"] + 1 and \
                    leaf["items"]:
                m = re.match(r'^(value|position) (-?\d+);$', s)
                if m and leaf["items"][-1][1] is None:
                    leaf["items"][-1][1] = m.group(2)
            if d == leaf["depth"]:
                m = re.match(r'^units "(.*)";$', s)
                if m:
                    leaf["units"] = m.group(1)
                m = re.match(r'^default "(.*)";$', s)
                if m:
                    leaf["dflt"].append(m.group(1))
        depth += opens - closes
        if skip and depth < skip:
            skip = 0
        if leaf is not None and depth < leaf["depth"]:
            rows.append((mod, row_of(leaf)))
            leaf = None
    return rows


def row_of(l):
    items = " ".join("%s=%s" % (n, v) for n, v in l["items"])
    return (l["kind"], l["name"], l["base"], l["range"], l["npat"], items,
            l["fd"], l["units"] or "", " ".join(l["dflt"]))


def walk_rows(text):
    rows = []
    for line in text.split("\n"):
        f = line.split(" ")
        if len(f) < 4 or f[1] not in ("leaf", "leaf-list") or \
                not f[2].startswith("/"):
            continue
        mod = f[2][1:].split(":", 1)[0]
        name = f[2].rsplit("/", 1)[1].split(":")[-1]
        rest = line.split(" ", 3)[3]
        # The type: the first word naming a base, then its own part up to
        # units, default, when or must.
        m = re.search(r'(?:^| )(%s)(\([^)]*\))?' %
                      "|".join(sorted(BASES, key=len, reverse=True)), rest)
        base = m.group(1)
        t = rest[m.end():]
        cut = re.search(r' (units|default|when|must) "', t)
        tail = t[cut.start():] if cut else ""
        t = t[:cut.start()] if cut else t
        rng = ""
        if base not in ("union", "leafref"):
            r = re.search(r' (range|length) (\S+)', t)
            rng = r.group(2) if r else ""
            # The walk writes min..max for every part; yanglint writes a
            # single value once.
            rng = "|".join(p.split("..")[0] if p.split("..")[0] ==
                           p.split("..")[-1] else p for p in rng.split("|")) \
                if rng else ""
        npat = len(re.findall(r" pattern(\(invert\))? '", t)) \
            if base == "string" else 0
        items = ""
        if base in ("enumeration", "bits"):
            body = re.search(r' \{([^}]*)\}', t).group(1)
            items = " ".join(x.replace("@", "=") for x in body.split(" ")
                             if x)
        fd = re.search(r' fraction-digits (\d+)', t)
        units = re.search(r' units "([^"]*)"', tail)
        dflts = re.findall(r' default "([^"]*)"', tail)
        rows.append((mod, (f[1], name, base, rng, npat, items,
                           fd.group(1) if fd and base == "decimal64" else "",
                           units.group(1) if units else "",
                           " ".join(dflts))))
    return rows


def main():
    walker, d = sys.argv[1], sys.argv[2]
    mods = sorted(f for f in glob.glob(os.path.join(d, "*.yang"))
                  if open(f).readline().startswith("module "))
    names = [os.path.basename(f) for f in mods]
    walk = subprocess.run([walker, "-p", "."] + names, cwd=d,
                          capture_output=True, text=True, check=True).stdout
    info = subprocess.run(["yanglint", "-i", "-p", ".", "-f", "info"] +
                          names, cwd=d, capture_output=True, text=True,
                          check=True).stdout
    a = collections.defaultdict(collections.Counter)
    b = collections.defaultdict(collections.Counter)
    for mod, row in walk_rows(walk):
        a[mod][row] += 1
    for mod, row in info_rows(info):
        b[mod][row] += 1
    fail = 0
    n = 0
    for mod in sorted(set(a) | set(b)):
        if a[mod] != b[mod]:
            fail = 1
            print("%s: %d leaves walked, %d in yanglint -f info" %
                  (mod, sum(a[mod].values()), sum(b[mod].values())))
            for r in list((a[mod] - b[mod]).elements())[:3]:
                print("  walk only:", r)
            for r in list((b[mod] - a[mod]).elements())[:3]:
                print("  info only:", r)
        n += sum(a[mod].values())
    if not fail:
        print("%d leaves and leaf-lists: their types agree with yanglint's "
              "compiled schema" % n)
    sys.exit(fail)


if __name__ == "__main__":
    main()

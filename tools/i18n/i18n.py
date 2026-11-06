#!/usr/bin/env python3
"""Moves Chinese string literals of a Kotlin UI file into Compose Multiplatform string resources.

  extract FILE            lists the literals with Chinese text: index, line, text with %n$s placeholders, arguments
  apply FILE TRANSLATIONS replaces the listed literals by stringResource(Res.string.key, args) and adds the strings to
                          composeResources/values (English) and values-zh (Traditional Chinese)
  check [FILES...]        counts Chinese literals per file (the i18n check of docs/design/i18n.md)

TRANSLATIONS is a UTF-8 text file with one line per literal to move: "index<TAB>key<TAB>English". A key that already
exists with the same Chinese text is reused. A key written as @key puts the resource itself (Res.string.key) in place of
the literal, for code outside composition. Lines starting with # are ignored; literals not listed stay in place.
"""
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "app/src/commonMain/composeResources"
HAN = re.compile(r"[\u3400-\u9fff\uff00-\uffef\u3000-\u303f]")


def literals(src):
    """(start, end, body) of every ordinary string literal outside comments."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if src.startswith('"""', i):
            j = src.find('"""', i + 3)
            i = n if j < 0 else j + 3
            continue
        if c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            continue
        if c == '"':
            j, depth = i + 1, 0
            while j < n:
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if src.startswith("${", j):
                    depth, j = 1, j + 2
                    while j < n and depth:
                        if src[j] == "{":
                            depth += 1
                        elif src[j] == "}":
                            depth -= 1
                        elif src[j] == '"':
                            k = j + 1
                            while k < n and src[k] != '"':
                                k += 2 if src[k] == "\\" else 1
                            j = k
                        j += 1
                    continue
                if ch == '"':
                    break
                j += 1
            out.append((i, j + 1, src[i + 1:j]))
            i = j + 1
            continue
        i += 1
    return out


def template(body):
    """Text with %n$s placeholders and the argument expressions of a literal body."""
    text, args, i, n = [], [], 0, len(body)
    while i < n:
        if body.startswith("${", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += {"{": 1, "}": -1}.get(body[j], 0)
                j += 1
            args.append(body[i + 2:j - 1].strip())
            text.append("%%%d$s" % len(args))
            i = j
            continue
        m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)", body[i:])
        if m:
            args.append(m.group(1))
            text.append("%%%d$s" % len(args))
            i += m.end()
            continue
        if body[i] == "\\" and i + 1 < n:
            text.append({"n": "\n", "t": "\t", '"': '"', "'": "'", "\\": "\\", "$": "$"}.get(body[i + 1], body[i:i + 2]))
            i += 2
            continue
        text.append(body[i])
        i += 1
    return "".join(text), args


def chinese(path):
    src = Path(path).read_text(encoding="utf-8")
    return src, [(s, e, b) for s, e, b in literals(src) if HAN.search(b)]


def line_of(src, pos):
    return src.count("\n", 0, pos) + 1


def cmd_extract(path):
    src, found = chinese(path)
    for idx, (s, e, b) in enumerate(found):
        text, args = template(b)
        print(json.dumps({"i": idx, "line": line_of(src, s), "zh": text, "args": args}, ensure_ascii=False))


def read_strings(f):
    if not f.exists():
        return {}
    out = {}
    for m in re.finditer(r'<string name="([^"]+)">(.*?)</string>', f.read_text(encoding="utf-8"), re.S):
        out[m.group(1)] = unescape(m.group(2))
    return out


def escape(text):
    t = html.escape(text, quote=False).replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace('"', '\\"')
    return t


def unescape(text):
    t = text.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
    return html.unescape(t)


def write_strings(f, strings):
    f.parent.mkdir(parents=True, exist_ok=True)
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<resources>"]
    for k in sorted(strings):
        lines.append('    <string name="%s">%s</string>' % (k, escape(strings[k])))
    lines.append("</resources>")
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_apply(path, translations):
    src, found = chinese(path)
    en = read_strings(RES / "values/strings.xml")
    zh = read_strings(RES / "values-zh/strings.xml")
    plan = {}
    for raw in Path(translations).read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        idx, key, english = raw.split("\t", 2)
        idx = int(idx)
        bare = key.startswith("@")
        key = key.lstrip("@")
        text, args = template(found[idx][2])
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            sys.exit("bad key %s" % key)
        if key in zh and zh[key] != text:
            sys.exit("key %s already holds other Chinese text: %s" % (key, zh[key]))
        if HAN.search(english):
            sys.exit("English text of %s has Chinese characters" % key)
        for n in range(1, len(args) + 1):
            if ("%%%d$s" % n) not in english and ("%%%d$d" % n) not in english:
                sys.exit("English text of %s lacks %%%d$s" % (key, n))
        english = english.replace("\\n", "\n")
        en[key], zh[key] = english, text
        if bare and args:
            sys.exit("@%s cannot take arguments" % key)
        call = ("Res.string.%s" % key) if bare else "stringResource(Res.string.%s%s)" % (key, "".join(", " + a for a in args))
        plan[idx] = call
    out, last = [], 0
    for idx, (s, e, b) in enumerate(found):
        if idx in plan:
            out.append(src[last:s])
            out.append(plan[idx])
            last = e
    out.append(src[last:])
    new = "".join(out)
    imports = ["import diw.wallet.app.res.Res", "import diw.wallet.app.res.*"]
    if any(c.startswith("stringResource(") for c in plan.values()):
        imports.insert(0, "import org.jetbrains.compose.resources.stringResource")
    for imp in imports:
        if imp not in new and plan:
            m = re.search(r"^import .*$", new, re.M)
            new = new[:m.start()] + imp + "\n" + new[m.start():]
    Path(path).write_text(new, encoding="utf-8")
    write_strings(RES / "values/strings.xml", en)
    write_strings(RES / "values-zh/strings.xml", zh)
    print("moved %d of %d literals" % (len(plan), len(found)))


def cmd_check(paths):
    total = 0
    for p in paths:
        _, found = chinese(p)
        if found:
            print("%5d %s" % (len(found), p))
        total += len(found)
    print("%5d total" % total)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["extract"]:
        cmd_extract(a[1])
    elif a[:1] == ["apply"]:
        cmd_apply(a[1], a[2])
    elif a[:1] == ["check"]:
        cmd_check(a[1:])
    else:
        sys.exit(__doc__)

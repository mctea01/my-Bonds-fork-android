#!/usr/bin/env python3
"""Moves Chinese string literals of a Kotlin UI file into Compose Multiplatform string resources.

  extract FILE            lists the literals with Chinese text: index, line, text with %n$s placeholders, arguments
  apply FILE TRANSLATIONS [--tr]
                          replaces the listed literals by stringResource(Res.string.key, args) and adds the strings to
                          composeResources/values (English) and values-zh (Traditional Chinese); with --tr the literal
                          becomes tr(Res.string.key, args), for model code outside composition
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


def skip_char(src, i):
    """Index after the char literal starting at i."""
    j = i + 1
    while j < len(src) and src[j] != "'":
        j += 2 if src[j] == "\\" else 1
    return j + 1


def skip_expr(src, i):
    """Index after the template expression whose body starts at i (just after the opening brace)."""
    depth, n = 1, len(src)
    while i < n and depth:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == "'":
            i = skip_char(src, i)
            continue
        elif c == '"':
            i = skip_string(src, i)
            continue
        i += 1
    return i


def skip_string(src, i):
    """Index after the ordinary or raw string literal starting at i."""
    n = len(src)
    if src.startswith('"""', i):
        j = i + 3
        while j < n and not src.startswith('"""', j):
            j = skip_expr(src, j + 2) if src.startswith("${", j) else j + 1
        return j + 3
    j = i + 1
    while j < n:
        if src[j] == "\\":
            j += 2
        elif src.startswith("${", j):
            j = skip_expr(src, j + 2)
        elif src[j] == '"':
            return j + 1
        else:
            j += 1
    return n


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
            i = skip_string(src, i)
            continue
        if c == "'":
            i = skip_char(src, i)
            continue
        if c == '"':
            j = skip_string(src, i)
            out.append((i, j, src[i + 1:j - 1]))
            i = j
            continue
        i += 1
    return out


def template(body):
    """Text with %n$s placeholders and the argument expressions of a literal body."""
    text, args, i, n = [], [], 0, len(body)
    while i < n:
        if body.startswith("${", i):
            j = skip_expr(body, i + 2)
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


def cmd_apply(path, translations, model=False):
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
        fn = "tr" if model else "stringResource"
        call = ("Res.string.%s" % key) if bare else "%s(Res.string.%s%s)" % (fn, key, "".join(", " + a for a in args))
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
    package = re.search(r"^package (\S+)", new, re.M)
    if any(c.startswith("tr(") for c in plan.values()) and not (package and package.group(1) == "diw.wallet.app"):
        imports.insert(0, "import diw.wallet.app.tr")
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
        cmd_apply(a[1], a[2], "--tr" in a[3:])
    elif a[:1] == ["check"]:
        cmd_check(a[1:])
    else:
        sys.exit(__doc__)

#!/usr/bin/env python3
"""Moves Chinese string literals of a Kotlin UI file into Compose Multiplatform string resources.

  extract FILE            lists the literals with Chinese text: index, line, text with %n$s placeholders, arguments
  apply FILE TRANSLATIONS [--tr|--core]
                          replaces the listed literals by stringResource(Res.string.key, args) and adds the strings to
                          composeResources/values (English) and values-zh (Traditional Chinese); with --tr the literal
                          becomes tr(Res.string.key, args), for model code outside composition; with --core (files of
                          the core module) it becomes ct("core_key", args) and core/.../i18n/CoreStrings.kt, the Chinese
                          text core uses without the app, is written again
  check [FILES...]        counts Chinese literals per file (the i18n check of docs/design/i18n.md)

TRANSLATIONS is a UTF-8 text file with one line per literal to move: "index<TAB>key<TAB>English". A key that already
exists with the same Chinese text is reused. A key written as @key puts the resource itself (Res.string.key) in place of
the literal, for code outside composition. Lines starting with # are ignored; literals not listed stay in place.
apply also fills values-zh-rCN (Simplified Chinese) with the new keys, see hans.

Translation files (docs/guides/translation.md):
  status                  lists every translation file with its language, how many strings it translates and its
                          errors (keys the default file lacks, placeholders that differ); exits 1 on errors
  new QUALIFIER [NAME]    starts values-QUALIFIER/strings.xml (for example ja, pt-rBR, b+sr+Latn) with its language
                          tag and NAME, the language's name in itself; strings it lacks are shown in English
  missing QUALIFIER [OUT] writes the strings values-QUALIFIER lacks as UTF-8 TSV (key, English, Traditional Chinese,
                          empty translation column) to OUT or the standard output
  import QUALIFIER TSV    adds the filled translation column of such a TSV to values-QUALIFIER/strings.xml
  hans [KEY...]           writes the Simplified Chinese strings (values-zh-rCN) missing there from Traditional Chinese
                          with OpenCC (pip install opencc) and drops keys the default file no longer has; listed KEYs
                          are converted again even when present
"""
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "app/src/commonMain/composeResources"
CORE_STRINGS = ROOT / "core/src/commonMain/kotlin/diw/wallet/core/i18n/CoreStrings.kt"
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
    for m in re.finditer(r'<string name="([^"]+)"[^>]*>(.*?)</string>', f.read_text(encoding="utf-8"), re.S):
        out[m.group(1)] = unescape(m.group(2))
    return out


def string_meta(f):
    """Key -> (comment lines just before it, attributes) of the strings in f, kept when the file is written again."""
    meta, pending = {}, []
    if not f.exists():
        return meta
    for line in f.read_text(encoding="utf-8").splitlines():
        t = line.strip()
        m = re.match(r'<string name="([^"]+)"([^>]*)>', t)
        if t.startswith("<!--"):
            pending.append(t)
        elif m:
            meta[m.group(1)], pending = (pending, m.group(2)), []
        elif t:
            pending = []
    return meta


def escape(text):
    t = html.escape(text, quote=False).replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace('"', '\\"')
    return t


def unescape(text):
    t = text.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
    return html.unescape(t)


def write_strings(f, strings, meta=None):
    """Writes strings in the order of the file before, then of the default file, then of their keys (new keys);
    comments and attributes (translatable) of the file before, or else of meta, stay."""
    meta = {**(meta or {}), **string_meta(f)}
    order = {}
    for k in list(string_meta(f)) + list(string_meta(RES / "values/strings.xml")) + sorted(strings):
        order.setdefault(k, len(order))
    f.parent.mkdir(parents=True, exist_ok=True)
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<resources>"]
    for k in sorted(strings, key=order.get):
        comments, attrs = meta.get(k, ([], ""))
        lines += ["    " + c for c in comments]
        lines.append('    <string name="%s"%s>%s</string>' % (k, attrs, escape(strings[k])))
    lines.append("</resources>")
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")


def kotlin_string(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t").replace("$", "\\$") + '"'


def write_core_strings(zh):
    lines = ["package diw.wallet.core.i18n", "",
             "/** Generated by tools/i18n/i18n.py from the core_ strings of values-zh: the text core uses without the app. */",
             "object CoreStrings {", "    val ZH: Map<String, String> = mapOf("]
    for k in sorted(zh):
        if k.startswith("core_"):
            lines.append("        %s to %s," % (kotlin_string(k), kotlin_string(zh[k])))
    lines += ["    )", "}"]
    CORE_STRINGS.parent.mkdir(parents=True, exist_ok=True)
    CORE_STRINGS.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_apply(path, translations, model=False, core=False):
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
        if core and not key.startswith("core_"):
            key = "core_" + key
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
        if core:
            if bare:
                sys.exit("@%s is not available with --core" % key)
            call = 'ct("%s"%s)' % (key, "".join(", " + a for a in args))
        else:
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
    package = re.search(r"^package (\S+)", new, re.M)
    if core:
        imports = [] if package and package.group(1) == "diw.wallet.core.i18n" else ["import diw.wallet.core.i18n.ct"]
    else:
        imports = ["import diw.wallet.app.res.Res", "import diw.wallet.app.res.*"]
    if any(c.startswith("stringResource(") for c in plan.values()):
        imports.insert(0, "import org.jetbrains.compose.resources.stringResource")
    package = re.search(r"^package (\S+)", new, re.M)
    if any(c.startswith("tr(") for c in plan.values()) and not (package and package.group(1) == "diw.wallet.app"):
        imports.insert(0, "import diw.wallet.app.tr")
    for imp in imports:
        if imp not in new and plan:
            m = re.search(r"^import .*$", new, re.M)
            if m:
                new = new[:m.start()] + imp + "\n" + new[m.start():]
            else:
                p = re.search(r"^package .*$", new, re.M)
                at = p.end() if p else 0
                new = new[:at] + "\n\n" + imp + new[at:]
    Path(path).write_text(new, encoding="utf-8")
    write_strings(RES / "values/strings.xml", en)
    write_strings(RES / "values-zh/strings.xml", zh)
    if core:
        write_core_strings(zh)
    print("moved %d of %d literals" % (len(plan), len(found)))
    if (RES / HANS / "strings.xml").exists():
        cmd_hans([])


def cmd_check(paths):
    total = 0
    for p in paths:
        if Path(p).resolve() == CORE_STRINGS.resolve():
            continue
        _, found = chinese(p)
        if found:
            print("%5d %s" % (len(found), p))
        total += len(found)
    print("%5d total" % total)


HANS = "values-zh-rCN"
PLACEHOLDER = re.compile(r"%(\d+)\$[sd]")
# Traditional words whose Simplified form is fixed here instead of by the OpenCC phrase table (tw2sp): names of
# Taiwanese bodies and products, and words the table turns into other words ("檔案" and "文件" stay file and
# document, "離線" stays offline). Longest first; each is kept whole.
HANS_KEEP = {
    "數位憑證皮夾": "数位凭证皮夹", "數位發展部": "数位发展部", "區域網路": "局域网", "原始檔案": "原始文件",
    "檔案": "文件", "存檔": "存档", "在線上": "在线", "離線": "离线", "啟用": "启用", "複製": "复制", "查詢": "查询",
    "預設": "默认", "帳號": "账号", "帳戶": "账户", "區域": "区域", "紀錄": "记录", "時戳": "时间戳",
}


def qualifier_tag(qualifier):
    """BCP 47 tag of a resource qualifier: zh-rCN is zh-CN, b+sr+Latn is sr-Latn; None when it names no language."""
    if qualifier.startswith("b+"):
        return "-".join(qualifier[2:].split("+"))
    parts = qualifier.split("-")
    if not re.fullmatch(r"[a-z]{2,3}", parts[0]):
        return None
    if len(parts) > 1 and re.fullmatch(r"r[A-Z]{2}", parts[1]):
        return parts[0] + "-" + parts[1][1:]
    return parts[0]


def translation_files():
    """(qualifier, file) of every translation of the default file, in the order of their directories."""
    out = []
    for d in sorted(RES.glob("values-*")):
        q = d.name[len("values-"):]
        if (d / "strings.xml").exists() and qualifier_tag(q):
            out.append((q, d / "strings.xml"))
    return out


def translation_file(qualifier):
    if not qualifier_tag(qualifier):
        sys.exit("%s names no language (examples: ja, pt-rBR, b+sr+Latn)" % qualifier)
    return RES / ("values-" + qualifier) / "strings.xml"


def problems(default, strings):
    out = []
    for k, v in strings.items():
        if k not in default:
            out.append("%s: not in the default file" % k)
        elif v and set(PLACEHOLDER.findall(v)) != set(PLACEHOLDER.findall(default[k])):
            out.append("%s: placeholders differ from the default file" % k)
    return out


def cmd_status():
    default = read_strings(RES / "values/strings.xml")
    meta = string_meta(RES / "values/strings.xml")
    total = sum(1 for k in default if 'translatable="false"' not in meta.get(k, ([], ""))[1])
    bad = 0
    print("%-14s %-12s %-14s %s" % ("directory", "language", "translated", "errors"))
    for q, f in translation_files():
        strings = read_strings(f)
        found = problems(default, strings)
        bad += len(found)
        done = sum(1 for k in strings if k in default and 'translatable="false"' not in meta.get(k, ([], ""))[1])
        tag = strings.get("language_tag") or qualifier_tag(q)
        print("%-14s %-12s %5d / %-6d %d" % ("values-" + q, tag, done, total, len(found)))
        for p in found[:20]:
            print("    " + p)
    sys.exit(1 if bad else 0)


def cmd_new(qualifier, name=None):
    f = translation_file(qualifier)
    if f.exists():
        sys.exit("%s exists" % f)
    tag = qualifier_tag(qualifier)
    strings = {"language_tag": tag, "language_self": name or tag}
    write_strings(f, strings, string_meta(RES / "values/strings.xml"))
    print("wrote %s (%s); next: python3 tools/i18n/i18n.py missing %s" % (f.relative_to(ROOT), tag, qualifier))


def cmd_missing(qualifier, out=None):
    default = read_strings(RES / "values/strings.xml")
    meta = string_meta(RES / "values/strings.xml")
    zh = read_strings(RES / "values-zh/strings.xml")
    have = read_strings(translation_file(qualifier))
    rows = ["key\tEnglish\tTraditional Chinese\ttranslation"]
    for k, v in default.items():
        if k not in have and 'translatable="false"' not in meta.get(k, ([], ""))[1]:
            rows.append("\t".join(x.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t") for x in (k, v, zh.get(k, ""))) + "\t")
    text = "\n".join(rows) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print("%d strings to translate in %s" % (len(rows) - 1, out))
    else:
        sys.stdout.write(text)


def cmd_import(qualifier, tsv):
    f = translation_file(qualifier)
    default = read_strings(RES / "values/strings.xml")
    strings = read_strings(f)
    added = 0
    for n, raw in enumerate(Path(tsv).read_text(encoding="utf-8-sig").splitlines(), 1):
        cols = raw.split("\t")
        if n == 1 and cols[0] == "key" or len(cols) < 4 or not cols[3].strip():
            continue
        key = cols[0]
        text = cols[3].replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
        if key not in default:
            sys.exit("line %d: %s is not in the default file" % (n, key))
        if set(PLACEHOLDER.findall(text)) != set(PLACEHOLDER.findall(default[key])):
            sys.exit("line %d: %s must keep the placeholders of %r" % (n, key, default[key]))
        strings[key] = text
        added += 1
    if "language_tag" not in strings:
        strings["language_tag"] = qualifier_tag(qualifier)
    write_strings(f, strings, string_meta(RES / "values/strings.xml"))
    print("%d translations in %s" % (added, f.relative_to(ROOT)))


def to_hans(text):
    import opencc
    converter = opencc.OpenCC("tw2sp")
    saved = []

    def hold(m):
        saved.append(HANS_KEEP[m.group(0)])
        return chr(0xE000 + len(saved) - 1)

    words = "|".join(re.escape(k) for k in sorted(HANS_KEEP, key=len, reverse=True))
    out = converter.convert(re.sub(words, hold, text))
    return re.sub("[\uE000-\uEFFF]", lambda m: saved[ord(m.group(0)) - 0xE000], out)


def cmd_hans(keys):
    try:
        import opencc  # noqa: F401
    except ImportError:
        print("Simplified Chinese not written: pip install opencc, then python3 tools/i18n/i18n.py hans")
        return
    default = read_strings(RES / "values/strings.xml")
    zh = read_strings(RES / "values-zh/strings.xml")
    f = RES / HANS / "strings.xml"
    hans = {k: v for k, v in read_strings(f).items() if k in default}
    hans.setdefault("language_tag", "zh-CN")
    hans.setdefault("language_self", "简体中文")
    added = 0
    for k, v in zh.items():
        if k in default and k not in ("language_tag", "language_self") and (k not in hans or k in keys):
            hans[k] = to_hans(v)
            added += 1
    write_strings(f, hans, string_meta(RES / "values/strings.xml"))
    print("%d Simplified Chinese strings written to %s" % (added, f.relative_to(ROOT)))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["extract"]:
        cmd_extract(a[1])
    elif a[:1] == ["apply"]:
        cmd_apply(a[1], a[2], "--tr" in a[3:], "--core" in a[3:])
    elif a[:1] == ["check"]:
        cmd_check(a[1:])
    elif a[:1] == ["status"]:
        cmd_status()
    elif a[:1] == ["new"] and len(a) in (2, 3):
        cmd_new(*a[1:])
    elif a[:1] == ["missing"] and len(a) in (2, 3):
        cmd_missing(*a[1:])
    elif a[:1] == ["import"] and len(a) == 3:
        cmd_import(a[1], a[2])
    elif a[:1] == ["hans"]:
        cmd_hans(a[1:])
    else:
        sys.exit(__doc__)

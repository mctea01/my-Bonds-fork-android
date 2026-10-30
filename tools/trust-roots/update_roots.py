#!/usr/bin/env python3
"""Regenerates the wallet's built-in public CA roots from their sources and reports what needs a person.

Sources (tools/trust-roots/roots.json):
  - CCADB (Mozilla and Microsoft root programs): every included root of the listed mainland China CA owners;
  - service hosts: each host is connected to, and the CCADB roots of the chain it serves are built in;
  - time stamping: CCADB roots the Microsoft program includes for the Time Stamping EKU (TSA anchors only);
  - SM2 roots: pinned PEM files (not in CCADB), checked against their SHA-256 and validity;
  - other pinned roots: roots outside CCADB that official documents chain to (BJCA Global Root CA3 for the
    National Immigration Administration's documents), pinned by SHA-256 and checked the same way;
  - intermediates: pinned CA certificates that complete chains whose senders leave them out (BJCA DocSign CA3, the
    e-sign platform eSign's CAs); they are never anchors, and each must be signed by a built-in root or by an
    importable root;
  - importable roots: pinned roots outside every program (eSign Root CA), built in untrusted so that a chain can be
    completed up to them and the user can import them from a document;
  - every pinned file above is compared with the certificate its source URL publishes on each run: a root re-issued
    with the same key and an intermediate a built-in root signed replace the file and its pin automatically; a new
    key, or the first certificate of a new entry, is written with a warning so that a person checks it;
  - GPKI: the Taiwan government CA repositories, compared with the built-in GPKI anchors (report only).

Writes core/.../trust/BuiltInPublicRoots.kt only when the set of roots changes, and keeps its UPDATED date
otherwise, so that a scheduled run opens a pull request only for a real change.

Usage:
  python3 -I tools/trust-roots/update_roots.py [--report FILE] [--check] [--strict]
    --check   exit 1 when the Kotlin file would change (nothing is written)
    --strict  exit 2 when the report has warnings (after writing)

Needs Python 3.9+ and the openssl command (3.0+). Honours HTTPS_PROXY for downloads and TLS connections.
"""
import argparse
import base64
import csv
import datetime
import hashlib
import io
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
KOTLIN = os.path.join(REPO, "core/src/commonMain/kotlin/diw/wallet/core/trust/BuiltInPublicRoots.kt")
CONFIG = os.path.join(HERE, "roots.json")
SERVICES_LOCK = os.path.join(HERE, "services.lock.json")
TODAY = datetime.datetime.now(datetime.timezone.utc)

warnings = []
notes = []


def warn(text):
    warnings.append(text)
    print("WARNING " + text, file=sys.stderr)


# Certificates are verified as usual, but without Python's RFC 5280 strict mode: the Taiwan government sites serve
# chains whose CA certificates lack a Subject Key Identifier, which strict mode refuses.
TLS = ssl.create_default_context()
TLS.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)


def fetch(url, attempts=3):
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "diw-wallet-trust-roots/1.0"})
            with urllib.request.urlopen(req, timeout=90, context=TLS) as r:
                return r.read()
        except Exception as e:  # network errors are retried, then reported by the caller
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"{url}: {last}")


def openssl(args, data=None):
    r = subprocess.run(["openssl"] + args, input=data, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("openssl " + " ".join(args) + ": " + r.stderr.decode("utf-8", "replace").strip())
    return r.stdout


def pem_blocks(text):
    return [base64.b64decode(re.sub(r"\s", "", b)) for b in
            re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)]


def to_pem(der):
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def sha256(der):
    return hashlib.sha256(der).hexdigest().upper()


class Cert:
    """The fields of one certificate the tool needs, read with openssl."""

    def __init__(self, der):
        self.der = der
        self.sha256 = sha256(der)
        out = openssl(["x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-subject_hash", "-issuer_hash",
                       "-startdate", "-enddate", "-nameopt", "utf8,sep_comma_plus_space"], der).decode("utf-8", "replace")
        lines = out.splitlines()
        self.subject = lines[0].split("=", 1)[1].strip()
        self.issuer = lines[1].split("=", 1)[1].strip()
        self.subject_hash = lines[2].strip()
        self.issuer_hash = lines[3].strip()
        self.not_before = parse_time(lines[4].split("=", 1)[1])
        self.not_after = parse_time(lines[5].split("=", 1)[1])
        text = openssl(["x509", "-inform", "DER", "-noout", "-text"], der).decode("utf-8", "replace")
        self.algorithm = key_algorithm(text)
        self.ca = bool(re.search(r"CA:TRUE", text))
        self.spki = sha256(openssl(["x509", "-inform", "DER", "-noout", "-pubkey"], der))

    @property
    def self_issued(self):
        return self.subject_hash == self.issuer_hash

    def valid_at(self, t):
        return self.not_before <= t <= self.not_after


def parse_time(s):
    return datetime.datetime.strptime(s.strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)


def key_algorithm(text):
    m = re.search(r"Public Key Algorithm: (\S+)", text)
    alg = m.group(1) if m else ""
    if alg == "rsaEncryption":
        m = re.search(r"Public-Key: \((\d+) bit\)", text)
        return "RSA " + (m.group(1) if m else "")
    if alg == "id-ecPublicKey":
        m = re.search(r"NIST CURVE: (\S+)", text) or re.search(r"ASN1 OID: (\S+)", text)
        curve = m.group(1) if m else ""
        return "SM2" if curve in ("SM2", "1.2.156.10197.1.301") else "ECC " + curve
    if alg in ("SM2", "sm2"):
        return "SM2"
    return alg or "?"


def signed_by(cert, root):
    """Whether root's key signed cert (time is not checked: the chain may be older or newer than today)."""
    with tempfile.TemporaryDirectory() as d:
        c, r = os.path.join(d, "c.pem"), os.path.join(d, "r.pem")
        open(c, "w").write(to_pem(cert.der))
        open(r, "w").write(to_pem(root.der))
        # SM2 signatures need the signer ID; certificates use the default one (GM/T 0009).
        sm2 = ["-vfyopt", "distid:1234567812345678"] if root.algorithm == "SM2" else []
        res = subprocess.run(["openssl", "verify", "-partial_chain", "-no_check_time"] + sm2 + ["-CAfile", r, c], capture_output=True)
        return res.returncode == 0


# ---- Pinned files kept up to date from their sources -------------------------------------------------------------

WRITE = True
config_changed = False


def certs_in(data, depth=0):
    """Every certificate in a download: a DER or PEM certificate, a PKCS#7 bundle, or a ZIP of those."""
    if depth > 2:
        return []
    if data[:2] == b"PK":
        out = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for i in z.infolist():
                    if not i.is_dir() and i.file_size <= 1 << 20:
                        out += certs_in(z.read(i), depth + 1)
        except zipfile.BadZipFile:
            pass
        return out
    text = data.decode("utf-8", "replace")
    if "-----BEGIN CERTIFICATE-----" in text:
        return pem_blocks(text)
    if "-----BEGIN PKCS7-----" in text or data[:1] == b"\x30":
        for form in ("DER", "PEM"):
            r = subprocess.run(["openssl", "pkcs7", "-inform", form, "-print_certs"], input=data, capture_output=True)
            if r.returncode == 0 and b"BEGIN CERTIFICATE" in r.stdout:
                return pem_blocks(r.stdout.decode("utf-8", "replace"))
        r = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "DER"], input=data, capture_output=True)
        if r.returncode == 0:
            return [r.stdout]
        return []
    # A certificate in base64 without the PEM lines.
    compact = re.sub(r"\s", "", text)
    if compact and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            return certs_in(base64.b64decode(compact), depth + 1)
        except Exception:
            return []
    return []


def common_name(subject):
    m = re.search(r"(?:^|, )CN=([^,]+)", subject)
    return m.group(1).strip() if m else None


_fetched = {}


def fetch_cached(url):
    """[fetch], once per run for each URL (a bundle is the source of many entries)."""
    if url not in _fetched:
        try:
            _fetched[url] = fetch(url)
        except Exception as e:
            _fetched[url] = e
    if isinstance(_fetched[url], Exception):
        raise _fetched[url]
    return _fetched[url]


def zip_name(info):
    """A ZIP member name: UTF-8 when flagged, else GBK (the bundles are made on Chinese Windows)."""
    if info.flag_bits & 0x800:
        return info.filename
    raw = info.filename.encode("cp437")
    for enc in ("utf-8", "gbk", "gb18030"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return info.filename


def bundle_url(b):
    """The newest bundle the CA's page links to (the file name carries its date), else the configured one."""
    try:
        page = fetch_cached(b["page"]).decode("utf-8", "replace").replace("\\u002F", "/")
        links = sorted(set(re.findall(b["linkPattern"], page)))
        if links:
            return links[-1]
        notes.append(f"{b['name']} 的頁面沒有找到憑證包連結，沿用 {b['url']}")
    except Exception as e:
        notes.append(f"{b['name']} 的頁面無法連線（{e}），沿用 {b['url']}")
    return b["url"]


def sync_bundles(cfg, cc):
    """
    Adds the production CA certificates a published bundle holds (the e-sign platform eSign publishes the roots and
    intermediates of every CA it works with) as pinned entries, so that a CA the platform adds later is picked up by
    the next run. Test and sandbox certificates, expired ones and certificates already built in are left out; a
    re-issued certificate of an entry already listed is handled by [refresh]. A new root is written with a warning
    so that a person checks it before the pull request is merged; a new intermediate is kept only when a built-in
    root or intermediate signed it.
    """
    global config_changed
    for b in cfg.get("bundles", []):
        url = bundle_url(b)
        if url != b["url"]:
            notes.append(f"{b['name']} 有新版：{url}")
            if WRITE:
                b["url"] = url
                config_changed = True
        try:
            data = fetch_cached(url)
            z = zipfile.ZipFile(io.BytesIO(data))
        except Exception as e:
            notes.append(f"{b['name']} 無法下載或讀取（{e}），沿用已釘選的憑證")
            continue
        sections = ("pinned", "sm2", "intermediates", "importableRoots")
        listed = [e for sec in sections for e in cfg.get(sec, [])]
        known = set(cc) | {e.get("sha256") for e in listed}
        keys = set()
        names = {e["name"] for e in listed}
        for e in listed:
            path = os.path.join(HERE, e["file"])
            if os.path.exists(path):
                c = Cert(pem_blocks(open(path, encoding="utf-8").read())[0])
                keys.add((c.subject, c.spki))
        found = []
        for info in z.infolist():
            if info.is_dir() or info.file_size > 1 << 20:
                continue
            path = zip_name(info)
            for der in certs_in(z.read(info)):
                try:
                    c = Cert(der)
                except Exception:
                    continue
                if re.search(b["exclude"], path + " " + c.subject, re.I) or not c.ca or not c.valid_at(TODAY):
                    continue
                if c.sha256 in known or (c.subject, c.spki) in keys:
                    continue
                known.add(c.sha256)
                parts = path.split("/")
                folder = next((p for p in parts if p in b["owners"]), None)
                found.append((c, b["owners"].get(folder, b["defaultOwner"])))
        # Roots first, then intermediates nearest the roots, so that each is checked against what came before.
        found.sort(key=lambda t: (not t[0].self_issued, t[0].not_before))
        for c, owner in found:
            cn = common_name(c.subject) or c.subject
            name = cn if cn not in names else f"{cn}（{owner}）"
            names.add(name)
            slug = re.sub(r"[^A-Za-z0-9]+", "-", cn).strip("-").lower() or "ca"
            entry = {"file": f"{b['dir']}/{slug}-{c.sha256[:8].lower()}.pem", "name": name, "subjectDN": c.subject,
                     "owner": owner, "purposes": b["purposes"], "url": url, "page": b["page"], "sha256": c.sha256}
            if c.self_issued:
                if c.algorithm == "SM2":
                    entry["fingerprintPublished"] = False
                    section = "sm2"
                else:
                    entry["evidence"] = b["evidence"]
                    section = "pinned"
                warn(f"新增{b['name']}的根憑證 {name}（{owner}，SHA-256 {c.sha256}），請核對後再合併")
            else:
                section = "intermediates"
                notes.append(f"新增{b['name']}的中繼憑證 {name}（{owner}）")
            if WRITE:
                os.makedirs(os.path.dirname(os.path.join(HERE, entry["file"])), exist_ok=True)
                with open(os.path.join(HERE, entry["file"]), "w", encoding="utf-8") as f:
                    f.write(to_pem(c.der))
                cfg.setdefault(section, []).append(entry)
                config_changed = True


def refresh(s, kind, issued_by=None):
    """
    Brings the pinned file of entry [s] up to date with the certificate its source (s["url"]) publishes, and returns
    the state for the report, or None when the entry has no certificate yet and none could be fetched.

    The pin moves automatically only when it stays as strong as it was: a root re-issued with the same key (newer
    validity), or an intermediate with the same subject that a built-in or importable root signed ([issued_by]).
    A root with a new key, or the first certificate of a new entry, is written and pinned too, but with a warning, so
    that a person compares the fingerprint with the CA's site before the pull request is merged.
    """
    global config_changed
    path = os.path.join(HERE, s["file"])
    old = Cert(pem_blocks(open(path, encoding="utf-8").read())[0]) if os.path.exists(path) else None
    if old is not None and s.get("sha256") and old.sha256 != s["sha256"]:
        raise RuntimeError(f"{s['file']} does not match its pinned SHA-256")
    if s.get("autoUpdate") is False or not s.get("url"):
        return "只檢查（來源不是下載檔）" if old else None
    try:
        data = fetch_cached(s["url"])
    except Exception as e:
        if old is None:
            warn(f"{s['name']} 尚未取得，且無法從 {s['url']} 下載：{e}")
            return None
        notes.append(f"{s['name']} 的來源無法連線，沿用釘選的檔案")
        return "來源無法連線，沿用釘選檔"
    found = []
    for der in certs_in(data):
        try:
            found.append(Cert(der))
        except Exception:
            continue
    if old is not None and any(c.sha256 == old.sha256 for c in found):
        return "與來源相符"
    # A new entry names the certificate by its common name, or "*" for a download that holds only that root.
    want = common_name(old.subject) if old else s.get("subject", s["name"])
    if old is not None:
        same = [c for c in found if c.subject == old.subject]
    elif s.get("subjectDN"):
        same = [c for c in found if c.subject == s["subjectDN"]]
    else:
        same = [c for c in found if want == "*" or common_name(c.subject) == want]
    if kind == "root":
        same = [c for c in same if c.self_issued and c.ca]
    else:
        same = [c for c in same if not c.self_issued and c.ca]
    same = [c for c in same if c.valid_at(TODAY) and (old is None or c.not_after > old.not_after)]
    if not same:
        if old is None:
            warn(f"{s['name']} 尚未取得：{s['url']} 沒有這張憑證")
            return None
        notes.append(f"{s['name']} 不在來源 {s['url']} 中，或來源的版本沒有比較新，沿用釘選的檔案")
        return "來源沒有較新的版本，沿用釘選檔"
    new = max(same, key=lambda c: c.not_after)
    if kind == "root":
        if old is not None and new.spki != old.spki:
            warn(f"{s['name']} 的來源有不同金鑰的新根憑證（SHA-256 {new.sha256}），沒有自動替換，需要人工確認")
            return "來源有不同金鑰的新版，需要人工確認"
        if old is None:
            warn(f"首次取得根憑證 {s['name']}（SHA-256 {new.sha256}），請與 {s.get('page', s['url'])} 核對後再合併")
    elif issued_by is not None and not issued_by(new):
        if old is None:
            warn(f"{s['name']} 尚未取得：來源的版本不是由內建或可匯入的根憑證簽發")
            return None
        warn(f"{s['name']} 的來源新版不是由內建或可匯入的根憑證簽發，沒有自動替換")
        return "來源新版無法連到根憑證，沿用釘選檔"
    if WRITE:
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_pem(new.der))
    if old is None and s.get("subject") == "*":
        s["name"] = common_name(new.subject) or s["name"]
        s.pop("subject")
    s["sha256"] = new.sha256
    config_changed = True
    what = "首次取得" if old is None else f"已自動更新（原 SHA-256 {old.sha256}）"
    notes.append(f"{s['name']} {what}，有效至 {new.not_after.date()}")
    return "首次取得" if old is None else "已自動更新"


# ---- CCADB ------------------------------------------------------------------------------------------------------

BITS = [("Websites", "Server Authentication", "網站"), ("Email", "Secure Email", "電子郵件"),
        (None, "Code Signing", "程式碼簽章"), (None, "Document Signing", "文件簽章"), (None, "Time Stamping", "時間戳記")]


def ccadb_roots(cfg):
    """All roots included in either program, keyed by SHA-256, each with its programs, owner and uses."""
    csv.field_size_limit(10 ** 8)
    roots = {}
    for program, url in (("mozilla", cfg["mozilla"]), ("microsoft", cfg["microsoft"])):
        rows = list(csv.DictReader(io.StringIO(fetch(url).decode("utf-8-sig"))))
        if len(rows) < 50:
            raise RuntimeError(f"CCADB {program} report has only {len(rows)} rows")
        for row in rows:
            if program == "microsoft" and row.get("Microsoft Status") != "Included":
                continue
            ders = pem_blocks(row.get("PEM Info", ""))
            if len(ders) != 1:
                continue
            fp = row["SHA-256 Fingerprint"].replace(":", "").upper()
            if sha256(ders[0]) != fp:
                warn(f"CCADB {program}: the PEM of {fp[:16]} does not match its fingerprint; skipped")
                continue
            e = roots.setdefault(fp, {"der": ders[0], "programs": set(), "uses": set(), "owner": "", "name": ""})
            e["programs"].add(program)
            if program == "mozilla":
                e["owner"] = e["owner"] or row["Owner"]
                e["name"] = row["Common Name or Certificate Name"] or e["name"]
                bits = row.get("Trust Bits", "")
                e["uses"].update(zh for moz, _, zh in BITS if moz and moz in bits)
            else:
                e["owner"] = e["owner"] or row["CA Owner"]
                e["name"] = e["name"] or row["CA Common Name or Certificate Name"]
                ekus = row.get("Microsoft EKUs", "")
                e["uses"].update(zh for _, ms, zh in BITS if ms in ekus)
    return roots


def uses_text(uses):
    order = [zh for _, _, zh in BITS]
    return "、".join(u for u in order if u in uses) or "其他用途"


# ---- Services ---------------------------------------------------------------------------------------------------

def proxy_args():
    p = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not p:
        return []
    m = re.match(r"^(?:https?://)?(?:([^:@/]*)(?::([^@/]*))?@)?([^/]+)", p)
    args = ["-proxy", m.group(3)]
    if m.group(1):
        args += ["-proxy_user", m.group(1)]
        if m.group(2):
            args += ["-proxy_pass", "pass:" + m.group(2)]
    return args


def served_chain(host):
    r = subprocess.run(["openssl", "s_client", "-connect", host + ":443", "-servername", host, "-showcerts"] + proxy_args(),
                       input=b"", capture_output=True, timeout=60)
    ders = pem_blocks(r.stdout.decode("utf-8", "replace"))
    if not ders:
        raise RuntimeError(r.stderr.decode("utf-8", "replace").strip().splitlines()[-1] if r.stderr else "no certificates")
    return [Cert(d) for d in ders]


def chain_roots(chain, by_subject):
    """Every CCADB root that anchors some certificate of the served chain (cross-signed paths give several)."""
    found = []
    for c in chain:
        for fp, root in by_subject.get(c.issuer_hash, []):
            if fp not in found and (c.sha256 == fp or signed_by(c, root)):
                found.append(fp)
    return found


# ---- GPKI -------------------------------------------------------------------------------------------------------

def kotlin_constants(path):
    """The base64 certificates in a Kotlin source: every string constant built from base64 literals."""
    text = open(path, encoding="utf-8").read()
    out = {}
    for m in re.finditer(r"const val (\w+)\s*=\s*((?:\"[A-Za-z0-9+/=]+\"\s*\+?\s*)+)", text):
        b64 = "".join(re.findall(r"\"([A-Za-z0-9+/=]+)\"", m.group(2)))
        if len(b64) > 400:
            try:
                out[m.group(1)] = base64.b64decode(b64)
            except Exception:
                pass
    return out


def p7b_certs(data):
    for form in ("DER", "PEM"):
        r = subprocess.run(["openssl", "pkcs7", "-inform", form, "-print_certs"], input=data, capture_output=True)
        if r.returncode == 0:
            return [Cert(d) for d in pem_blocks(r.stdout.decode("utf-8", "replace"))]
    return [Cert(d) for d in pem_blocks(data.decode("utf-8", "replace"))]


def check_gpki(cfg, warn_until):
    built = {}
    for rel in cfg["builtIn"]:
        for name, der in kotlin_constants(os.path.join(REPO, rel)).items():
            try:
                built[sha256(der)] = (name, Cert(der))
            except Exception:
                pass
    lines = [f"內建 GPKI 憑證 {len(built)} 張。"]
    for fp, (name, c) in sorted(built.items(), key=lambda kv: kv[1][1].not_after):
        if c.not_after < warn_until:
            warn(f"GPKI 內建憑證 {name}（{c.subject}）將於 {c.not_after.date()} 到期")
    for repo in cfg["repositories"]:
        try:
            certs = p7b_certs(fetch(repo["url"]))
        except Exception as e:
            warn(f"GPKI {repo['ca']} 儲存庫無法取得：{e}")
            continue
        # Compared by key: a link certificate between two built-in keys (GRCA's key rollover) or a re-issue that ends
        # no later than the built-in certificate of the same key needs nothing.
        latest = {}
        for _, b in built.values():
            latest[b.spki] = max(latest.get(b.spki, b.not_after), b.not_after)
        new = [c for c in certs if c.sha256 not in built and c.valid_at(TODAY) and c.ca
               and (c.spki not in latest or c.not_after > latest[c.spki])]
        lines.append(f"- {repo['ca']}：儲存庫 {len(certs)} 張，金鑰未內建或延長效期的 CA 憑證 {len(new)} 張")
        for c in new:
            what = "延長效期的憑證" if c.spki in latest else "未內建的 CA 金鑰"
            warn(f"GPKI {repo['ca']} 有{what}：{c.subject}，簽發者 {c.issuer}，有效至 {c.not_after.date()}，SHA-256 {c.sha256}")
    return lines


# ---- Kotlin -----------------------------------------------------------------------------------------------------

def kstr(s):
    return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$")


def kotlin_b64(der):
    b = base64.b64encode(der).decode()
    return " +\n            ".join("\"" + b[j:j + 100] + "\"" for j in range(0, len(b), 100))


def c2pa_trust_list(cfg, entries):
    """Adds the valid anchors of the C2PA trust list to [entries]; returns the report lines."""
    path = os.path.join(HERE, cfg["file"])
    old = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    try:
        text = fetch(cfg["url"]).decode("utf-8")
        how = "連線取得"
    except Exception as e:
        if not old:
            raise
        text = old
        how = "沿用釘選的清單（" + str(e).splitlines()[0][:80] + "）"
        notes.append("C2PA 信任清單這次無法下載，沿用釘選的清單")
    ders = pem_blocks(text)
    if not ders:
        raise RuntimeError(cfg["url"] + " holds no certificate")
    old_fps = {sha256(d) for d in pem_blocks(old)}
    new_fps = [sha256(d) for d in ders]
    if old and set(new_fps) != old_fps:
        warn(f"C2PA 信任清單有變更（新增 {len(set(new_fps) - old_fps)} 張，移除 {len(old_fps - set(new_fps))} 張），請確認後合併")
    if not old:
        warn("首次取得 C2PA 信任清單，請確認後合併")
    if WRITE and text != old:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    lines = [f"來源：{cfg['url']}（{how}）", "", "| 憑證 | 機構 | 種類 | 有效至 | 狀態 |", "|---|---|---|---|---|"]
    for der in ders:
        c = Cert(der)
        fp = sha256(der)
        org = re.search(r"(?:^|, )O=([^,]+)", c.subject)
        name = common_name(c.subject) or c.subject
        kind = "根憑證" if c.self_issued else "清單列入的中繼憑證"
        state = "有效"
        if not c.valid_at(TODAY):
            state = "已過期，不內建"
        elif fp in entries:
            state = "已在其他群組"
        else:
            entries[fp] = {"name": name, "owner": org.group(1).strip() if org else name, "group": "CONTENT_CREDENTIALS",
                           "algorithm": c.algorithm, "base": "C2PA 內容憑證（Content Credentials）簽署者的信任錨點；" + kind,
                           "services": [], "source": "C2PA 信任清單（" + cfg["url"] + "）", "sha256": fp, "der": der}
        lines.append(f"| {name} | {org.group(1).strip() if org else '-'} | {kind} | {c.not_after.date()} | {state} |")
    return lines


def kotlin(entries, intermediates, importable, updated):
    blocks = []
    for e in entries:
        body = kotlin_b64(e["der"])
        blocks.append(f"""        Root(
            name = "{kstr(e['name'])}",
            owner = "{kstr(e['owner'])}",
            group = Group.{e['group']},
            algorithm = "{kstr(e['algorithm'])}",
            purposes = "{kstr(e['purposes'])}",
            source = "{kstr(e['source'])}",
            sha256 = "{e['sha256']}",
            b64 = {body},
        ),""")
    def chain_blocks(items):
        return [f"""        Intermediate(
            name = "{kstr(e['name'])}",
            owner = "{kstr(e['owner'])}",
            issuer = "{kstr(e['issuer'])}",
            purposes = "{kstr(e['purposes'])}",
            source = "{kstr(e['source'])}",
            sha256 = "{e['sha256']}",
            b64 = {kotlin_b64(e['der'])},
        ),""" for e in items]
    iblocks = chain_blocks(intermediates)
    rblocks = chain_blocks(importable)
    return """package diw.wallet.core.trust

import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64

/**
 * Public CA roots built into the wallet. Generated by tools/trust-roots/update_roots.py; do not edit by hand.
 * - mainland China CAs: every root of CFCA, GDCA, SHECA, BJCA, iTrusChina and TrustAsia included in the Mozilla or
 *   Microsoft root program (CCADB, SHA-256 checked), and the SM2 roots (Chinese national algorithms) of the national
 *   root CA and licensed CAs, pinned by SHA-256 as downloaded from each CA's own site, and roots outside the
 *   programs that official documents chain to (BJCA Global Root CA3 for the immigration administration), pinned too;
 * - common services: the roots of the certificate chains that the e-invoice and immigration services serve
 *   (China's tax administration and immigration administration, Taiwan's e-invoice platform and immigration agency);
 * - time stamping: the roots the Microsoft root program includes for the Time Stamping EKU, used for time-stamp
 *   authorities only (platform stores hold TLS roots, and many TSA roots are in none of them);
 * - content credentials: the anchors of the C2PA trust list, used for C2PA manifest signers only. The list names
 *   intermediates as anchors too, so this group is not limited to self-issued certificates.
 *
 * A chain to any of them is T2, like the platform store: a trust root verified a domain or organisation. The mainland
 * China group is switched on and off on its own; the others follow the platform store switch. A root is used only
 * while it is valid.
 *
 * [intermediates] are CA certificates that complete chains whose senders leave them out. They are never anchors: a
 * chain they complete is trusted only through the root it reaches. [importableRoots] are roots outside every program
 * that intermediates lead to: chains are completed up to them so that the user can import one from a document, and
 * they are trusted only once imported.
 */
object BuiltInPublicRoots {
    enum class Group { MAINLAND_CHINA, SERVICE, TIMESTAMPING, CONTENT_CREDENTIALS }

    class Root(
        val name: String,
        val owner: String,
        val group: Group,
        /** Key algorithm and size, e.g. "RSA 4096", "ECC secp384r1", "SM2". */
        val algorithm: String,
        /** What the CA issues for, and the services known to use it. */
        val purposes: String,
        val source: String,
        val sha256: String,
        private val b64: String,
    ) {
        val certificate: X509Cert by lazy { X509Cert(ByteString(b64.fromBase64())) }
        val national: Boolean get() = algorithm == "SM2"
    }

    class Intermediate(
        val name: String,
        val owner: String,
        /** The root that signed it (itself for an importable root). */
        val issuer: String,
        val purposes: String,
        val source: String,
        val sha256: String,
        private val b64: String,
    ) {
        val certificate: X509Cert by lazy { X509Cert(ByteString(b64.fromBase64())) }
    }

    /** The date the set of roots last changed (UTC). */
    const val UPDATED = \"""" + updated + """\"

    const val MAINLAND_SOURCE = "builtin:mainland-china"
    const val SERVICE_SOURCE = "builtin:services"
    const val TIMESTAMPING_SOURCE = "builtin:timestamping"
    const val CONTENT_CREDENTIALS_SOURCE = "builtin:c2pa"

    val all: List<Root> by lazy {
        listOf(
""" + "\n".join(blocks) + """
        )
    }

    val mainlandChina: List<Root> get() = all.filter { it.group == Group.MAINLAND_CHINA }
    val services: List<Root> get() = all.filter { it.group == Group.SERVICE }
    val timestamping: List<Root> get() = all.filter { it.group == Group.TIMESTAMPING }
    val contentCredentials: List<Root> get() = all.filter { it.group == Group.CONTENT_CREDENTIALS }

    val intermediates: List<Intermediate> by lazy {
        listOf(
""" + "\n".join(iblocks) + """
        )
    }

    val importableRoots: List<Intermediate> by lazy {
        listOf(
""" + "\n".join(rblocks) + """
        )
    }
}
"""


def previous():
    """The current file's UPDATED date and its roots (SHA-256 to name)."""
    if not os.path.exists(KOTLIN):
        return None, {}, ""
    text = open(KOTLIN, encoding="utf-8").read()
    m = re.search(r'const val UPDATED = "([0-9-]+)"', text)
    roots = dict((fp, name) for name, fp in re.findall(r'Root\(\s*name = "([^"]*)",(?:.|\n)*?sha256 = "([0-9A-F]{64})"', text))
    return (m.group(1) if m else None), roots, text


# ---- Main -------------------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", help="write the Markdown report to this file")
    ap.add_argument("--check", action="store_true", help="exit 1 when the Kotlin file would change; write nothing")
    ap.add_argument("--strict", action="store_true", help="exit 2 when there are warnings")
    args = ap.parse_args()
    global WRITE
    WRITE = not args.check

    cfg = json.load(open(CONFIG, encoding="utf-8"))
    warn_until = TODAY + datetime.timedelta(days=cfg.get("warnDays", 540))
    report = ["# 內建根憑證更新報告", "", f"執行時間：{TODAY.strftime('%Y-%m-%d %H:%M')} UTC", ""]

    # CCADB: the mainland owners' roots, valid now.
    cc = ccadb_roots(cfg["ccadb"])
    parsed = {}

    def cert_of(fp):
        if fp not in parsed:
            parsed[fp] = Cert(cc[fp]["der"])
        return parsed[fp]

    def mainland_owner(owner):
        for o in cfg["ccadb"]["mainlandOwners"]:
            if o["match"].lower() in owner.lower():
                return o["owner"]
        return None

    entries = {}
    for fp, e in cc.items():
        owner = mainland_owner(e["owner"])
        if owner is None:
            continue
        c = cert_of(fp)
        if not c.valid_at(TODAY):
            continue
        progs = "、".join(p for p in ("Mozilla", "Microsoft") if p.lower() in e["programs"])
        note = cfg["ccadb"]["notes"].get(e["name"])
        entries[fp] = {"name": e["name"], "owner": owner, "group": "MAINLAND_CHINA", "algorithm": c.algorithm,
                       "base": uses_text(e["uses"]) + ("；" + note if note else ""), "services": [],
                       "source": f"CCADB（{progs} 根憑證計畫）", "sha256": fp, "der": e["der"]}

    # Services: the roots of the chains they serve now, or as last seen when a host cannot be reached.
    lock = json.load(open(SERVICES_LOCK, encoding="utf-8")) if os.path.exists(SERVICES_LOCK) else {}
    by_subject = {}
    for fp in cc:
        try:
            by_subject.setdefault(cert_of(fp).subject_hash, []).append((fp, cert_of(fp)))
        except Exception:
            pass
    report += ["## 服務網站的憑證鏈", "", "| 服務 | 主機 | 根憑證 | 取得方式 |", "|---|---|---|---|"]
    new_lock = {}
    for s in cfg["services"]:
        host = s["host"]
        try:
            roots = chain_roots(served_chain(host), by_subject)
            how = "連線取得"
            if not roots:
                raise RuntimeError("the served chain leads to no CCADB root")
        except Exception as e:
            roots = [fp for fp in lock.get(host, []) if fp in cc]
            how = "沿用上次結果（" + str(e).splitlines()[0][:80] + "）"
            # Sites in mainland China often refuse connections from abroad: the last chain seen stays in use, and
            # only a host never seen needs a person.
            if roots:
                notes.append(f"服務 {s['name']}（{host}）這次無法連線，沿用上次取得的根憑證")
            else:
                warn(f"服務 {s['name']}（{host}）無法取得憑證鏈，也沒有上次的結果：{e}")
        new_lock[host] = roots
        for fp in roots:
            if fp not in entries:
                c = cert_of(fp)
                owner = next((v for k, v in cfg["ccadb"]["owners"].items() if k.lower() in cc[fp]["owner"].lower()), cc[fp]["owner"])
                progs = "、".join(p for p in ("Mozilla", "Microsoft") if p.lower() in cc[fp]["programs"])
                entries[fp] = {"name": cc[fp]["name"], "owner": owner, "group": "SERVICE", "algorithm": c.algorithm,
                               "base": "", "services": [], "source": f"CCADB（{progs} 根憑證計畫）", "sha256": fp,
                               "der": cc[fp]["der"]}
            entries[fp]["services"].append(f"{s['name']}（{host}）")
        report.append(f"| {s['name']} | {host} | " + "、".join(cc[fp]["name"] for fp in roots) + f" | {how} |")
    report.append("")

    # Bundles: new CA certificates a platform publishes become pinned entries below.
    sync_bundles(cfg, cc)

    # SM2: pinned, checked.
    report += ["## 國密 SM2 根憑證（釘選）", "", "| 根憑證 | 機構 | 有效至 | 狀態 | 來源核對 |", "|---|---|---|---|---|"]
    for s in cfg["sm2"]:
        fetched = refresh(s, "root")
        if fetched is None:
            continue
        der = pem_blocks(open(os.path.join(HERE, s["file"]), encoding="utf-8").read())[0]
        if sha256(der) != s["sha256"]:
            raise RuntimeError(f"{s['file']} does not match its pinned SHA-256")
        c = Cert(der)
        if c.algorithm != "SM2" or not c.self_issued:
            raise RuntimeError(f"{s['file']} is not a self-issued SM2 certificate")
        state = "有效"
        if not c.valid_at(TODAY):
            state = "已過期，不內建"
            warn(f"SM2 根憑證 {s['name']} 已過期（{c.not_after.date()}），需要從 {s['page']} 取得新版")
        elif c.not_after < warn_until:
            state = "即將到期"
            warn(f"SM2 根憑證 {s['name']} 將於 {c.not_after.date()} 到期，需要從 {s['page']} 確認新版")
        report.append(f"| {s['name']} | {s['owner']} | {c.not_after.date()} | {state} | {fetched} |")
        if not c.valid_at(TODAY):
            continue
        source = "官網下載 " + s["url"] + ("（指紋與官網公布相符）" if s.get("fingerprintPublished") else "")
        entries[s["sha256"]] = {"name": s["name"], "owner": s["owner"], "group": "MAINLAND_CHINA", "algorithm": "SM2",
                                "base": s["purposes"], "services": [], "source": source, "sha256": s["sha256"], "der": der}
    report.append("")

    # Other pinned roots: outside CCADB, pinned by the SHA-256 of the chain an official document carries.
    pinned_certs = {}
    report += ["## 其他釘選的根憑證（不在 CCADB）", "", "| 根憑證 | 機構 | 有效至 | 狀態 | 來源核對 |", "|---|---|---|---|---|"]
    for s in cfg.get("pinned", []):
        fetched = refresh(s, "root")
        if fetched is None:
            continue
        der = pem_blocks(open(os.path.join(HERE, s["file"]), encoding="utf-8").read())[0]
        if sha256(der) != s["sha256"]:
            raise RuntimeError(f"{s['file']} does not match its pinned SHA-256")
        c = Cert(der)
        if not c.self_issued or not c.ca:
            raise RuntimeError(f"{s['file']} is not a self-issued CA certificate")
        if s["sha256"] in cc:
            notes.append(f"{s['name']} 已收錄於 CCADB，可從 pinned 移除")
        state = "有效"
        if not c.valid_at(TODAY):
            state = "已過期，不內建"
            warn(f"根憑證 {s['name']} 已過期（{c.not_after.date()}），需要從 {s['page']} 取得新版")
        elif c.not_after < warn_until:
            state = "即將到期"
            warn(f"根憑證 {s['name']} 將於 {c.not_after.date()} 到期，需要從 {s['page']} 確認新版")
        report.append(f"| {s['name']} | {s['owner']} | {c.not_after.date()} | {state} | {fetched} |")
        if not c.valid_at(TODAY) or s["sha256"] in entries:
            continue
        pinned_certs[s["sha256"]] = c
        source = "釘選 SHA-256（" + s["evidence"] + "），取自 " + s["url"]
        entries[s["sha256"]] = {"name": s["name"], "owner": s["owner"], "group": "MAINLAND_CHINA", "algorithm": c.algorithm,
                                "base": s["purposes"], "services": [], "source": source, "sha256": s["sha256"], "der": der}
    report.append("")

    # Time stamping: roots the Microsoft program includes for the Time Stamping EKU, valid now. Many TSA roots
    # (Sectigo and GlobalSign time stamping roots, for instance) are in no platform store, which only serves TLS.
    for fp, e in cc.items():
        if fp in entries or "microsoft" not in e["programs"] or "時間戳記" not in e["uses"]:
            continue
        c = cert_of(fp)
        if not c.valid_at(TODAY):
            continue
        owner = next((v for k, v in cfg["ccadb"]["owners"].items() if k.lower() in e["owner"].lower()), e["owner"])
        entries[fp] = {"name": e["name"], "owner": owner, "group": "TIMESTAMPING", "algorithm": c.algorithm,
                       "base": uses_text(e["uses"]), "services": [], "source": "CCADB（Microsoft 根憑證計畫，時間戳記用途）",
                       "sha256": fp, "der": e["der"]}

    # Content credentials: the anchors of the C2PA trust list (conformance program), roots and the intermediates it
    # lists as anchors. The list is pinned; a change is written and needs a person to review the pull request.
    report += ["## C2PA 信任清單（內容憑證）", ""] + c2pa_trust_list(cfg["c2pa"], entries) + [""]

    for e in entries.values():
        parts = [p for p in (e["base"], ("、".join(e["services"]) + "的網站憑證鏈") if e["services"] else "") if p]
        e["purposes"] = "；".join(parts)
        # CCADB roots are replaced from their source when they expire; pinned roots were warned about above.
        if e["group"] == "CONTENT_CREDENTIALS":
            continue
        if e["algorithm"] != "SM2" and e["sha256"] not in pinned_certs and cert_of(e["sha256"]).not_after < warn_until:
            notes.append(f"{e['name']} 將於 {cert_of(e['sha256']).not_after.date()} 到期，到期後依來源自動移除或更新")

    order = {"MAINLAND_CHINA": 0, "SERVICE": 1, "TIMESTAMPING": 2, "CONTENT_CREDENTIALS": 3}
    ordered = sorted(entries.values(), key=lambda e: (order[e["group"]], e["algorithm"] == "SM2", e["owner"], e["name"], e["sha256"]))

    # Importable roots: pinned, self-issued, untrusted until the user imports one.
    importable = []
    report += ["## 可匯入的根憑證（釘選，內建但不信任）", "", "| 根憑證 | 機構 | 有效至 | 狀態 | 來源核對 |", "|---|---|---|---|---|"]
    for s in cfg.get("importableRoots", []):
        fetched = refresh(s, "root")
        if fetched is None:
            continue
        der = pem_blocks(open(os.path.join(HERE, s["file"]), encoding="utf-8").read())[0]
        if sha256(der) != s["sha256"]:
            raise RuntimeError(f"{s['file']} does not match its pinned SHA-256")
        c = Cert(der)
        if not c.self_issued or not c.ca:
            raise RuntimeError(f"{s['file']} is not a self-issued CA certificate")
        state = "有效"
        if not c.valid_at(TODAY):
            state = "已過期，不內建"
            warn(f"可匯入的根憑證 {s['name']} 已過期（{c.not_after.date()}），需要從 {s['page']} 取得新版")
        report.append(f"| {s['name']} | {s['owner']} | {c.not_after.date()} | {state} | {fetched} |")
        if c.valid_at(TODAY):
            importable.append({"name": s["name"], "owner": s["owner"], "issuer": s["name"], "purposes": s["purposes"],
                               "source": "釘選 SHA-256，取自 " + s["url"], "sha256": s["sha256"], "der": der, "cert": c})
    report.append("")

    # Intermediates: pinned, each signed by a built-in or importable root, or by an intermediate that is; they only
    # complete chains.
    intermediates = []
    report += ["## 內建中繼憑證（釘選，只用於補足憑證鏈）", "", "| 中繼憑證 | 簽發者 | 有效至 | 狀態 | 來源核對 |", "|---|---|---|---|---|"]
    roots_by_fp = {e["sha256"]: Cert(e["der"]) for e in ordered}
    roots_by_fp.update({e["sha256"]: e["cert"] for e in importable})
    signers = [(e, roots_by_fp[e["sha256"]]) for e in ordered + importable]
    listed = []
    for s in cfg.get("intermediates", []):
        path = os.path.join(HERE, s["file"])
        if os.path.exists(path):
            listed.append(Cert(pem_blocks(open(path, encoding="utf-8").read())[0]))

    def issuer_of(c):
        return next((e for e, ec in signers if ec.subject_hash == c.issuer_hash and signed_by(c, ec)), None)

    pending = []
    for s in cfg.get("intermediates", []):
        fetched = refresh(s, "intermediate", lambda c: issuer_of(c) is not None or any(
            o.subject_hash == c.issuer_hash and signed_by(c, o) for o in listed))
        if fetched is None:
            continue
        der = pem_blocks(open(os.path.join(HERE, s["file"]), encoding="utf-8").read())[0]
        if sha256(der) != s["sha256"]:
            raise RuntimeError(f"{s['file']} does not match its pinned SHA-256")
        c = Cert(der)
        if c.self_issued or not c.ca:
            raise RuntimeError(f"{s['file']} is not an intermediate CA certificate")
        pending.append([s, fetched, der, c, None])
    # An intermediate may be issued by another one: accept in passes until nothing more links up.
    progress = True
    while progress:
        progress = False
        for item in pending:
            if item[4] is None and item[3].valid_at(TODAY):
                issuer = issuer_of(item[3])
                if issuer is not None:
                    item[4] = issuer
                    signers.append(({"name": item[0]["name"], "sha256": item[0]["sha256"], **({"cert": True} if "cert" in issuer else {})}, item[3]))
                    progress = True
    for s, fetched, der, c, issuer in pending:
        state = "有效" if issuer is None or "cert" not in issuer else "有效（根憑證需使用者匯入）"
        if not c.valid_at(TODAY):
            state = "已過期，不內建"
            warn(f"中繼憑證 {s['name']} 已過期（{c.not_after.date()}），需要從 {s['page']} 取得新版")
        elif issuer is None:
            state = "不連到內建或可匯入的根憑證，不內建"
            warn(f"中繼憑證 {s['name']} 不是由任何內建或可匯入的根憑證簽發")
        elif c.not_after < warn_until:
            state = "即將到期"
            warn(f"中繼憑證 {s['name']} 將於 {c.not_after.date()} 到期，需要從 {s['page']} 確認新版")
        report.append(f"| {s['name']} | {issuer['name'] if issuer else '-'} | {c.not_after.date()} | {state} | {fetched} |")
        if issuer is None or not c.valid_at(TODAY):
            continue
        intermediates.append({"name": s["name"], "owner": s["owner"], "issuer": issuer["name"], "purposes": s["purposes"],
                              "source": "釘選 SHA-256，取自 " + s["url"], "sha256": s["sha256"], "der": der})
    report.append("")

    # GPKI: report only.
    report += ["## 政府憑證（GPKI，只檢查）", ""] + check_gpki(cfg["gpki"], warn_until) + [""]

    old_date, old_roots, old_text = previous()
    text = kotlin(ordered, intermediates, importable, old_date or TODAY.strftime("%Y-%m-%d"))
    changed = text != old_text
    if changed:
        text = kotlin(ordered, intermediates, importable, TODAY.strftime("%Y-%m-%d"))
    added = [e for e in ordered if e["sha256"] not in old_roots]
    removed = [(fp, n) for fp, n in old_roots.items() if fp not in entries]

    report[4:4] = ["## 摘要", "",
                   f"- 內建根憑證 {len(ordered)} 個：中國大陸 {sum(1 for e in ordered if e['group'] == 'MAINLAND_CHINA')} 個"
                   f"（SM2 {sum(1 for e in ordered if e['algorithm'] == 'SM2')} 個），常用服務 {sum(1 for e in ordered if e['group'] == 'SERVICE')} 個"
                   f"，時間戳記 {sum(1 for e in ordered if e['group'] == 'TIMESTAMPING')} 個，C2PA {sum(1 for e in ordered if e['group'] == 'CONTENT_CREDENTIALS')} 個；中繼憑證 {len(intermediates)} 個，可匯入的根憑證 {len(importable)} 個",
                   "- 檔案" + ("有變更" if changed else "沒有變更"),
                   *[f"- 新增：{e['name']}（{e['owner']}，SHA-256 {e['sha256']}）" for e in added],
                   *[f"- 移除：{n}（SHA-256 {fp}）" for fp, n in removed],
                   *[f"- 注意：{n}" for n in notes],
                   *[f"- 警告：{w}" for w in warnings], ""]

    if args.check:
        print("\n".join(report))
        return 1 if changed else 0
    if changed:
        open(KOTLIN, "w", encoding="utf-8").write(text)
    if config_changed:
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            f.write("\n")
    with open(SERVICES_LOCK, "w", encoding="utf-8") as f:
        json.dump(new_lock, f, ensure_ascii=False, indent=2)
        f.write("\n")
    out = "\n".join(report) + "\n"
    if args.report:
        open(args.report, "w", encoding="utf-8").write(out)
    print(out)
    return 2 if args.strict and warnings else 0


if __name__ == "__main__":
    sys.exit(main())

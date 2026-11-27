#!/usr/bin/env python3
"""Google Play store listing and releases (docs/google-play.md).

  check
      checks distribution/play/listing: every language has title.txt (30 characters at most), short_description.txt
      (80), full_description.txt (4,000) and, when it has release notes, header and footer with their placeholders
  publish --package PKG [--aab FILE --track TRACK --status STATUS] [--fraction F] [--mapping FILE] [--name NAME]
          [--whatsnew DIR] [--listing]
      one edit of Play's publishing API, committed at the end:
      --aab        the App Bundle. When Play already has a bundle with the same SHA-256, it is not uploaded again and
                   the release of the track is written again with that version code, so a run for the same version
                   only updates its release notes (and the listing).
      --whatsnew   DIR/whatsnew-<language> files (tools/release-notes.py --play-out); languages the store listing lacks
                   are left out, since Play refuses them.
      --listing    writes title, short and full description of every language of distribution/play/listing, and the
                   images of its images folder: phoneScreenshots/*.png replace all phone screenshots of that language,
                   featureGraphic.png and icon.png replace those images.

The service account key is read from the environment variable PLAY_SERVICE_ACCOUNT_JSON; its token is signed with the
openssl command, so only the Python standard library is needed.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

LISTING = pathlib.Path(__file__).resolve().parents[1] / "distribution/play/listing"
LIMITS = {"title.txt": 30, "short_description.txt": 80, "full_description.txt": 4000}
NOTES = {"release_notes_header.txt": "{version}", "release_notes_more.txt": "{count}", "release_notes_footer.txt": "{url}"}
API = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
UPLOAD = "https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/"
SCOPE = "https://www.googleapis.com/auth/androidpublisher"


def read(path):
    return path.read_text(encoding="utf-8").strip()


def languages():
    return sorted(d for d in LISTING.iterdir() if d.is_dir())


def check():
    errors = []
    for d in languages():
        for name, limit in LIMITS.items():
            f = d / name
            if not f.is_file():
                errors.append(f"{d.name}/{name}: missing")
            elif not read(f):
                errors.append(f"{d.name}/{name}: empty")
            elif len(read(f)) > limit:
                errors.append(f"{d.name}/{name}: {len(read(f))} characters, at most {limit}")
        present = [n for n in NOTES if (d / n).is_file()]
        if present and len(present) != len(NOTES):
            errors.append(f"{d.name}: release notes need all of {', '.join(NOTES)}")
        for name in present:
            if NOTES[name] not in read(d / name):
                errors.append(f"{d.name}/{name}: must contain {NOTES[name]}")
    for e in errors:
        print(e)
    print(f"{len(languages())} languages, {len(errors)} errors")
    return 1 if errors else 0


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def access_token():
    raw = os.environ.get("PLAY_SERVICE_ACCOUNT_JSON", "")
    if not raw:
        sys.exit("PLAY_SERVICE_ACCOUNT_JSON is not set")
    key = json.loads(raw)
    now = int(time.time())
    claims = {"iss": key["client_email"], "scope": SCOPE, "aud": key["token_uri"], "iat": now, "exp": now + 3600}
    signing_input = b64url(b'{"alg":"RS256","typ":"JWT"}') + "." + b64url(json.dumps(claims).encode())
    fd, pem = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(key["private_key"])
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", pem], input=signing_input.encode(),
                                   capture_output=True, check=True).stdout
    finally:
        os.remove(pem)
    body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "assertion": signing_input + "." + b64url(signature)}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(key["token_uri"], body), timeout=60) as r:
            return json.load(r)["access_token"]
    except urllib.error.HTTPError as e:
        sys.exit(f"service account token: HTTP {e.code}\n{e.read().decode(errors='replace')}")


class Play:
    def __init__(self, package):
        self.package = package
        self.token = access_token()
        self.edit = None

    def call(self, method, path, body=None, data=None, upload=False, timeout=120, content_type="application/octet-stream"):
        url = (UPLOAD if upload else API) + self.package + path
        headers = {"Authorization": "Bearer " + self.token}
        if data is not None:
            url += ("&" if "?" in url else "?") + "uploadType=media"
            headers["Content-Type"] = content_type
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read().decode()
        except urllib.error.HTTPError as e:
            sys.exit(f"{method} {path}: HTTP {e.code}\n{e.read().decode(errors='replace')}")
        return json.loads(text) if text.strip() else {}

    def in_edit(self, method, path, **kw):
        return self.call(method, f"/edits/{self.edit}{path}", **kw)


def publish(a):
    if a.aab and not (a.track and a.status):
        sys.exit("--aab needs --track and --status")
    if not a.aab and not a.listing:
        sys.exit("nothing to do: give --aab, --listing or both")
    play = Play(a.package)
    play.edit = play.call("POST", "/edits", body={})["id"]
    print(f"edit {play.edit}")

    if a.listing:
        for d in languages():
            play.in_edit("PUT", f"/listings/{d.name}", body={
                "language": d.name, "title": read(d / "title.txt"),
                "shortDescription": read(d / "short_description.txt"),
                "fullDescription": read(d / "full_description.txt")})
            print(f"listing {d.name} written")
            images = d / "images"
            shots = sorted((images / "phoneScreenshots").glob("*.png"))
            if shots:
                play.in_edit("DELETE", f"/listings/{d.name}/phoneScreenshots")
                for f in shots:
                    play.in_edit("POST", f"/listings/{d.name}/phoneScreenshots", data=f.read_bytes(), upload=True,
                                 content_type="image/png")
                print(f"listing {d.name}: {len(shots)} phone screenshots")
            for kind in ("featureGraphic", "icon"):
                f = images / f"{kind}.png"
                if f.is_file():
                    play.in_edit("DELETE", f"/listings/{d.name}/{kind}")
                    play.in_edit("POST", f"/listings/{d.name}/{kind}", data=f.read_bytes(), upload=True,
                                 content_type="image/png")
                    print(f"listing {d.name}: {kind}")

    if a.aab:
        aab = pathlib.Path(a.aab)
        digest = hashlib.sha256(aab.read_bytes()).hexdigest()
        bundles = play.in_edit("GET", "/bundles").get("bundles", [])
        same = next((b for b in bundles if b.get("sha256", "").lower() == digest), None)
        if same:
            code = same["versionCode"]
            print(f"version code {code} is already on Play with the same SHA-256: not uploaded again")
        else:
            code = play.in_edit("POST", "/bundles", data=aab.read_bytes(), upload=True, timeout=900)["versionCode"]
            print(f"bundle uploaded as version code {code}")
        if a.mapping:
            play.in_edit("POST", f"/apks/{code}/deobfuscationFiles/proguard",
                         data=pathlib.Path(a.mapping).read_bytes(), upload=True, timeout=300)
            print("R8 mapping uploaded")

        listed = {x["language"] for x in play.in_edit("GET", "/listings").get("listings", [])}
        notes = []
        for f in sorted(pathlib.Path(a.whatsnew).glob("whatsnew-*")) if a.whatsnew else []:
            language = f.name[len("whatsnew-"):]
            if language in listed:
                notes.append({"language": language, "text": read(f)})
            else:
                print(f"release notes {language} left out: the store listing has no {language}")
        release = {"versionCodes": [str(code)], "status": a.status, "releaseNotes": notes}
        if a.name:
            release["name"] = a.name
        if a.status == "inProgress":
            release["userFraction"] = float(a.fraction)
        play.in_edit("PUT", f"/tracks/{a.track}", body={"track": a.track, "releases": [release]})
        print(f"track {a.track}: version code {code}, {a.status}, release notes {', '.join(n['language'] for n in notes) or 'none'}")

    play.in_edit("POST", ":commit")
    print("edit committed")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    p = sub.add_parser("publish")
    p.add_argument("--package", required=True)
    p.add_argument("--aab")
    p.add_argument("--track")
    p.add_argument("--status", choices=["draft", "completed", "inProgress", "halted"])
    p.add_argument("--fraction")
    p.add_argument("--mapping")
    p.add_argument("--name")
    p.add_argument("--whatsnew")
    p.add_argument("--listing", action="store_true")
    a = ap.parse_args()
    if a.command == "check":
        sys.exit(check())
    if a.status == "inProgress" and not a.fraction:
        sys.exit("status inProgress needs --fraction")
    publish(a)


if __name__ == "__main__":
    main()

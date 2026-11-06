#!/usr/bin/env python3
"""Validate decoded resources and export readable HTML, manifests and shader text."""

import argparse
import base64
import csv
import gzip
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import struct
import subprocess
import xml.etree.ElementTree as ET
import zlib
import zipfile

from cryptography.hazmat.primitives import serialization
from fontTools.ttLib import TTFont

from resource_formats import art_metadata, art_profile, runtime_stages, spirv_summary


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.tags = []
        self.links = []
        self.scripts = 0
        self.heading = None
        self.headings = []
        self.title = ""

    def handle_starttag(self, tag, attributes):
        self.tags.append(tag)
        if tag in ("title", "h1", "h2", "h3"):
            self.heading = [tag, ""]
        if tag == "script":
            self.scripts += 1
        for name, value in attributes:
            if name in ("href", "src", "action"):
                self.links.append(dict(tag=tag, attribute=name, value=value))
        if tag in ("p", "li", "h1", "h2", "h3", "br", "div"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if self.heading and self.heading[0] == tag:
            if tag == "title":
                self.title = self.heading[1].strip()
            else:
                self.headings.append(self.heading[1].strip())
            self.heading = None
        if tag in self.tags:
            self.tags = self.tags[:len(self.tags) - 1 - self.tags[::-1].index(tag)]
        if tag in ("p", "li", "h1", "h2", "h3", "div"):
            self.text.append("\n")

    def handle_data(self, value):
        if self.heading:
            self.heading[1] += value
        if not any(tag in self.tags for tag in ("style", "script", "head")):
            self.text.append(value)


class MessageReader:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def take(self, size):
        result = self.data[self.position:self.position + size]
        if len(result) != size:
            raise ValueError("Truncated StandardMessageCodec data")
        self.position += size
        return result

    def size(self):
        value = self.take(1)[0]
        return struct.unpack("<H" if value == 254 else "<I", self.take(2 if value == 254 else 4))[0] if value >= 254 else value

    def read(self):
        tag = self.take(1)[0]
        if tag == 0:
            return None
        if tag in (1, 2):
            return tag == 1
        if tag in (3, 4):
            return struct.unpack("<i" if tag == 3 else "<q", self.take(4 if tag == 3 else 8))[0]
        if tag == 6:
            self.position += -self.position % 8
            return struct.unpack("<d", self.take(8))[0]
        if tag in (5, 7):
            value = self.take(self.size()).decode("utf-8")
            return int(value, 16) if tag == 5 else value
        if tag == 12:
            return [self.read() for _ in range(self.size())]
        if tag == 13:
            result = {}
            for _ in range(self.size()):
                key = self.read()
                result[key] = self.read()
            return result
        raise ValueError("Unsupported StandardMessageCodec tag: " + str(tag))


def profiles(root, out, apk=None):
    results = []
    for name, magic, offset in (("baseline.prof", b"pro\x00010\x00", 17), ("baseline.profm", b"prm\x00002\x00", 18)):
        data = (root / "dexopt" / name).read_bytes()
        assert data[:8] == magic
        start = 9 if name.endswith(".prof") else 10
        expected, compressed = struct.unpack_from("<II", data, start)
        assert len(data) == offset + compressed
        body = zlib.decompress(data[offset:])
        assert len(body) == expected
        (out / (name + ".body.bin")).write_bytes(body)
        parsed = (art_profile if name.endswith(".prof") else art_metadata)(data)
        write_json(out / (name + ".json"), parsed)
        if name.endswith(".prof"):
            with (out / "baseline-methods.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["dex_key", "method_index", "flags", "hot", "startup", "post_startup"])
                writer.writeheader()
                for dex in parsed["dexes"]:
                    for method in dex["methods"]:
                        writer.writerow(dict(dex_key=dex["dex_key"], **method))
            if apk:
                with zipfile.ZipFile(apk) as package:
                    for dex in parsed["dexes"]:
                        value = package.read(dex["dex_key"])
                        checksum = struct.unpack_from("<I", value, 8)[0]
                        if checksum != zlib.adler32(value[12:]) & 0xffffffff:
                            raise ValueError("APK DEX checksum is invalid")
                        dex["apk_dex_comparison"] = dict(
                            apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
                            dex_sha256=hashlib.sha256(value).hexdigest(), apk_dex_checksum=checksum,
                            profile_dex_checksum=dex["dex_checksum"], checksum_matches=checksum == dex["dex_checksum"],
                            apk_method_id_count=struct.unpack_from("<I", value, 88)[0],
                            method_names_resolved=False,
                            reason="Method names are not mapped without an exact matching DEX checksum.",
                        )
                write_json(out / (name + ".json"), parsed)
        results.append(dict(file=name, format=magic[4:7].decode(), decompressed_bytes=len(body),
                            dex_count=data[8] if start == 9 else struct.unpack_from("<H", data, 8)[0],
                            decompressed_sha256=hashlib.sha256(body).hexdigest(),
                            structures_consumed_bytes=parsed["consumed_bytes"], structured_output=name + ".json",
                            dex_summaries=[{key: value for key, value in dex.items() if key not in ("methods", "class_indices", "inline_caches")} for dex in parsed["dexes"]]))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Decoder output directory")
    parser.add_argument("--apk", type=Path, help="Compare ART profile checksums to this APK's DEX")
    parser.add_argument("--spirv-dis", type=Path, help="Optional SPIRV-Tools disassembler executable")
    parser.add_argument("--spirv-val", type=Path, help="Optional SPIRV-Tools validator executable")
    args = parser.parse_args()
    root = args.root / "decoded/assets"
    out = args.root / "readable"
    out.mkdir(exist_ok=False)
    results = {}
    for path in sorted(root.glob("*.html")):
        page = Page()
        source = path.read_text("utf-8")
        assert source.lstrip().lower().startswith("<!doctype html>")
        page.feed(source)
        page.close()
        text = "\n".join(line.strip() for line in "".join(page.text).splitlines() if line.strip()) + "\n"
        (out / (path.stem + ".txt")).write_text(text, encoding="utf-8")
        results[path.name] = dict(title=page.title, headings=page.headings, scripts=page.scripts, links=page.links,
                                  text_urls=sorted(set(re.findall(r"https?://[^\s<>\"']+", text))))
    for path in sorted(root.rglob("*.json")):
        value = json.loads(path.read_text("utf-8"))
        write_json(out / path.name, value)
        results[path.name] = dict(valid_json=True, members=list(value) if isinstance(value, dict) else len(value))
        if path.name == "loading_page.json":
            results[path.name].update(kind="Lottie animation", width=value["w"], height=value["h"], frames_per_second=value["fr"],
                                      seconds=(value["op"] - value["ip"]) / value["fr"], layers=len(value["layers"]), embedded_assets=value["assets"])
    reader = MessageReader((root / "flutter_assets/AssetManifest.bin").read_bytes())
    manifest = reader.read()
    assert reader.position == len(reader.data)
    write_json(out / "AssetManifest.json", manifest)
    results["AssetManifest.bin"] = dict(kind="Flutter StandardMessageCodec", content=manifest)
    notices = gzip.decompress((root / "flutter_assets/NOTICES.Z").read_bytes())
    text = notices.decode("utf-8")
    (out / "NOTICES.txt").write_bytes(notices)
    results["NOTICES.Z"] = dict(kind="gzip-compressed UTF-8 license notices", decompressed_bytes=len(notices), lines=len(text.splitlines()))
    for path in sorted(root.rglob("*")):
        if path.suffix not in (".otf", ".ttf"):
            continue
        with TTFont(path, checkChecksums=2) as font:
            for name in font.keys():
                if name != "GlyphOrder":
                    font[name]
            info = dict(family=font["name"].getDebugName(1), glyph_count=len(font.getGlyphOrder()), tables=list(font.keys()),
                        unicode_characters={str(code): glyph for code, glyph in font.getBestCmap().items()})
            xml = out / (path.name + ".ttx")
            font.saveXML(str(xml), disassembleInstructions=True)
        document = ET.parse(xml)
        assert document.getroot().tag == "ttFont"
        assert len(document.getroot().findall("GlyphOrder/GlyphID")) == info["glyph_count"]
        info["full_table_xml"] = xml.name
        info["full_table_xml_sha256"] = hashlib.sha256(xml.read_bytes()).hexdigest()
        write_json(out / (path.name + ".json"), info)
        results[path.name] = {name: value for name, value in info.items() if name != "unicode_characters"}
    for path in sorted(root.rglob("*.frag")):
        data = path.read_bytes()
        bundle, programs = runtime_stages(data)
        shader_dir = out / "shaders" / path.stem
        shader_dir.mkdir(parents=True)
        for stage in bundle["stages"]:
            backend = stage["backend"]
            extension = {"vulkan": ".spv", "sksl": ".sksl", "metal": ".metal"}.get(backend, ".glsl")
            destination = shader_dir / (backend + extension)
            destination.write_bytes(programs[backend])
            stage["file"] = str(destination.relative_to(out))
            if backend == "vulkan":
                stage["spirv"] = spirv_summary(programs[backend])
                if args.spirv_dis:
                    disassembly = shader_dir / "vulkan.spvasm"
                    subprocess.run([str(args.spirv_dis), str(destination), "-o", str(disassembly)], check=True, capture_output=True)
                    stage["spirv"]["disassembly"] = str(disassembly.relative_to(out))
                if args.spirv_val:
                    validation = subprocess.run([str(args.spirv_val), "--target-env", "vulkan1.1", str(destination)], capture_output=True, text=True)
                    stage["spirv"]["validation"] = dict(target="vulkan1.1", returncode=validation.returncode, stdout=validation.stdout, stderr=validation.stderr)
                    if validation.returncode:
                        raise ValueError("SPIR-V validation failed: " + validation.stderr)
            else:
                programs[backend].decode("utf-8")
        write_json(shader_dir / "reflection.json", bundle)
        results[path.name] = dict(kind="Flutter IPLR shader bundle", **bundle)
    for name in ("dwapp201i_public", "dwapp201i_public.txt"):
        text = "".join((root / name).read_text("utf-8").split()).encode("ascii")
        key = serialization.load_der_public_key(base64.b64decode(text, validate=True))
        (out / (name + ".pem")).write_bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        results[name] = dict(curve=key.curve.name, normalized_text_sha256=hashlib.sha256(text).hexdigest())
    assert results["dwapp201i_public.txt"]["normalized_text_sha256"] == "dfbbc7e88f69844fe449aca4f02ce1d719ddaaad9e3fd9dc25f1934869bc5a82"
    results["dexopt"] = profiles(root, out, args.apk)
    write_json(out / "analysis.json", results)
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

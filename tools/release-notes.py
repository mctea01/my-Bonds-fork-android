#!/usr/bin/env python3
"""Writes the body of a GitHub release (nightly or stable) in Markdown.

The download guide comes once, at the top: GitHub lists the files themselves below the body, so a reader sees which
file to take, then the changes, then the file list. Only files present in --dir are named, so the guide never points
at a file that is missing. The changes are the commit subjects since the previous stable tag (v*), with dependency
updates folded away.

  python3 -I tools/release-notes.py --channel nightly --version 0.5.3 --tag nightly --dir dist > notes.md
  python3 -I tools/release-notes.py --channel stable --version 0.5.3 --tag v0.5.3 --dir dist > notes.md
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys

MAX_CHANGES = 100
BOTS = ("renovate[bot]", "dependabot[bot]", "github-actions[bot]")


def git(*args):
    run = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8")
    return run.stdout.strip() if run.returncode == 0 else ""


def size(path):
    return f"{path.stat().st_size / 1_000_000:.0f} MB"


def changes(channel):
    """(range description, compare base, lines of features, lines of dependency updates, truncated)."""
    head = "HEAD^" if channel == "stable" else "HEAD"
    previous = git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", head)
    if previous:
        rev_range = f"{previous}..HEAD"
        title = f"{previous} 以來的變更"
    else:
        base = git("log", "-G^version=", "-1", "--format=%H", "--", "version.properties")
        rev_range = f"{base}^..HEAD" if base and git("rev-parse", "-q", "--verify", f"{base}^") else "HEAD"
        title = "這個版本線以來的變更"
    log = git("log", "--no-merges", "--format=%an%x1f%s", rev_range)
    features, deps = [], []
    for entry in log.splitlines():
        author, _, subject = entry.partition("\x1f")
        (deps if author in BOTS else features).append(f"- {subject}")
    truncated = len(features) > MAX_CHANGES
    return title, previous, features[:MAX_CHANGES], deps, truncated


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--channel", choices=["nightly", "stable"], required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "mctea01/my-Bonds-fork-android"))
    a = ap.parse_args()

    files = {p.name: p for p in sorted(pathlib.Path(a.dir).iterdir()) if p.is_file()}
    v = a.version
    base_url = f"https://github.com/{a.repo}/releases/download/{a.tag}/"

    def link(name):
        return f"[{name}]({base_url}{name})（{size(files[name])}）" if name in files else None

    def first(*names):
        return next((link(n) for n in names if n in files), None)

    out = []
    sha = git("rev-parse", "--short", "HEAD")
    if a.channel == "stable":
        out.append(f"**DIW MY WALLET {v}** 穩定版（commit `{sha}`）。")
    else:
        out.append(
            f"**DIW MY WALLET {v}** 測試版：main 的自動建置（commit `{sha}`），每次更新 main 都會取代。"
            f"一般使用請改裝[最新穩定版](https://github.com/{a.repo}/releases/latest)。"
        )
    out += ["", "## 下載哪個檔案", "", "| 你的裝置 | 下載 | 說明 |", "|---|---|---|"]
    rows = [
        ("Android 手機（大多數）", link(f"DIW-MY-WALLET-{v}-arm64-v8a.apk"), "Android 10 以上的 64 位元 ARM 手機"),
        ("Android 模擬器、x86 平板", link(f"DIW-MY-WALLET-{v}-x86_64.apk"), ""),
        ("不確定是哪一種 Android", link(f"DIW-MY-WALLET-{v}.apk"), "通用版，含所有架構，檔案較大"),
        ("Windows 10、11", first(*[n for n in files if n.endswith(".msi")]), "安裝檔，內含 Java，不需要系統管理員權限"),
        ("Linux x86_64", first(*[n for n in files if n.endswith(".AppImage")]),
         "AppImage，內含 Java，不需安裝：`chmod +x 檔名.AppImage` 後執行"),
        ("macOS（Apple 晶片）", first(*[n for n in files if n.startswith("DIW-MY-WALLET-macos-")]),
         "先安裝 Java 21，以 `java -jar 檔名.jar` 執行"),
        ("其他已安裝 Java 21 的電腦",
         " ".join(x for x in (first(*[n for n in files if n.startswith("DIW-MY-WALLET-linux-")]),
                              first(*[n for n in files if n.startswith("DIW-MY-WALLET-windows-")])) if x) or None,
         "依作業系統選擇，以 `java -jar` 執行"),
    ]
    out += [f"| {who} | {what} | {note} |" for who, what, note in rows if what]
    out += [
        "",
        "Android 第一次安裝時，要允許瀏覽器或檔案管理員「安裝不明應用程式」。新版可以直接覆蓋安裝，資料會保留；"
        "debug 版與一般版簽章不同，不能互相覆蓋，要先移除。零知識證明只支援 64 位元裝置。"
        "使用方式見 [README](https://github.com/" + a.repo + "#readme)。",
        "",
    ]

    native = [
        (f"DIW-MY-WALLET-{v}-windows-x64-native.zip", "Windows 10、11 x64：解壓後執行 `diw-desktop.exe`"),
        (f"DIW-MY-WALLET-{v}-linux-x64-native.tar.gz", "Linux x86_64：解壓後執行 `diw-desktop`，需要與建置主機（GitHub ubuntu-latest）同樣新或更新的系統"),
    ]
    rows = [(link(n), what) for n, what in native if n in files]
    if rows:
        out += ["<details><summary>實驗版：原生執行檔（不需要 Java，啟動較快）</summary>", "",
                "GraalVM 編成的原生執行檔，尚在實驗，問題請以上方的安裝檔為準；不需要安裝，資料與安裝版共用（兩者不能同時開啟）。", "",
                "| 檔案 | 說明 |", "|---|---|"]
        out += [f"| {f} | {what} |" for f, what in rows]
        out += ["", "</details>", ""]

    others = [
        (f"DIW-MY-WALLET-{v}.apks", "分割 APK 組（與 Google Play 相同的分割），用 `bundletool install-apks` 或 SAI 安裝"),
        (f"DIW-MY-WALLET-{v}.aab", "Google Play 用的 App Bundle，不能直接安裝"),
        (f"DIW-MY-WALLET-{v}-mapping.txt", "R8 mapping，與 AAB 一起上傳 Google Play 以還原當機記錄"),
        (f"DIW-MY-WALLET-{v}-debug.apk", "測試建置：未最佳化，允許連到區網測試伺服器的 HTTP"),
        (f"DIW-MY-WALLET-{v}-debug.aab", "測試建置的 App Bundle"),
        ("zk-templates.jwt", "零知識證明版型包，App 會自己下載，不必手動下載"),
    ]
    rows = [(link(n), what) for n, what in others if n in files]
    if rows:
        out += ["<details><summary>其他檔案（開發、測試與上架用）</summary>", "", "| 檔案 | 用途 |", "|---|---|"]
        out += [f"| {f} | {what} |" for f, what in rows]
        out += ["", "</details>", ""]
    out += ["每個檔案的 SHA-256 列在本頁最下方的檔案清單。", ""]

    title, previous, features, deps, truncated = changes(a.channel)
    out += [f"## {title}", ""]
    out += features or ["- 沒有功能變更"]
    if truncated:
        out.append(f"- 只列出最近 {MAX_CHANGES} 項")
    if deps:
        out += ["", f"<details><summary>相依套件更新（{len(deps)} 項）</summary>", "", *deps, "", "</details>"]
    if previous:
        target = a.tag if a.channel == "stable" else sha
        out += ["", f"完整差異：[{previous}...{target}](https://github.com/{a.repo}/compare/{previous}...{target})"]
    out.append("")
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()

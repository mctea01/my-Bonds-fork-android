# TWDIW 1.0.14 assets 還原與內容解析

對已核對的 1.0.14 APK 資產，離線重現 `JcPQWBA` reader。程式不安裝 APK、不執行 JNI、不連網。所有資產保留原始 bytes；兩個私鑰資產保留密文，不執行私鑰解碼或簽署。

`decode_assets.py` 掃描指定資料夾的每個 APK，依資產相對名稱的 Java FNV 雜湊查 stage-b 的 seed／algorithm 表，先移除 `VVcmSog7` 外層，再重現三種 reader：

- 0：`ua7zwMYm`，8-round Blowfish 變體，CBC，僅展開 P-array。
- 2：`WNTdXCgQ`，10-round Rijndael／AES 變體，自訂列置換，ECB。
- 3：`VoUJXo4w`，16-round TEA 變體，signed-short delta `-25033`，CBC。

依 reader 驗證各 block padding。dexopt 的兩個 profile 未加密，直接保留。

## 重現

需要本次 APK 分包與既有 JADX 主 DEX／stage-b 匯出。`--jadx-main` 須含 `o/jHzEsshZ.java`，`--jadx-stage-b` 須含 `o/JcPQWBA.java`；前者提供 Blowfish 初始表，後者提供資產映射。下載包的 `evidence/jadx-main` 與 `evidence/jadx-stage-b` 也附有這兩份定位來源。

```bash
python -m pip install -r tools/twdiw-assets/requirements.txt
python tools/twdiw-assets/decode_assets.py \
  --apk-dir /workspace/scratch/twdiw-apkcube-splits \
  --jadx-main /workspace/scratch/twdiw-jadx-simple/sources \
  --jadx-stage-b /workspace/scratch/twdiw-b-jadx/sources \
  --out /tmp/twdiw-assets-new
python tools/twdiw-assets/analyze_assets.py /tmp/twdiw-assets-new
```

輸出根目錄及 readable 子目錄須尚未存在，避免覆寫前次結果。

可加 `--apk /path/to/base.apk` 比對 ART profile 與 DEX checksum；加 `--spirv-dis /path/to/spirv-dis --spirv-val /path/to/spirv-val` 產生 SPIR-V 文字反組譯與外部驗證結果。SPIRV-Tools 是選用的外部工具，不由 Python requirements 安裝。

## 產物

- `raw/<apk>/assets/`：所有原始資產，包含未解碼的私鑰密文。
- `decoded/assets/`：15 份解碼後的非私鑰資源與 2 份原本未加密的 dexopt profiles。
- `manifest.json`：每個資產的來源、名稱雜湊、reader 類型、原始／還原大小及 SHA-256、狀態。
- `readable/`：4 份 HTML 的純文字、JSON 格式的 Flutter AssetManifest、pretty JSON、解壓的 NOTICES、兩個公鑰 PEM、完整字型 TTX／字碼對照、shader 各後端 program／reflection／選用 SPIR-V 反組譯，以及 profile 解壓資料／結構 JSON／方法旗標 CSV。
- `readable/analysis.json`：HTML 標題／scripts／連結、動畫參數、公鑰指紋與各類解析紀錄。

`analyze_assets.py` 以 UTF-8／JSON／Flutter StandardMessageCodec 解析文字與清單，驗證 gzip／zlib CRC 與解壓長度、以 fontTools 完整載入字型 tables 並匯出 XML，以 cryptography 匯入公鑰並核對既有 `.txt` 公鑰指紋。`resource_formats.py` 依 version 1 FlatBuffer schema 拆分 IPLR 所有已定義欄位與後端 program，並解析 ART 010／002 的 hot methods、inline caches、class deltas 及方法旗標 bitmaps。索引 JSON 精確消耗解壓輸入；checksum 不符時不猜方法名稱。

```bash
python -m unittest discover -s tools/twdiw-assets -p 'test_*.py' -v
```

`dwapp201i_public` 與 `dwapp201i_public.txt` 是兩把不同的公鑰。只有 `.txt` reader 已綁定目前研究的 `dwapp-201i` keyId；本工具沒有以私鑰確認任何配對。

完整結果見 [資產解析報告](../../docs/research/twdiw-1.0.14/twdiw-1.0.14-assets.md)。原始第三方資源及 reader 定位匯出屬分析資料，不放入 repo 原始碼或當成本專案的美術／字型資產使用。

逐層算法、每檔流程、shader schema 版本及 ART checksum 限制見 [資產解碼說明](../../docs/research/twdiw-1.0.14/twdiw-1.0.14-asset-decoding-guide.md)。

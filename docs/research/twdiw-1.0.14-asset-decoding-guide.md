# TWDIW 1.0.14 資產解碼說明與格式解析

日期：2026-11-03。對應 APK：base.apk SHA-256 `0df9fb52206747cb2e4df2985c34e91f7203390c7d31ccd3b6b62c99ae4d383d`。本文件補足 [完整 assets 報告](twdiw-1.0.14-assets.md) 的逐層解碼說明，以及 shader、字型、ART profiles 的進一步解析。

19 個原始資產全部保留；其中 15 個非私鑰資產已解碼，2 個原本未加密的 profiles 已完整解析其索引結構。兩個應用簽章私鑰資產只保留密文及來源資訊，不交付可用的官方簽章私鑰。本包不能稱為「19 個資產全部解密」。

## 一、如何由資產路徑找到 reader

stage-b 的 `o.JcPQWBA.ISyARpnL(AssetManager, String)` 是共用 reader。它對移除 `assets/` 前綴的完整相對路徑計算 Java 實作的 FNV 雜湊，再查 seed 與 reader selector 兩張表。

```text
assets/privacy_contract.html
              ↓ 移除 assets/
privacy_contract.html
              ↓ UTF-8；Java byte 保留 signed 行為
FNV 初值 2166136261
h = ((h XOR signed_byte) × 16777619) mod 2^32
              ↓ 將結果解讀為 signed int32
727129305
              ↓ 查 JcPQWBA 的兩張表
外層 PCG seed + selector 0
```

路徑包含子目錄與大小寫；不能只取 basename。這裡的名稱雜湊是選擇 reader 用的索引，不是內容完整性雜湊。交付包另以 SHA-256 核對檔案。

### 外層 `VVcmSog7`

這層使用各檔案的 seed 初始化 PCG 狀態，對輸入每 8 bytes 的第 1 byte 做 XOR，其餘 7 bytes 保留。狀態更新保留 Java long 的 64-bit overflow；輸出旋轉保留 unsigned shift 與 32-bit 截斷。

```text
increment = ((global_parameter << 1) | 1) mod 2^64
state = 0
step()
state = (state + per_asset_seed) mod 2^64
step()
每 8 bytes：block[0] ^= low8(step())

step 的狀態更新：
state = (old_state × 6364136223846793005 + increment) mod 2^64
```

`step()` 的輸出由 old_state 經 xor／unsigned shift／rotate 得到，精確實作見 `decode_assets.py:outer`。不能只做外層 XOR 就把剩餘內容當成文字。

### 內層三種 reader

| selector | 類別與處理 | 要注意的細節 |
|---|---|---|
| 0 | `ua7zwMYm`／`jHzEsshZ`；8-round Blowfish 變體、64-bit block、CBC | P-array 展開但不展開 S-box；不是直接套用標準完整輪數的 Blowfish；block words 為 big-endian |
| 2 | `WNTdXCgQ`／`YHqZjOUd`／`Z93PHtg`；10-round Rijndael 變體、128-bit block、ECB | 先依位元遮罩轉換 reader key；row permutation 由 `0x7887e11e` 分組取得，與標準 AES ShiftRows 不同 |
| 3 | `VoUJXo4w`；16-round TEA 變體、64-bit block、CBC | delta 是 Java signed-short `-25033`，不是標準 TEA 的 32-bit delta；兩個 word 保留 32-bit overflow |

實際常數由本版本 reader 匯出與工具程式保存；它們是特定版本的實作資料，不是一般 APK 通用格式。工具還額外檢查 PKCS-style padding 的範圍與每個 byte 是否一致；原 reader 末端主要依最後一個 byte 決定輸出長度。

## 二、每個資產的解碼與可讀產物

表中 B／R／T 分別表示 selector 0、2、3；受保護資源皆先通過上述 PCG 外層。

| assets/ 相對路徑 | 還原步驟 | 可讀結果／格式驗證 |
|---|---|---|
| `privacy_contract.html` | PCG → B → UTF-8 | 中文 HTML、純文字，完整 HTML 保留 inline CSS |
| `privacy_contract_en.html` | PCG → T → UTF-8 | 英文 HTML、純文字 |
| `use_agreement_contract.html` | PCG → B → UTF-8 | 中文 HTML、純文字 |
| `use_agreement_contract_en.html` | PCG → R → UTF-8 | 英文 HTML、純文字 |
| `loading_page.json` | PCG → T → UTF-8 → JSON | 完整 Lottie 動畫資料與 pretty JSON；375×180、60 fps、5 秒、5 layers |
| `flutter_assets/AssetManifest.bin` | PCG → R → StandardMessageCodec | 轉 `AssetManifest.json`，檢查 parser 消耗全部 117 bytes |
| `flutter_assets/FontManifest.json` | PCG → B → UTF-8 → JSON | 兩個 font family 與字型路徑 |
| `flutter_assets/NativeAssetsManifest.json` | PCG → T → UTF-8 → JSON | version `[1,0,0]`、native-assets 空物件 |
| `flutter_assets/NOTICES.Z` | PCG → R → gzip → UTF-8 | 完整 `NOTICES.txt`，1,350,124 bytes；gzip CRC 檢查 |
| `flutter_assets/fonts/MaterialIcons-Regular.otf` | PCG → R → OTF parser | 原 OTF、8661 glyphs 的字碼資料與完整 `MaterialIcons-Regular.otf.ttx` |
| `flutter_assets/packages/cupertino_icons/assets/CupertinoIcons.ttf` | PCG → T → TTF parser | 原 TTF、1257 glyphs 的字碼資料與完整 `CupertinoIcons.ttf.ttx` |
| `flutter_assets/shaders/ink_sparkle.frag` | PCG → T → IPLR FlatBuffer | 4 個 backend 的 reflection／shader；文字來源、SPIR-V binary 與反組譯 |
| `flutter_assets/shaders/stretch_effect.frag` | PCG → R → IPLR FlatBuffer | 同上 |
| `dwapp201i_public` | PCG → B → UTF-8 → 去空白 → Base64 → DER SPKI | P-256 公鑰 PEM、正規化文字摘要 |
| `dwapp201i_public.txt` | PCG → B → UTF-8 → 去空白 → Base64 → DER SPKI | 另一把 P-256 公鑰；目前 dwapp-201i 成功路徑對應此檔的文字摘要 |
| `dexopt/baseline.prof` | 原始 ART 010 → zlib → profile parser | header、hot method deltas、inline caches、class indices、startup／post-startup bitmaps，輸出 JSON／CSV |
| `dexopt/baseline.profm` | 原始 ART metadata 002 → zlib → metadata parser | profile index、dex key、type-id count、class deltas，輸出 JSON |
| `dwapp201i_private` | 原始密文保留 | 96 bytes；沒有明文私鑰或配對驗證結果 |
| `dwapp201i_private.txt` | 原始密文保留 | 192 bytes；沒有明文私鑰或配對驗證結果 |

兩個公鑰的正規化文字 SHA-256 分別為 `38bbe4d0…e36ee7` 與 `dfbbc7e8…5a82`；完整值見原報告。不可互相替代，也不能由檔名推定正式／測試環境。

## 三、HTML、JSON 與 Flutter 清單

HTML 是完整還原的文件，不需要執行瀏覽器或 JavaScript 才能讀取。原 HTML 保留樣式；額外純文字版本去除 style／script 內容並保留正文。4 份 HTML 均無 script tag 及 href／src／action 資源引用；正文中的網站文字另列於 `analysis.json`。

Lottie 的原始 JSON 完整保留動畫 keyframes、shapes 與 layers，另輸出縮排版本；它沒有外掛 images/assets。`FontManifest.json` 與 `NativeAssetsManifest.json` 同樣以完整 JSON 解析，不是只擷取字串。

`AssetManifest.bin` 使用 Flutter StandardMessageCodec。本檔出現 Map、List 與 String；parser 依 type tag 及可變長度欄位解出一筆 CupertinoIcons asset 記錄，最後核對讀取位置恰好等於輸入長度。這份清單不是 APK 全部 assets 的目錄，不能用它取代 ZIP 掃描。

## 四、字型完整 TTX

除了保留可直接使用字型檢視器開啟的 OTF／TTF，新增所有 font tables 的 XML 匯出：

- `readable/MaterialIcons-Regular.otf.ttx`：包含 8661 glyphs，約 9.18 MB。
- `readable/CupertinoIcons.ttf.ttx`：包含 1257 glyphs，約 3.28 MB。

fontTools 完整載入各 table、檢查 checksum，匯出 TTX 後再以 XML parser 驗證 `ttFont` 與 GlyphOrder 的數量。字型原檔、字碼對照與 XML 同時保留，不把字型 binary 強行當成一般文字。TTX 不是原作者的設計工程檔。

## 五、shader 完整後端拆分

本輪不再靠連續 ASCII 搜尋決定 shader 邊界，而是依 Flutter RuntimeStages **format version 1** 的 FlatBuffer schema 解析 table／vtable／uoffset／vector。

schema 交叉來源為 Flutter `3.41.0` tag 的 `runtime_stage_types.fbs`，其 version 與這兩份 bundle 一致。這是格式核對，不是據此斷言 App 精確使用 Flutter 3.41.0。新 master schema 已是 version 2，不能直接套用其中變動的 uniform 欄位位置。

每份 bundle 都有：

- `sksl.sksl`：完整 UTF-8 SkSL。
- `opengles.glsl`：GLSL ES 100。
- `opengles3.glsl`：GLSL ES 300。
- `vulkan.spv`：原始 SPIR-V 1.3。
- `vulkan.spvasm`：SPIRV-Tools 的文字反組譯。
- `reflection.json`：stage、entrypoint、uniform 名稱／location／binding／type／尺寸、輸入欄位、program offsets、長度與雜湊。

兩份 bundle 的 metal 欄位本來就沒有值，不是解碼失敗。都是 fragment stage。ink_sparkle 的 SPIR-V 為 5588 bytes、285 instructions；stretch_effect 為 3068 bytes、204 instructions。兩者均通過 `spirv-val --target-env vulkan1.1`，回傳碼 0；SPIR-V parser 也核對所有 instruction word count 與檔尾邊界。未進一步將 SPIR-V 偽還原成作者原始 GLSL。

## 六、ART profiles 完整索引結構

`baseline.prof` 解壓後 18,091 bytes，parser 精確消耗全部資料：

- dex key：`classes.dex`，method-id count 50,910。
- hot region 4,840 bytes；本檔 inline cache 數為 0。
- 248 個 class indices，以 uint16 delta 還原。
- 1,329 個帶旗標的方法索引；HOT 1,210、STARTUP 1,208、POST_STARTUP 1,329，旗標可以同時存在。
- 方法旗標的兩張 bitmap 是先整段 STARTUP、再整段 POST_STARTUP，不是每個方法交錯存兩個 bit。

`baseline.profm` 解壓後 517 bytes，輸出 profile index、dex key、10,371 個 type IDs 的總數及 248 個 class indices。metadata 的 class 索引與 P-format profile 的 class 索引保留各自語意，不假定兩組數字必須相同。

新增 `baseline.prof.json`、`baseline.profm.json` 與 `baseline-methods.csv`。兩個原始 profile 及解壓 `.body.bin` 仍保留。

**方法名稱對照限制**：profile 記錄的 DEX checksum 為 `0x7c4e3d7e`，APK `classes.dex` 為 `0x9aebae35`。APK DEX 的 Adler-32 自身核對正確，但與 profile 不同。雖然 method-id count 相同，仍不足以保證索引指向同一方法，因此沒有把這些索引強行套上現有 DEX 方法名稱。JSON 中明列 `checksum_matches=false`、`method_names_resolved=false`；完整索引解析已完成，名稱關聯仍未驗證。

## 七、重現與驗證

工具：`tools/twdiw-assets/decode_assets.py`、`analyze_assets.py`、`resource_formats.py`。需要 Python、cryptography、fontTools；SPIR-V 文字反組譯與外部驗證另需 SPIRV-Tools。

```bash
python -m pip install -r tools/twdiw-assets/requirements.txt
python tools/twdiw-assets/decode_assets.py \
  --apk-dir /path/to/apk-splits \
  --jadx-main evidence/jadx-main \
  --jadx-stage-b evidence/jadx-stage-b \
  --out /tmp/twdiw-assets-reproduced
python tools/twdiw-assets/analyze_assets.py /tmp/twdiw-assets-reproduced \
  --apk /path/to/apk-splits/base.apk \
  --spirv-dis /path/to/spirv-dis \
  --spirv-val /path/to/spirv-val
python -m unittest discover -s tools/twdiw-assets -p 'test_*.py' -v
```

輸出路徑須尚未存在。省略兩個 SPIRV-Tools 參數時仍會拆出原始 program、reflection 與 SPIR-V 結構摘要，但不會產生外部反組譯／驗證結果。

5 項測試涵蓋 profile delta 與 bitmap、metadata 索引、壓縮區截斷／尾隨資料、FlatBuffer optional 欄位／版本及越界、SPIR-V instruction 長度錯誤。實際 19 個資產也重新執行完整解碼與格式驗證，已還原資產與 v1 的 SHA-256 逐一相同。

新版交付包 `/workspace/scratch/twdiw-all-assets-1.0.14-v2.zip` 包含上述全部產物、工具、reader／schema 定位與來源雜湊，以及 `SHA256SUMS`。讀取公開 Flutter／AndroidX 格式參考及 SPIRV-Tools 套件使用了網路；沒有執行 APK／JNI，也沒有向 TWDIW 服務發出請求。

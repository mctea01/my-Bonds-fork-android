# TWDIW 1.0.14：完整 assets 清單與內容還原

日期：2026-11-03。使用者要求分析 `assets/` 全部資產，包含 HTML 與其他內容。本輪掃描已核對官方簽章的 **27 個 APK**；所有 assets 都在 base.apk，其他分包沒有 assets 項目。

base.apk SHA-256：`0df9fb52206747cb2e4df2985c34e91f7203390c7d31ccd3b6b62c99ae4d383d`。共 **19 檔**：15 個非私鑰資產成功解碼，2 個原本未加密的 ART profiles 已辨識並解壓，2 個私鑰資產保留原始密文。這是完整資產盤點，不表示已解出全部金鑰。沒有執行 APK／JNI、私鑰解碼、簽署或網路請求。

後續 v2 已進一步將字型全部 tables 匯出 TTX，依 FlatBuffer schema 拆分 shader 的完整後端與 reflection、反組譯及驗證 SPIR-V，並完整展開 ART profiles 的方法／class 索引與旗標。方法名稱因 DEX checksum 不符仍未關聯。逐層說明與最新版交付見 [資產解碼說明](twdiw-1.0.14-asset-decoding-guide.md)；下文記錄的 v1 原始產物維持不變。

## 全部資產

以下路徑皆相對於 `assets/`，大小為原始 bytes → 解碼後 bytes；profile 大小不含額外的解壓衍生物。

| 路徑 | 大小 | 內容與處理 |
|---|---:|---|
| `dexopt/baseline.prof` | 3228 → 3228 | ART profile 010；zlib 解壓 18,091 bytes、1 dex |
| `dexopt/baseline.profm` | 365 → 365 | ART metadata 002；zlib 解壓 517 bytes、1 dex |
| `dwapp201i_private` | 96 | 保留原始密文，未解碼 |
| `dwapp201i_private.txt` | 192 | 保留原始密文，未解碼 |
| `dwapp201i_public` | 128 → 125 | Base64 SPKI 公鑰文字，已解析 P-256 |
| `dwapp201i_public.txt` | 128 → 125 | Base64 SPKI 公鑰文字，已解析 P-256；去空白後 124 bytes |
| `flutter_assets/AssetManifest.bin` | 128 → 117 | StandardMessageCodec，已轉 JSON；只有 CupertinoIcons 的 asset 記錄 |
| `flutter_assets/FontManifest.json` | 216 → 208 | JSON；MaterialIcons 與 CupertinoIcons 兩個 family |
| `flutter_assets/NOTICES.Z` | 107216 → 107208 | gzip；再解壓得 1,350,124 bytes UTF-8、31,366 行授權聲明 |
| `flutter_assets/NativeAssetsManifest.json` | 48 → 45 | format-version `[1,0,0]`；native-assets 為空物件 |
| `flutter_assets/fonts/MaterialIcons-Regular.otf` | 1645200 → 1645184 | OTF，family Material Icons，8661 glyphs；全部 tables 載入成功 |
| `flutter_assets/packages/cupertino_icons/assets/CupertinoIcons.ttf` | 257632 → 257628 | TTF，family CupertinoIcons，1257 glyphs；全部 tables 載入成功 |
| `flutter_assets/shaders/ink_sparkle.frag` | 21336 → 21328 | Flutter IPLR shader bundle；抽出 GLSL ES 300、GLSL 100、SkSL 三份文字來源 |
| `flutter_assets/shaders/stretch_effect.frag` | 17376 → 17368 | Flutter IPLR shader bundle；抽出 GLSL ES 300、GLSL 100、SkSL 三份文字來源 |
| `loading_page.json` | 32536 → 32532 | Lottie 5.7.0；375×180、60 fps、300 frames／5 秒、5 layers，assets 陣列為空 |
| `privacy_contract.html` | 6984 → 6983 | 中文隱私政策，已匯出 HTML 與純文字 |
| `privacy_contract_en.html` | 7872 → 7864 | 英文隱私政策，已匯出 HTML 與純文字 |
| `use_agreement_contract.html` | 13344 → 13339 | 中文使用同意書，已匯出 HTML 與純文字 |
| `use_agreement_contract_en.html` | 15296 → 15288 | 英文使用同意書，已匯出 HTML 與純文字 |

## HTML 與對先前研究的補充

4 個 HTML 都可作 UTF-8 解析，以 `<!DOCTYPE html>` 開頭；沒有 script tag、href／src／action 外部資源引用。純文字中可能有服務網站與聯絡資訊，不能把「沒有外部資源引用」寫成完全沒有 URL。沒有在這 4 份頁面發現領卡 API 或手機註冊 endpoint；它們是條款頁，不是執行領卡流程的前端程式。

中文隱私政策「二、數位憑證皮夾資料安全性」明文寫：

> 數位憑證皮夾APP採用GuardSquare DexGuard方案來提供反靜態分析的保護、提供對動態分析與即時攻擊的防護，來避免惡意攻擊。

這是 APK 內官方隨附文字的產品聲明。先前只靠 loader／SO 命名無法證實 DexGuard 的保留仍適用於二進位歸因；本輪新增的是明確文字證據，沒有因此聲稱已逐項驗證所有反 Hook、反代理或釘選機制。頁面也含尚未替換的專案名稱提示文字，這只能說明隨包文字的內容，不能推論實際後端行為。

## 公鑰檔案不是重複副本

兩個公鑰檔案都可解成 P-256，但正規化公鑰文字不同：

| 檔案 | SHA-256(UTF-8(去空白的 Base64 SPKI 文字)) |
|---|---|
| `dwapp201i_public` | `38bbe4d0eef0b2616b0cb84f93c06a05fe94f8b623e4f09c403922f7a8e36ee7` |
| `dwapp201i_public.txt` | `dfbbc7e88f69844fe449aca4f02ce1d719ddaaad9e3fd9dc25f1934869bc5a82` |

只有 `.txt` 的來源已在目前成功路徑綁到 `dwapp-201i` 的 payload.keyId。另一份的用途、環境與私鑰配對仍未確認，不能僅憑檔名猜正式／測試環境。

## 離線重現方式

stage-b `o.JcPQWBA` 的 `ISyARpnL(AssetManager, String)` 以相對檔名的 FNV 雜湊查兩張表：17 個資產各自的 PCG seed 與 reader selector。`VVcmSog7` 先對每 8 bytes 的首 byte 做 PCG XOR，接著分別使用：

- selector 0：`ua7zwMYm`／`jHzEsshZ` 的 8-round Blowfish 變體、CBC。
- selector 2：`WNTdXCgQ`／`YHqZjOUd`／`Z93PHtg` 的 10-round Rijndael 變體，自訂列置換、ECB。
- selector 3：`VoUJXo4w` 的 16-round TEA 變體、CBC，delta 為 signed-short `-25033`。

私鑰資產只保留密文；其餘 15 個受保護資產均通過對應 block padding 與格式解析。工具及使用方法見 [twdiw-assets](../../../tools/twdiw-assets/README.md)。HTML 不經瀏覽器執行；分析只讀其文字與標籤。

驗證包括：JSON 解析、AssetManifest StandardMessageCodec 消耗完整輸入、gzip／zlib 解壓校驗與長度、fontTools 字型 tables、公鑰匯入及既有 `.txt` 指紋核對、shader IPLR magic。profile 保留解壓後的原始資料，不宣稱已有完整方法名稱反查；shader 保留 bundle 並抽文字，不宣稱完整反編譯 GPU binary。

## 交付

工作目錄：`/workspace/scratch/twdiw-all-assets-1.0.14/`。

- `raw/`：全部 19 個原始資產，保留 APK 名稱與檔案路徑。
- `decoded/assets/`：17 個可交付還原／原本未加密的資產。
- `readable/`：HTML 純文字、pretty JSON、AssetManifest.json、NOTICES.txt、公鑰 PEM、字型資訊、6 份 shader 文字、profile 解壓資料。
- `manifest.json`：逐檔來源、reader、大小與雜湊。
- `readable/analysis.json`：內容解析與驗證結果。
- `SHA256SUMS`：完整包內的檔案校驗清單。

下載包：`/workspace/scratch/twdiw-all-assets-1.0.14.zip`，包含原始／解碼資產、可讀衍生物、工具與 reader 定位匯出。不含 APK、SO 或明文私鑰。原 APK 內兩個私鑰資產僅以原始密文列入 raw。

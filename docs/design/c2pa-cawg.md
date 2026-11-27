# C2PA 簽署、CAWG 身分與 AI 來源宣告

狀態：規格（2026-11-27）。目前完成度見 [STATUS.md](../STATUS.md) 第 3.3 節。

本文記錄錢包怎麼在使用者的檔案加上 C2PA 內容憑證與 CAWG 身分聲明、怎麼驗證 CAWG 身分，以及怎麼讀取檔案對 AI 生成與浮水印的宣告（含 Google SynthID）。讀取 C2PA manifest 與 claim 簽章的部分見 [AGENTS.md](../../AGENTS.md) 的 C2PA 段落。

參考規格：C2PA 2.2（claim v2、`c2pa.hash.data`、`c2pa.hash.boxes`、`c2pa.hash.bmff.v2`／`v3`、`c2pa.hash.collection.data`、附錄 A 的各容器、`c2pa.actions.v2`、`c2pa.ingredient.v3`）、CAWG Identity Assertion 1.3（`cawg.identity`、`cawg.x509.cose`、`cawg.identity_claims_aggregation`）、CAWG Training and Data Mining 1.1（`cawg.training-mining`）、IPTC Digital Source Type 詞彙、C2PA 軟綁定演算法清單。

## 1. 簽署（`C2paWriter`）

- 容器（`C2paContainers`，C2PA 2.2 附錄 A，存放位置與 c2pa-rs 相同）：

  | 格式 | 存放位置 | 硬綁定 |
  |---|---|---|
  | JPEG | APP11 JPEG XT 盒，超過 64 KB 自動分段 | 資料雜湊（可選方塊雜湊） |
  | PNG | `caBX` 區塊，放在 IHDR 之後 | 資料雜湊（可選方塊雜湊） |
  | WebP、WAV、AVI | RIFF 的 `C2PA` 區塊（WebP 簡易格式先補 `VP8X`） | 資料雜湊 |
  | GIF | 應用程式延伸區塊 `C2PA_GIF`，放在標頭與全域色盤之後，版本升為 89a | 資料雜湊（可選方塊雜湊） |
  | TIFF、DNG | 標籤 0xCD41；單頁放在 IFD0，多頁另加只有這個標籤的最後一個 IFD | 資料雜湊 |
  | SVG | 根元素後的 `<metadata><c2pa:manifest>`（Base64） | 資料雜湊 |
  | MP3、FLAC | ID3v2 的 GEOB 框（`application/c2pa`），FLAC 放在 `fLaC` 前的 ID3 | 資料雜湊 |
  | JPEG XL | 容器格式的 `jumb` 盒（裸碼流先包成容器） | 方塊雜湊（可選資料雜湊） |
  | MP4、MOV、HEIF、HEIC、AVIF 等 BMFF | `ftyp` 之後的 C2PA `uuid` 盒；`stco`、`co64`、`iloc`、`tfhd`、`tfra`、`saio` 的位移一併調整 | `c2pa.hash.bmff.v3` |
  | PDF | 增量更新：內嵌檔案串流，型錄 `/AF` 的檔案規格（`/AFRelationship /C2PA_Manifest`）與 EmbeddedFiles 名稱樹 | 資料雜湊，排除串流內容 |
  | ZIP、OOXML、ODF、EPUB | `META-INF/content_credential.c2pa`，不壓縮，放在中央目錄之前 | `c2pa.hash.collection.data` |

  其他檔案與無法嵌入的檔案（加密 PDF、交叉參照損壞的 PDF、DocMDP 認證 PDF、ZIP64、分卷或中央目錄後還有資料的 ZIP 等）產生外部清單（`檔名.c2pa`，C2PA sidecar），原檔不變，App 會說明原因。PDF 採增量更新，既有的核准簽章仍有效（檢查結果會顯示簽章後有增量更新）。
- 已有 manifest 的檔案：舊 manifest 保留在同一個 store，新 manifest 以 `c2pa.opened` 加 `parentOf` 成分指向它，成分的 `validationResults` 記錄錢包對舊 manifest 的檢查結果。
- 宣告：`c2pa.actions.v2`（`c2pa.created` 帶 IPTC 數位來源類型，或 `c2pa.opened`）、可選的 `cawg.training-mining`（允許或不允許 AI 訓練與資料探勘）、依上表的硬綁定。方塊雜湊寫最小形式（store 之前的方塊一組、`C2PA` 本身、之後的方塊一組）；BMFF 雜湊用標準排除（`/uuid` 的 C2PA 盒、`/ftyp`、`/mfra`），v3 在每個頂層盒前加入 8 位元組位移；集合雜湊列出每個項目的 URI、雜湊與大小，加上中央目錄雜湊。
- claim 簽章：COSE_Sign1，EC P-256 用 ES256，RSA 一律用 PS256（C2PA 不接受 PKCS#1 v1.5）。可加 `sigTst2` 時戳，時戳涵蓋 `["CounterSignature", protected, h'', bstr(signature)]`（與 c2pa-rs 相同）。
- 空間預留：先以同樣大小的佔位硬綁定排版，算出排除範圍與各雜湊，再把 CAWG 身分聲明與 claim 簽章填回同樣大小（CAWG 的 `pad1`／`pad2`、COSE 的 `pad` 標頭），所以最終檔案的雜湊不必重算；完成後確認 manifest 以外的內容與排版時相同。
- 資料雜湊的排除範圍必須與各容器的 manifest 位置完全相同（c2pa-rs 的要求）：RIFF 是區塊標頭加內容、不含奇數長度的補齊位元組；GIF 是整個延伸區塊；TIFF 是標籤指向的資料；SVG 是 Base64 文字；ID3 是 GEOB 的資料；PDF 是串流內容。排除範圍以外還有其他範圍時，驗證結果另列 `*.additionalExclusionsPresent`。

### 驗證硬綁定（`C2paBindings`）

- 作用中的 manifest 只能有一個硬綁定（`claim.hardBindings.multiple`），且必須在簽署的 claim 中（`claim.hardBindings.missing`）。
- `c2pa.hash.boxes`（`C2paBoxHash`）：JPEG 標記區段、PNG 區塊、GIF 區塊、JPEG XL 盒依規格命名，store 為 `C2PA`，結尾多出的位元組為 `c2pa.after`；必須依序列出檔案的每個方塊。
- `c2pa.hash.bmff`（`C2paBmff`）：v1、v2、v3 與排除條件（xpath、長度、版本、旗標、資料、子集）依 c2pa-rs 解讀；Merkle 樹檢查分段 MP4（`moof` 到下一個 `moof`）與 `mdat` 固定或可變區塊，初始化區段單獨驗證時另加說明；以媒體時間劃分的 Merkle 樹列為未檢查。
- PDF：以空白密碼可開啟的加密 PDF 也讀取（與 c2pa-rs 相同），store 為解密後的串流，排除範圍是加密後的串流內容；簽署時加密 PDF 改用外部清單。JUMBF URI 寫成 `self#jumbf=c2pa/...`（沒有開頭斜線）時視為絕對路徑，與 c2pa-rs 相同。
- `c2pa.hash.collection.data`：只檢查 ZIP 內的集合（中央目錄雜湊接受 c2pa-rs 的範圍、完整範圍與 CRC 歸零三種算法），其他檔案的集合列為未檢查。ZIP 內有兩個同名項目（或宣告列出重複的 URI）時判定為 `assertion.collectionHash.malformed`，簽署時改用外部清單。SVG 以每個位元組一個字元處理，不論宣告的編碼都逐位元組保留內容。

### 簽署金鑰

所有 `DocumentSigner` 都可簽：自然人憑證卡、PIV、PKCS#11、PKCS#12、系統金鑰、錢包金鑰、CSC。RSA 金鑰要支援 PSS：

| 來源 | PSS 做法 |
|---|---|
| PKCS#12、系統金鑰、PKCS#11 | JCA 的 `RSASSA-PSS`（參數 SHA-256、MGF1-SHA-256、鹽 32 位元組），或 Android 的 `SHA256withRSA/PSS` |
| 自然人憑證卡（GPKI） | 卡片只做 RSA 原始運算，錢包自己做 EMSA-PSS 編碼（`RsaPss`）後送卡 |
| PIV | 同上，以 PIV 的一般驗證指令做原始 RSA |
| CSC | `signAlgo` 1.2.840.113549.1.1.10 加 `signAlgoParams`（DER 的 RSASSA-PSS 參數） |

每個簽章都以憑證公鑰檢查，卡片或服務用錯金鑰會在寫入前發現。

### CAWG 身分聲明

- `sig_type` 為 `cawg.x509.cose`，`signer_payload` 列出 `c2pa.hash.data`、動作、成分與訓練宣告的 hashed URI，角色預設 `cawg.creator`。
- 身分金鑰可以與 claim 簽署金鑰相同（例如自然人憑證卡同時簽兩者），也可分開（錢包金鑰簽 claim、卡片簽身分）。
- `signer_payload` 依 CAWG 1.3 第 8.2 節以 RFC 8949 核心決定性編碼簽署（預設）。c2pa-rs 0.9x 驗證時改以自己的欄位順序（`referenced_assertions`、`sig_type`、`role`）重新編碼，所以決定性編碼的身分聲明在 c2pa-rs（含 contentcredentials.org 的檢查頁）會顯示 `cawg.x509.signature.mismatch`。簽署選項的「互通」區可改用 c2pa-rs 順序；這不是標準編碼，只為相容而提供。錢包驗證時兩種編碼都接受。
- 身分憑證須符合 CAWG 的 X.509 信任模型：EKU `id-kp-documentSigning`（1.3.6.1.5.5.7.3.36），或 2027-03-31 前的過渡規則（`id-kp-emailProtection` 加 S/MIME 個人或組織驗證政策 2.23.140.1.5.{2,3,4}.{2,3}）。自然人憑證沒有這些用途，簽出的身分只會是「格式正確」，畫面在簽署前提示。

## 2. CAWG 驗證（`CawgIdentities`）

依 CAWG 1.3 第 8 章，狀態代碼照規格原文，`url` 為身分聲明的標籤。

- 共同：CBOR 結構（`cawg.identity.cbor.invalid`）、補齊必須全為 0（`pad.invalid`）、參照的宣告存在且雜湊相符、不重複、必須包含 claim 的硬綁定（`hard_binding_missing`、`hard_binding_incorrect`）。
- `cawg.x509.cose`：演算法、`x5chain`、簽章（嘗試內嵌 payload、儲存的編碼、決定性編碼與 c2pa-rs 順序）、身分自己的 `sigTst2` 或 claim 的時戳、憑證鏈以 `TrustRole.DOCUMENT` 判定、OCSP、有效期間、CAWG 信任模型。
- `cawg.identity_claims_aggregation`：COSE 內容類型 `application/vc`、W3C VC 結構、發行者 DID 的 `assertionMethod` 金鑰（DID 文件內嵌的驗證方法也接受）、發行者以 `DidTrust` 判定（`TrustRole.ISSUER`）、時戳、`validFrom`／`validUntil`、`credentialStatus` 撤銷、`c2paAsset` 與 `signer_payload` 相符、`verifiedIdentities` 的欄位。
- `c2paAsset` 比對：同樣的 hashed URI（url 與雜湊、順序）、`sig_type`、`role`。Adobe 的彙整服務會多帶 `alg`；c2pa-rs 的測試樣本把雜湊寫成 base64 文字的位元組陣列，這兩種都接受。
- 只有信任失敗（`cawg.x509.credential.untrusted`、`cawg.ica.untrusted_issuer`）或憑證不符 CAWG 信任模型時，結果是 `cawg.identity.well-formed`（畫面為「警告」）；全部通過才是 `cawg.identity.trusted`。
- c2pa-rs 的 `success.jpg` 樣本中 `cawg.crypto_wallet` 項目沒有 `address`，CAWG 規定必須有，錢包會判 `cawg.ica.verified_identities.invalid`（c2pa-rs 不檢查這一項）。

## 3. AI 來源宣告與 SynthID（`AiProvenanceReader`）

- 讀取 C2PA 動作的 `digitalSourceType`、`c2pa.soft-binding` 宣告與標籤，以及 XMP 的 `Iptc4xmpExt:DigitalSourceType`、`photoshop:Credit`、`xmp:CreatorTool`。每筆宣告記錄來源（C2PA 或 XMP）、所屬 manifest、claim 簽章是否驗證通過（XMP 不簽章）。
- `trainedAlgorithmicMedia`、`compositeWithTrainedAlgorithmicMedia` 為 AI 生成；`algorithmicMedia` 等為演算法合成。
- 軟綁定演算法以內建的 C2PA 清單辨識（`SoftBindingAlgorithms`，由 `tools/c2pa/update_softbinding.py` 產生，CC-BY-4.0）。清單目前沒有 SynthID。
- SynthID：Google 沒有公開的偵測 API 或離線偵測器，官方查驗頁 https://synthid.com/ 需要登入並有每日次數限制。錢包只讀宣告：檔案提到 SynthID（軟綁定演算法、宣告標籤、XMP），或宣告由 Google 的生成工具（Gemini、Imagen、Veo、Made with Google AI 等）以 AI 生成時，提示「可能含 SynthID 浮水印」，並提供按鈕開啟官方查驗頁讓使用者自行上傳。畫面一律標示「只讀宣告，未偵測浮水印」。

## 4. 測試

`test-servers` 的 `C2paSigningTest`：JPEG、PNG、WebP 與外部清單的簽驗往返；GIF、單頁與多頁 TIFF、WAV、AVI、MP3、FLAC、SVG、JPEG XL（裸碼流、容器、方塊雜湊與資料雜湊）、MP4、AVIF、PDF、ZIP、DOCX、ODT 與 JPEG／PNG／GIF 方塊雜湊的簽驗往返、再次簽署、竄改內容與移除 store；BMFF 移動 `mdat` 後 `stco` 仍指向同一份樣本；無法嵌入的 PDF 改為外部清單；c2pa-rs 為 `boxhash.jpg` 算出的方塊雜湊（`boxhash.json`，方塊名稱與雜湊都相同）與分段 MP4 Merkle 樹樣本（`dashinit.mp4`）；設定 `DIW_C2PA_FIXTURES` 指向 c2pa-rs 的 `sdk/tests/fixtures` 時另驗較大的樣本（`video1.mp4`、`legacy.mp4` 的 BMFF v2 雜湊，Adobe Express 簽出的 `express-signed.pdf`，均通過）；RSA 改用 PS256、c2pa-rs 順序與分開的身分金鑰、沒有 CAWG 用途的憑證、未知根憑證、再次簽署保留舊 manifest、改動像素、AI 宣告、XMP 的 Google AI 宣告、軟綁定清單，以及 c2pa-rs 與 Adobe 的身分彙整樣本。簽出的檔案以 c2pa-python 0.39（c2pa-rs 0.92）交叉檢查：claim 簽章、資料雜湊與 hashed URI 都通過，c2pa-rs 順序的身分聲明通過，決定性編碼的身分聲明如第 1 節所述不通過。

## 5. 未做

錢包自己當身分彙整服務發 `cawg.identity_claims_aggregation`（另開 PR）；SynthID 的像素偵測；字型（C2PA 附錄 A 的 OpenType 方式尚無參考實作）；BMFF 的更新 manifest 與 `brob` 壓縮盒；以媒體時間劃分的 BMFF Merkle 樹；多部分資產雜湊（`c2pa.hash.multi-asset`）。新容器簽出的檔案尚未以 c2pa-rs 交叉檢查（本次環境無法安裝 c2pa-python），列為實機項目。

# zkPassport 支援與整合：研究與方案

撰寫日期：2026-11-05。狀態：研究與方案，尚未實作；第 8 節的事項待使用者決定後才開始實作。

標記：**【確認】** 已讀過 zkPassport 原始碼（`zkpassport/circuits`、`zkpassport/zkpassport-packages`、`zkpassport/noir_rs`、`zkpassport/zkpassport-docs`，2026-11-04 的 main）或本 repo 程式碼；**【推論】** 依已知資料推論，需在實作時驗證。

P4 的設計文件（`p4-zkp.md`、`p4-circuits.md`、`p4-work-packages.md`）目前在 P4 整合分支上，本文以檔名引用。

## 1. 結論

建議把 zkPassport 當成「電子護照（ICAO 9303 晶片證件）」這種新文件的零知識證據，掛進既有的「一份文件、一張衍生憑證、多層證據」架構，而不是另做一個獨立功能。分四層，依序做：

| 層 | 做什麼 | 價值 | 大小 |
|---|---|---|---|
| Z1 電子護照文件 | 以 NFC 讀取護照晶片（BAC／PACE），做被動驗證（SOD 簽章、DSC 到 CSCA），存成文件分頁的一種證件，有結構化預覽與卡面 | 其他三層的基礎；不依賴 zkPassport 服務也能用 | 中 |
| Z2 zkPassport 查驗 | 查驗分頁產生 zkPassport 請求 QR，由使用者的 zkPassport App（或本錢包）回應，在本機驗證證明 | 可以查驗任何 zkPassport 使用者 | 中 |
| Z3 zkPassport 相容回應 | 本錢包掃描網站或 App 的 zkPassport 請求 QR，用 Z1 讀到的護照資料以 zkPassport 的公開電路產生證明並回應 | 使用者不必另裝 zkPassport App；同一份護照資料同時服務本專案與 zkPassport 生態 | 大 |
| Z4 文件與憑證整合 | 護照衍生 SD-JWT VC（含 zkPassport 證據）、以 bind 電路把證明綁到持有者金鑰、ISO 23220 Photo ID mdoc、年齡證明多一種後端、護照與其他文件的關聯 | 使用者要的「既有功能與 zkPassport、文件、憑證整合」 | 中到大 |

不做：zkPassport 的 FaceMatch 證明與加鹽唯一識別碼（OPRF）。兩者都綁定 zkPassport 官方 App 的應用程式識別碼，第三方 App 產生的證明一定會被查驗端拒絕（第 3.5 節）。

可行性的關鍵事實：

- zkPassport 的證明系統與 P4 相同（Noir 電路、Barretenberg UltraHonk），電路以 Apache-2.0 公開，查驗端只核對驗證金鑰雜湊是否在 zkPassport 的電路註冊表裡，不核對是哪個 App 產生的（FaceMatch 除外）。所以本錢包用同一批電路產生的證明，一般的 zkPassport 查驗端會接受。【確認：`zkpassport-sdk/src/public-input-checker.ts` 只在 FaceMatch 核對 app id hash】
- zkPassport 已把 App 端的輸入產生（`zkpassport-core`）、請求流程狀態機（`zkpassport-ffi` 的 `driver.rs`）與 bridge 協定（`zkpassport-bridge`）移植成 Rust，授權 MIT，可以直接放進本專案的 `native/` 工作區。【確認：`zkpassport-packages/rust/Cargo.toml` 的 `license = "MIT"`】
- 臺灣護照在 zkPassport 的支援清單上（`passport_support: 1`），中國大陸護照也是；臺灣身分證沒有晶片，不適用。【確認：`registry-sdk/src/document-support-rules.json` 的 TWN、CHN 項目】
- 主要成本是 Barretenberg 版本：zkPassport 用 barretenberg-rs 6.0.0（bb.js v6），P4 釘選 bb 2.1.9，證明與驗證金鑰格式很可能不相容，需要第二套 bb 或整體升級（第 4.2 節）。

## 2. zkPassport 是什麼

zkPassport（Obsidion Labs）讓使用者以手機 NFC 讀取護照、身分證或居留證的晶片，在手機上產生零知識證明，只揭露查驗方要求的屬性（年齡、國籍、姓名等），同時證明證件是發證國簽發且未被竄改。【確認：zkpassport-docs `intro.md`、`faq.md`】

### 2.1 元件與授權

| 元件 | 內容 | 授權 | 本專案可用的方式 |
|---|---|---|---|
| `zkpassport/circuits` | Noir 電路，約 10 類（sig-check DSC 與 ID data、data-check integrity、disclose、compare age／birthdate／expiry、inclusion／exclusion 國籍與發證國、sanctions、bind、facematch、oprf-auth、outer 聚合），依簽章演算法與 TBS 長度展開成數百個 package | Apache-2.0 | 不必自己編譯：查驗端與持有端都用 zkPassport 發佈的封裝電路（含 vkey），以 SHA-256 與註冊表核對 |
| `zkpassport-packages` | TypeScript SDK（`@zkpassport/sdk`）、UI 按鈕、utils、registry SDK 與合約、bridge 測試伺服器、Rust 移植 | SDK、UI、registry-sdk、bridge 為 Apache-2.0；Rust 工作區為 MIT；utils、合約、explorer 的 package.json 沒有寫授權 | 以 Rust crate 引用 `zkpassport-core`、`zkpassport-bridge`、`zkpassport-ffi` 的 driver；TypeScript 只當行為依據 |
| `zkpassport/noir_rs` | Noir 執行與 bb 證明、驗證的 Rust 包裝（zkPassport 的 fork） | Apache-2.0 | 可作為 Z2、Z3 的證明後端 |
| zkPassport 行動 App | React Native，含 128 MB SRS（2^21）、47 MB FaceMatch 模型 | 尚未開源（官方說正式上架後才開源） | 只能互通，不能引用 |
| 服務端 | bridge（`wss://bridge.zkpassport.id`）、電路 CDN（`circuits2.zkpassport.id`）、憑證包（`certificates.zkpassport.id`、IPFS）、制裁清單、查驗 API（`verifier.zkpassport.id`）、dashboard、雲端證明器（壓縮證明用） | 服務條款 | 見第 6 節：每一項都有自架或替代方式，FaceMatch 以外都不是必要 |

【確認】版本：電路 0.21.1、Noir 1.0.0-beta.22、SDK 依賴 `@aztec/bb.js` 5.0.0 與 `@aztec-foundation/bb.js` 6.0.0；電路版本 0.22.0 以上用 bb v6。

### 2.2 證明的組成

一次完整的查驗至少四個子證明【確認：`faq.md`、`rust/crates/zkpassport-core/src/outer.rs`】：

1. `sig_check_dsc_*`：CSCA 對 DSC 的簽章，CSCA 屬於憑證註冊表的 Merkle 樹（公開輸入含憑證樹根）。
2. `sig_check_id_data_*`：DSC 對 SOD 簽署屬性的簽章。
3. `data_check_integrity_*`：DG1 等資料群組的雜湊與 SOD 相符，並檢查效期。
4. 揭露或述詞證明，一項要求一個：`disclose_bytes`、`compare_age`、`inclusion_check_nationality`、`exclusion_check_sanctions`、`bind` 等。

前三個是「基礎證明」，掃描證件後就產生並快取（10 到 50 秒，RSA 不超過 1 GB 記憶體，P-521 或 brainpoolP512r1 可到 2 GB）；第 4 類在使用者同意請求時才產生（1 到 10 秒）。子證明之間以 Poseidon2 承諾串接（`comm_in`／`comm_out`）。另有 `outer` 聚合證明（`compressed`、`compressed-evm` 模式），由 zkPassport 的雲端證明器產生，用於鏈上驗證。

## 3. 協定與信任模型

### 3.1 請求

查驗方的 SDK 產生網址（QR 或連結）【確認：`zkpassport-sdk/src/index.ts` `_getUrl`】：

```
https://zkpassport.id/r?d=<網域>&t=<請求 ID>&c=<base64 查詢 JSON>&s=<base64 服務資訊>
  &p=<查驗方公鑰>&m=<fast|compressed|compressed-evm>&v=<SDK 版本>&dt=<最早可接受的 integrity 證明時間>
  &dev=<0|1>[&nt=<唯一識別碼種類>][&oprf_k=…][&r=<返回深層連結>]
```

`/c` 是 iOS App Clip 的路徑。查詢 JSON 是每個屬性一項：`disclose`、`eq`、`gte`／`gt`／`lte`／`lt`／`range`（年齡、出生日期、效期）、`in`／`out`（國籍、發證國）、`sanctions`、`facematch`、`bind`（使用者地址、chain id、自訂資料）。服務資訊含名稱、logo、用途、scope、chain。

### 3.2 傳輸（bridge）

查驗方與持有端經 bridge 中繼的 WebSocket 通訊，bridge 只轉送密文【確認：`rust/crates/zkpassport-bridge/src/lib.rs` 的協定註解與實作】：

- secp256k1 ECDH，公鑰 33 bytes 壓縮格式；AES-256-GCM 的金鑰直接取共享點壓縮編碼的前 32 bytes，沒有 KDF。
- GCM nonce 為 `sha256(bridge_id)[0..12]`，同一個工作階段的每一則訊息都用同一個 nonce。
- 訊息為 JSON-RPC：持有端送 `accept`／`reject`、每個子證明一則 `proof`（`proof`、`vkeyHash`、`version`、`name`、`total`）、最後 `done`（查詢結果），失敗送 `error`。內文 deflate 後 base64、分段。
- bridge 在轉送時加上來源連線的 `Origin`；持有端以 `ooc` 參數可取得建立者連線的 origin。

### 3.3 查驗

`verify()` 的本機路徑【確認：`index.ts` `verifyLocally`、`public-input-checker.ts`、`bb-verifier.ts`】：

1. 依電路版本取電路清單（manifest），每個子證明的 vkey 雜湊必須在清單裡，清單的根要等於鏈上電路註冊表的根。
2. 以 bb 驗證每個 UltraHonk 子證明。
3. 重算公開輸入並核對：憑證樹根在鏈上憑證註冊表中且以證明日期為準有效、`current_date` 與 `dt`、網域與 scope 的雜湊、查詢參數承諾、子證明之間的承諾串接、FaceMatch 的 app id 與 attestation 根金鑰。
4. 失敗時可退回 zkPassport 的查驗 API（`verifierMode` 可強制只用本機）。

註冊表合約在 Ethereum 主網（chain 1，也支援 Base 8453），測試網為 Sepolia；SDK 預設用內建 RPC，0.18 起可設定自己的 `rpcUrl`。

### 3.4 唯一識別碼

未加鹽時，唯一識別碼是 Poseidon2(證件資料、網域、scope)：同一份證件對同一服務固定、跨服務不同；但完整知道晶片資料的人（例如發證國）也能算出。加鹽版本用 vOPRF，且要求 strict FaceMatch。【確認：`faq.md`、`api.md`】

### 3.5 FaceMatch 與 App 綁定

FaceMatch 電路在 Android 上驗證 Play Integrity 權杖與 Android 金鑰證明鏈，並把 app id 雜湊放進參數承諾；SDK 只接受 zkPassport 官方 App 的兩個值（iOS `YL5MS3Z639.app.zkpassport.zkpassport`、Android `app.zkpassport.zkpassport`）。【確認：`zkpassport-sdk/src/constants.ts`、`public-input-checker.ts` 第 2132 行附近、`circuits/src/noir/bin/facematch/android`】因此本錢包不可能產生被一般查驗端接受的 FaceMatch 證明；這也是加鹽唯一識別碼不可用的原因。

## 4. 與本專案的契合點

| 項目 | 本專案現況 | zkPassport | 結論 |
|---|---|---|---|
| 證明系統 | Noir beta.15＋bb 2.1.9，UltraHonk ZK（P4 `native/circuits/VERSIONS`）【確認】 | Noir beta.22＋barretenberg-rs 6.0.0【確認】 | 同一家族，版本不同（4.2） |
| SRS | P4 已下載 Aztec 儀式的 BN254 g1 前綴（134,217,792 bytes）【確認：p4-status】 | App 內建 128 MB，涵蓋 2^21 | 同一份公開儀式，可共用一份資產【推論：需比對前綴雜湊】 |
| NFC | `core/document/card` 有 `CardChannel` 抽象，Android 以 `IsoDep` 讀自然人憑證（`AndroidNfcReaders.kt`）【確認】 | 晶片讀取在未開源的 App 內 | 護照讀取（BAC／PACE、安全訊息）要自己寫，可重用 `CardChannel` 與 NFC 掃描畫面 |
| 信任 | `TrustRegistry` 的角色有 ISSUER、VERIFIER、DOCUMENT、TSA 等，沒有證件 CSCA【確認：`TrustRegistry.kt`】 | 鏈上憑證註冊表 | 新增 CSCA 錨點（4.3） |
| ZK 後端 | `ZkProofEngine` 以後端名稱與電路識別碼區分（p4-zkp.md 第 4 節） | — | 新增後端 `zkpassport-ultrahonk` |
| mdoc | Multipaz 0.102 有 ISO 23220 Photo ID doctype，含 `org.iso.23220.datagroups.1`（dg1 到 dg16、sod）【確認：Multipaz `PhotoID.kt`】 | — | Z4 的標準出示路徑 |
| 影像與人臉 | Multipaz 有 `multipaz-jpeg2000`（DG2 相片常為 JPEG 2000）與 `multipaz-facenet`【確認：Multipaz repo】 | FaceMatch 用自家模型與裝置證明 | DG2 預覽用 jpeg2000；本機人臉比對只能作為本錢包自己的 T3 證據 |

### 4.1 NFC 讀取護照

- 實作 ICAO 9303 第 10、11 部分：MRZ（相機 OCR 或手動輸入號碼、生日、效期）導出 BAC 金鑰；優先 PACE（EF.CardAccess），退回 BAC；安全訊息（3DES 或 AES）；讀 EF.COM、EF.SOD、DG1、DG2，選讀 DG11、DG12、DG14、DG15。
- 被動驗證：SOD（CMS SignedData）簽章以 DSC 驗證、DSC 以 CSCA 驗證、各 DG 雜湊與 SOD 相符；沿用 P3 的 CMS 與 X.509 程式碼。
- 防複製：有 DG14 時做 Chip Authentication，有 DG15 時做 Active Authentication；結果寫在證件詳情，不影響 zkPassport 證明（zkPassport 不做這兩項【推論：電路沒有 CA／AA 相關 package】）。
- 函式庫：建議以 Kotlin 自行實作在 `commonMain`（Apache-2.0，可跨平台與兜底）；JMRTD 0.8.1 功能完整但為 LGPL-3.0，只建議當測試對照。
- MRZ 相機 OCR：Android 可用 ML Kit 文字辨識【推論】；一律保留手動輸入。

### 4.2 Barretenberg 版本

zkPassport 的證明要用它發佈的 vkey 與相同 bb 版本驗證；本專案的 zkPDF 釘選 bb 2.1.9。三個選擇：

1. 在 `native/` 另建 `zkpassport` feature，引用 zkPassport 的 `noir_rs`（barretenberg-rs 6.0.0），與 zkPDF 的 bb 2.1.9 並存。原生函式庫變大、建置時間增加，但互不影響。**建議**。
2. 把整個 P4 升到 bb 6：zkPDF 的 v1 ABI 已凍結、vkey 已發佈，升級等於重發 zkpdf-v1 資產，不建議在 P4 結束前做。
3. 只做查驗並一律用 zkPassport 的查驗 API：違反「盡量不依賴伺服器」與隱私原則，只當可選退回。

【推論】兩套 bb 靜態連結在同一個 `.so` 可能有符號衝突，WP0 式的建置驗證要先做；不行就拆成兩個 `.so`。

### 4.3 信任分級

zkPassport 的證明只證明「DSC 由憑證註冊表裡的某個 CSCA 簽發」，註冊表由 zkPassport 維護。本專案自己判定：

- 下載該憑證樹根對應的憑證包，重算樹根與鏈上值相符。證明不會揭露用了樹中哪一張 CSCA，所以只有在請求同時揭露發證國（或以 `in` 限定發證國）時，才能以本專案的 CSCA 錨點判定：憑證包中該國的 CSCA 全部在錨點中為 T2，否則 T3。沒有發證國資訊時一律 T3，畫面寫「依 zkPassport 註冊表」。Z2 建立請求時預設加上發證國揭露，讓結果可以判到 T2。
- CSCA 錨點來源：ICAO PKD 主清單（Master List）、德國 BSI 與法國 ANTS 等公開的主清單、各國公開的 CSCA；臺灣護照 CSCA 的公開來源要查證【推論：外交部領事事務局】。以新角色 `TrustRole.TRAVEL_DOCUMENT`（CSCA）加入 `TrustRegistry`，沿用「使用者可匯入、測試憑證加標記」的規則。
- Z1 的被動驗證直接以 CSCA 錨點判定，不經 zkPassport。
- `devMode` 的模擬護照（發證國「Zero Knowledge Republic」，ZKR）只在測試環境接受並加測試標記。

## 5. 方案細節

### 5.1 Z1 電子護照文件

- 加入證件畫面新增「電子護照（NFC）」：MRZ 掃描或輸入、NFC 讀取、被動驗證結果、確認後存檔。
- 文件分頁的結構化預覽：個人（姓名、國籍、出生日期、性別）、證件（種類、號碼、發證國、效期）、晶片（被動驗證、CA／AA、DSC 與 CSCA）、DG2 相片（JPEG 2000 經 `multipaz-jpeg2000` 解碼）；卡面影像用於 DC API 選擇。
- 原始 DG 與 SOD 以 App 私有儲存加密保存，DG2 屬敏感資料；同一本護照重讀時更新而非新增，換發的新護照與舊護照可並存（沿用文件並存規則）。
- 不依賴 zkPassport 的任何服務，可單獨交付。

### 5.2 Z2 zkPassport 查驗

- 查驗分頁新增「zkPassport」：以既有的查驗設定畫面選擇要求（年齡門檻、國籍包含或排除、揭露欄位、效期、bind），產生第 3.1 節的網址與 QR；`d` 用本專案控制的網域（例如使用者 VPS 上的查驗網頁網域），scope 依用途。
- 以 Kotlin 或 `zkpassport-bridge` 連接 bridge，收齊子證明後在本機驗證（4.2 選項 1），公開輸入檢查移植 `public-input-checker.ts` 中非 FaceMatch 的部分。
- 鏈上註冊表根：用 JSON-RPC `eth_call` 讀取，RPC 位址可設定（內建公開 RPC 與使用者自訂）；查到的根、電路清單與憑證包快取在本機，離線時以快取驗證並顯示「註冊表狀態截至 ○○」。
- 結果用既有的判定卡：每個揭露與述詞一列，標示「零知識證明（zkPassport）」與信任等級（4.3）。
- 要求 FaceMatch 或加鹽識別碼時，提示只有 zkPassport 官方 App 能回應。

### 5.3 Z3 zkPassport 相容回應

- 使用分頁的掃描器辨識 `https://zkpassport.id/r?…`（Android 無法驗證 zkpassport.id 的 App Links，所以以 App 內掃描為主，不註冊攔截該網域）。
- 同意畫面：顯示 `d`、bridge 回報的建立者 origin、服務名稱與用途、每項要求；`d` 與 origin 不一致或 origin 不是 https 時以 `RiskConfirmDialog` 強提示（第 7 節的轉送攻擊）。服務名稱與 logo 來自請求本身，一律標示「未經驗證」，除非能對上 zkPassport dashboard 的網域註冊【推論：dashboard 有公開查詢介面需確認】。
- 基礎證明在 Z1 讀取護照後背景產生並快取（依 p4-zkp.md 第 8 節的裝置分級與前景服務）；揭露證明在同意後產生，產生後先本機驗證再送出。
- 使用 zkPassport 發佈的電路包，依 manifest 與註冊表根核對 SHA-256 後才載入，與 P4 的資產規則一致（不從清單外載入）。
- 不支援的要求（FaceMatch、OPRF、`compressed` 模式需雲端證明器）回 `error` 並在畫面說明；`compressed` 模式可選擇在使用者同意後交給 zkPassport 雲端證明器，預設不做。
- 協定沒有公開規格，SDK 升級曾要求 App 最低版本（SDK 0.17 需要 App 1.4.0）；以 SDK 的 e2e 測試與 bridge acceptance 測試建立回歸測試，並以設定頁顯示支援的協定版本。

### 5.4 Z4 文件與憑證整合

1. **護照衍生憑證**：P3 衍生憑證架構新增 vct `urn:diw-wallet:vct:travel-document-derived:1`（IETF SD-JWT VC），欄位全部來自 DG1（遵守「衍生內容來自文件解析」原則）。證據層：
   - 被動驗證摘要（SOD 雜湊、DSC 與 CSCA 指紋），T2 或 T3；
   - zkPassport 基礎證明與承諾（disclosure，出示時可選擇帶上），讓查驗方不看 SOD 也能確認證件真實；
   - 選擇性帶 SOD＋DG1 原文（給不支援 ZK 的查驗方，隱私較低）。
2. **bind 綁定持有者**：以 zkPassport 的 `bind` 電路把證明綁到衍生憑證的持有者金鑰指紋（JWK thumbprint），證明「這張衍生憑證的持有者金鑰就是讀這本護照的人產生的」，避免證明被搬到別人的憑證上。
3. **ISO 23220 Photo ID mdoc**：以 Multipaz 的 Photo ID doctype 產生自簽 mdoc，`org.iso.23220.datagroups.1` 放 dg1、sod（dg2 可選），走 OpenID4VP DCQL、ISO 18013-5、DC API 的標準路徑；發行端是錢包金鑰（T3），但查驗方可自行以 SOD 驗到 CSCA。這是唯一的標準出示方式，與 zkPassport 方言隔離。
4. **年齡與國籍證明**：既有的年齡證明畫面多一個來源「電子護照（zkPassport 電路）」，以 `compare_age` 產生；國籍包含或排除以 `inclusion_check`／`exclusion_check`。出示給 zkPassport 查驗端時走 Z3；給本專案查驗端時包成 SD-JWT VC 證據或直接以 Z2 的格式。
5. **護照與其他文件的關聯**：入出國日期證明書、大陸出入境記錄等文件含證件號碼時，在本機比對 DG1 的號碼與文件解析出的號碼，加入既有的「雙證件關聯」。之後可設計零知識關聯電路，證明 zkPassport 承諾中的證件號碼等於 zkPDF 欄位承諾中的號碼而不揭露號碼；兩邊都是 Poseidon2 承諾，但承諾格式不同，列為後續研究。
6. **簽章**：護照晶片不提供簽章用的私鑰，不適用電子簽章。

## 6. 對外服務與法律聲明

依使用者 2026-11-05 的要求，與 TWDIW、Microsoft Verified ID 類似、依賴特定營運方服務的支援，需要專門的法律聲明與確認頁，不同意即停用。zkPassport 屬於此類：

| 服務 | 用途 | 看得到什麼 | 不用時的替代 |
|---|---|---|---|
| bridge `wss://bridge.zkpassport.id` | Z2、Z3 傳送 | IP、時間、bridge ID、密文大小；密文本身看不到 | 自架相容 bridge（`packages/bridge`，Apache-2.0，可放 diw-wallet-server）只能用在雙方都是本錢包的情況，官方 App 與網站固定用官方 bridge |
| 電路 CDN、憑證包、制裁清單 | 下載電路、憑證包 | IP、下載的電路與憑證樹根（可推得證件國家與簽章演算法） | IPFS 閘道（憑證包有 CID）；本專案鏡像並以雜湊核對 |
| Ethereum RPC | 讀註冊表根 | RPC 提供者看得到查詢的合約 | 使用者自訂 RPC 或自己的節點 |
| 查驗 API | 本機驗證失敗時退回 | 整份證明與查詢結果 | 預設關閉 |
| 雲端證明器 | `compressed` 模式 | 子證明（不是證件原始資料）【推論】 | 預設不做 |

聲明要寫明：zkPassport 不是本專案的服務、上述各項的資料流向、FaceMatch 與加鹽識別碼不可用、zkPassport 服務條款允許營運方隨時變更或停止服務（Terms 第 11、17 節）、以及未加鹽唯一識別碼可被發證國推算。聲明頁與停用開關由「法律聲明與初始化頁面」那串統一設計；Z1 不依賴 zkPassport，不受此停用影響。

## 7. 安全與隱私審查重點

- **bridge 的固定 nonce**：同一工作階段所有訊息共用一個 GCM nonce，金鑰也沒有經過 KDF。看得到密文的一方（bridge 營運者或網路上的人）可以由兩則密文推得明文的 XOR，並可能偽造訊息【確認：`zkpassport-bridge/src/lib.rs`；推論：GCM nonce 重用的已知後果】。本錢包為了互通只能照做，但要：每次請求用新的 ECDH 金鑰對、不在 bridge 上傳送任何未經 ZK 處理的個資、查驗端只信任驗證通過的證明而不信任 `done` 的明文結果。建議另向 zkPassport 回報（使用者決定）。
- **網域未經驗證**：網址的 `d` 由建立請求的人填寫，惡意網站可以填別人的網域，取得綁定該網域的證明後轉送給真正的網站使用。持有端要比對 bridge 回報的建立者 origin 與 `d`，不一致時強提示；查驗端（Z2）以自己控制的網域建立請求。
- **唯一識別碼的可連結性**：未加鹽識別碼對同一服務固定，且發證國可推算；同意畫面要寫明。
- **DG2 相片與完整 DG1** 不得寫入紀錄、log 或當機報告（沿用 p4-zkp.md 第 10 節的私密輸入規則）。
- **測試證件**：ZKR 模擬護照與 Sepolia 註冊表只在測試環境，與正式結果在畫面上區分。
- **電路來源**：只接受 manifest 內、雜湊相符、且 manifest 根等於鏈上電路註冊表根的電路；這也是信任 zkPassport 營運方的地方，聲明中要寫明。

## 8. 待使用者決定

1. **範圍**：建議做 Z1 到 Z4，其中 Z3（本錢包直接回應 zkPassport 請求）工作量最大；也可以先做 Z1、Z2、Z4，Z3 之後再做，期間回應 zkPassport 請求改為轉交官方 App。
2. **時程位置**：建議排在 P4（zkPDF 的 App 整合與 M4b）完成之後，作為 P4 的延伸工作包；Z1 不依賴 ZK，可提前。
3. **查驗 API 退回**：建議預設關閉，使用者可在設定開啟。
4. **Ethereum RPC**：建議內建一個公開 RPC 並允許自訂；或要求使用者自訂才啟用。
5. **NFC 實作**：建議 Kotlin 自行實作 BAC／PACE；JMRTD（LGPL-3.0）只作測試對照。
6. **回報 bridge nonce 問題**：是否由使用者向 zkPassport 回報（安全回報管道在 `zkpassport-packages/SECURITY.md`）。

## 9. 參考

- zkPassport 文件：https://docs.zkpassport.id（原始檔 https://github.com/zkpassport/zkpassport-docs）
- 電路：https://github.com/zkpassport/circuits
- SDK、registry、bridge、Rust 移植：https://github.com/zkpassport/zkpassport-packages
- noir_rs：https://github.com/zkpassport/noir_rs
- 支援國家地圖：https://registry.zkpassport.id/map
- 服務條款：https://zkpassport.id/terms
- ICAO Doc 9303（第 10、11、12 部分）：https://www.icao.int/publications/pages/publication.aspx?docnum=9303
- ICAO PKD 主清單：https://www.icao.int/Security/FAL/PKD/Pages/icao-master-list.aspx
- ISO/IEC 23220 Photo ID：Multipaz `multipaz-doctypes/.../PhotoID.kt`

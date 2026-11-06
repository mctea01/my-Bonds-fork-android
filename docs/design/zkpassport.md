# zkPassport 支援與整合：研究與方案

撰寫日期：2026-11-05。狀態：方案已定（第 8 節，2026-11-05 使用者決定）；2026-11-06 起實作，Z1 已完成（第 5.1 節），接著 Z2。

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

FaceMatch 與加鹽唯一識別碼（OPRF）：zkPassport 的版本綁定官方 App 的應用程式識別碼與 TACEO 的 OPRF 節點，本錢包產生的這兩種證明一定會被 zkPassport 的查驗端拒絕（第 3.5 節）。依使用者決定，本專案仍以同一批電路完成這兩項，改用本專案自己的值（本 App 的 app id、Play Integrity 金鑰、本專案的 OPRF 金鑰，私密的部分以 secret 保存），在本專案的查驗端可以驗證（第 5.5 節）。

可行性的關鍵事實：

- zkPassport 的證明系統與 P4 相同（Noir 電路、Barretenberg UltraHonk），電路以 Apache-2.0 公開，查驗端只核對驗證金鑰雜湊是否在 zkPassport 的電路註冊表裡，不核對是哪個 App 產生的（FaceMatch 除外）。所以本錢包用同一批電路產生的證明，一般的 zkPassport 查驗端會接受。【確認：`zkpassport-sdk/src/public-input-checker.ts` 只在 FaceMatch 核對 app id hash】
- zkPassport 已把 App 端的輸入產生（`zkpassport-core`）、請求流程狀態機（`zkpassport-ffi` 的 `driver.rs`）與 bridge 協定（`zkpassport-bridge`）移植成 Rust，授權 MIT，可以直接放進本專案的 `native/` 工作區。【確認：`zkpassport-packages/rust/Cargo.toml` 的 `license = "MIT"`】
- 臺灣護照在 zkPassport 的支援清單上（`passport_support: 1`），中國大陸護照也是；臺灣身分證沒有晶片，不適用。【確認：`registry-sdk/src/document-support-rules.json` 的 TWN、CHN 項目】
- 主要成本是 Barretenberg 版本：zkPassport 用 barretenberg-rs 6.0.0（bb.js v6），P4 釘選 bb 2.1.9，證明與驗證金鑰格式很可能不相容。決定把 P4 的 bb 升到 v6.0.0，全專案只留一套（第 4.2 節）。

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

zkPassport 的證明要用它發佈的 vkey 與相同 bb 版本驗證；本專案的 zkPDF 釘選 bb 2.1.9（aztec-packages `v2.1.9`，以 `native/zkpdf-prover/tools/build_bb.py` 從原始碼靜態建置，Android 每個 ABI 的 `.so` 約 15 到 16 MB）【確認】。zkPassport 用 barretenberg-rs 6.0.0（對應 aztec-packages `v6.0.0`，目前最新的 tag）【確認】。

使用者 2026-11-05 指出原生函式庫已經偏大，要求評估升級。建議**把 P4 的 bb 升到 v6.0.0，全專案只留一套 bb**，不要兩套並存：

- bb 只被 zkPDF 使用；OpenAC 用 Spartan2、zkTLS 用 TLSNotary、Longfellow 由 Multipaz 提供，都不受影響【確認：`native/*/Cargo.toml`】。
- 要改的地方：`build_bb.py` 的 tag 與 REVISION、`cpp/bridge.cpp` 對 `bbapi` 的呼叫（v2 到 v6 之間 API 有變動【推論】）、Noir 從 beta.15 升到與 bb v6.0.0 搭配的 v1.0.0-rc.3（P4 串 2026-11-05 查證；rc.3 沒有官方 release 執行檔，要以 cargo 自行建置，且移除了 `--bounded-codegen`）、`zkpdf-prover` 的 acvm／noirc_abi 版本；zkPDF 電路原始碼與 `PUBLIC_SPEC.md` 的 v1 公開輸入不變，只重新編譯並更新 `VERSIONS` 的 ACIR 與 VK 雜湊，重新發佈 zkpdf 的 Release 資產與簽署的範本包。
- 驗證方式：P4 既有的 zkPDF 回歸測試、正負向測試向量與實機量測（證明時間、記憶體峰值）都要在新版本重跑，結果不得變差到超出 p4-zkp.md 第 8 節的門檻。
- 升級後 zkPassport 的證明與 zkPDF 共用同一個 bb 與同一份 SRS；zkPassport 需要的 Noir 執行（witness 產生）也與 zkPDF 共用 acvm。zkPassport 發佈的電路包以 Noir beta.22 編譯，rc.3 的 acvm 能否讀取 beta.22 的 ACIR 序列化格式要在 Z2 開始時先驗證【推論】；bb v6 本身就是 zkPassport 用來證明 beta.22 電路的版本，所以 bb 端可以共用；不相容的只會是產生 witness 的 acvm。不相容時，在 zkPassport 這邊另外鎖一版 beta.22 的 acvm（純 Rust，不含 bb，體積小，Cargo 可以重新命名並存）。不採用以 rc.3 重新編譯 zkPassport 電路，因為編譯結果不同時 vkey 雜湊就對不上它的註冊表。
- 附帶好處：`build_bb.py` 目前因 v2.1.9 的 POSIX 依賴而不支援 Windows，v6 是否改善要在升級時確認【推論】。

時間點：在 P4 收尾前（M4b 正式範圍凍結前）由 P4 升級，zkPDF 的正式資產只發佈一次（第 8 節第 8 項）。

2026-11-06 實測更正：zkPassport 目前發佈的 0.21.1 電路以 bb 5.0.0 產生 vkey 與證明（SDK `bb-verifier.ts`：0.22.0 起才用 bb v6，0.22.0 尚未發佈）。以 compare_age 與 zkpassport-packages 的測試向量核對：Noir rc.3 的 acvm 可以讀取並執行 beta.22 的 ACIR；bb v6 由同一份 ACIR 算出的 vkey 與發佈的不同；bb.js 5.0.0 的證明 bb v6 不接受，bb v6 的證明 bb.js 5.0.0 也不接受。所以只用 bb v6 時，0.21.1 的證明不能在本機查驗或產生，要等 0.22.0，或另外加入 bb v5（使用者決定中）。

不採用的做法：兩套 bb 並存（每個 ABI 多約 15 MB，且兩套靜態 C++ 可能符號衝突）；只用 zkPassport 的查驗 API（違反盡量不依賴伺服器與隱私原則，只當可選退回）。

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

實作狀態（2026-11-06，Z1 完成）：

- 核心在 `core/document/mrtd`：機讀區解析（`Mrz`：TD1、TD2、TD3，檢查碼，名字以 `<` 分段全部保留，DG11 的完整姓名另外顯示；姓名可能被截斷時加註）、BAC 與 PACE（`MrtdAccess`：通用對應 GM，ECDH 與 DH，標準參數 0 到 2、8 到 18，3DES 與 AES 128／192／256）、安全通訊（`SecureChannel`）、晶片驗證 CA（v1 3DES 與 AES）、主動驗證 AA（RSA ISO 9796-2 與 ECDSA，挑戰與回應保存，查驗時重新驗證）、LDS 解析（`Lds`：COM、DG1、DG2 相片、DG5、DG11、DG12、DG14、DG15）、讀取流程（`MrtdReader`）。讀取結果是 `MrtdDump`（`urn:diw-wallet:emrtd:1` 的 JSON，副檔名 `.emrtd.json`），存成一般檔案，隨文件加密保存。
- 被動驗證在 `MrtdInspection`：SOD 的 CMS 簽章、DSC 到 CSCA（新信任角色 `TrustRole.TRAVEL_DOCUMENT`，不在系統角色內）、每個資料群組的雜湊、DSC 國別與機讀區簽發國比對。沒有 CSCA 錨點時結果為部分驗證。
- 不內建 CSCA：信任錨點頁可匯入 ICAO 主清單（.ml，驗章後加入，世代交替的連結憑證當中繼憑證，過期的略過），或匯入 PEM。
- App：檔案分頁「讀取電子護照」（機讀區三欄或貼上機讀區自動填入、CAN、內建 NFC 或外接讀卡機），檔案預覽顯示相片、所有名字、DG11／DG12 與晶片資訊，詳細頁顯示雜湊比對結果。
- JPEG 2000 相片：`multipaz-jpeg2000` 不在 Maven Central，目前無法解碼時只列出格式並保留原始資料，之後再決定解碼方式。
- 測試：`test-servers` 的 `mrtd/SoftwarePassport` 模擬晶片，`MrtdTest` 含 ICAO 9303 附錄 D 的 BAC 與安全通訊已知答案、PACE 各組合、CA、AA、複製晶片、竄改與未知 CSCA。尚未以實體護照測試。

### 5.2 Z2 zkPassport 查驗

- 查驗分頁新增「zkPassport」：以既有的查驗設定畫面選擇要求（年齡門檻、國籍包含或排除、揭露欄位、效期、bind），產生第 3.1 節的網址與 QR；`d` 用本專案控制的網域（例如使用者 VPS 上的查驗網頁網域），scope 依用途。
- 以 Kotlin 或 `zkpassport-bridge` 連接 bridge，收齊子證明後以升級後的 bb（4.2）在本機驗證，公開輸入檢查移植 `public-input-checker.ts`；FaceMatch 與 OPRF 的檢查同時接受 zkPassport 的值與本專案的值（5.5），結果標明是哪一種。
- 鏈上註冊表根：用 JSON-RPC `eth_call` 讀取，RPC 位址可設定（內建公開 RPC 與使用者自訂）；查到的根、電路清單與憑證包快取在本機，離線時以快取驗證並顯示「註冊表狀態截至 ○○」。
- 結果用既有的判定卡：每個揭露與述詞一列，標示「零知識證明（zkPassport）」與信任等級（4.3）。
- 要求 FaceMatch 或加鹽識別碼時，可選「zkPassport 官方」或「本專案」：前者只有官方 App 能回應，後者只有本錢包能回應（5.5）。

實作狀態（2026-11-06，Z2 未加 FaceMatch 與加鹽識別碼）：

- 原生 `native/zkpassport-verify`（`diw-zk-ffi` 的 zkpdf 功能）：證明組解讀與承諾串接、公開輸入與查詢參數承諾（揭露、年齡、國籍與發證國的包含或排除、bind）、日期與效期、網域與 scope、識別碼類型（模擬護照只在測試模式）、電路清單根（高度 12 的 Poseidon2 樹）與金鑰雜湊、憑證包樹根（v0 與 v1，含撤銷與主清單樹），以 bb v6 驗證每個子證明。只回報證明承諾的值，查詢的每個條件都要有證明支撐。測試以 zkPassport 正式的 0.21.1 清單、compare_age 金鑰與 2026-11 主網憑證包核對到鏈上的值。
- Kotlin `core/zkpassport`：請求網址與 SDK 查詢（`ZkPassport`）、bridge 建立端（`ZkPassportBridgeProtocol`，ECDH、AES-GCM、zlib 分塊、ping、重連與 replay）、電路清單與金鑰、憑證包、`isRootValid`（`ZkPassportRegistry`，依清單版本與憑證樹根快取在本機）、工作階段（`JvmZkPassportVerifier`，最多重連 5 次）。證明全部失敗於 bb 且使用者開啟時才問 zkPassport 查驗 API，結果標示。
- 信任：揭露或限定的發證國，其憑證包中的 CSCA 金鑰全部是本 App 的 `TRAVEL_DOCUMENT` 錨點時為 T2（結果卡通過），否則 T3（結果卡注意）並列出比對數；憑證包下載失敗或雜湊不符時維持 T3。
- App：查驗分頁「以 zkPassport 查驗護照」（需同意 zkPassport 專門聲明 v2），設定網域、服務名稱、用途、揭露欄位、最低年齡、國籍與發證國條件、綁定資料，測試環境可接受測試護照；QR 與在本機開啟、進度、結果卡（揭露值、條件、識別碼與其可關聯性、證明日期、技術細節）與歷史紀錄。零知識證明設定頁有網域、主網與 Sepolia 節點（空白用內建公開節點）與查驗 API 開關（預設關閉）。Windows 沒有 zkPDF 原生元件，入口會說明無法查驗。
- 未驗證：zkPassport 目前鏈上的 0.21.1 電路是 bb 5 產生的證明，以 bb v6 驗證尚未以實機與官方 App 測試；離線時註冊表查詢會失敗，「註冊表狀態截至」的離線模式尚未提供。

### 5.3 Z3 zkPassport 相容回應

- 使用分頁的掃描器辨識 `https://zkpassport.id/r?…`（Android 無法驗證 zkpassport.id 的 App Links，所以以 App 內掃描為主，不註冊攔截該網域）。
- 同意畫面：顯示 `d`、bridge 回報的建立者 origin、服務名稱與用途、每項要求；`d` 與 origin 不一致或 origin 不是 https 時以 `RiskConfirmDialog` 強提示（第 7 節的轉送攻擊）。服務名稱與 logo 來自請求本身，一律標示「未經驗證」，除非能對上 zkPassport dashboard 的網域註冊【推論：dashboard 有公開查詢介面需確認】。
- 基礎證明在 Z1 讀取護照後背景產生並快取（依 p4-zkp.md 第 8 節的裝置分級與前景服務）；揭露證明在同意後產生，產生後先本機驗證再送出。
- 使用 zkPassport 發佈的電路包；執行前以本機 bb 由電路 ACIR 算出 vkey，其 Poseidon2 雜湊必須等於 manifest 的葉，manifest 再以 Poseidon2 樹根對鏈上電路註冊表（不從清單外載入，與 P4 的資產規則一致）。只核對檔案雜湊不夠：電路決定哪些值公開，清單外的電路可以把晶片資料變成公開輸入。
- 請求要 FaceMatch 或 OPRF 時，本錢包可以用本專案的值產生（5.5），但 zkPassport 的查驗端會拒絕；同意畫面先說明這一點，使用者仍要送出才產生。`compressed` 模式需要 zkPassport 雲端證明器，預設不做，使用者同意後才交給它。
- 協定沒有公開規格，SDK 升級曾要求 App 最低版本（SDK 0.17 需要 App 1.4.0）；以 SDK 的 e2e 測試與 bridge acceptance 測試建立回歸測試，並以設定頁顯示支援的協定版本。

手機端證明（2026-11-06 完成基礎，Z3、Z4-4、5.5 共用）：

- 輸入產生與流程沿用 zkPassport 官方的 Rust 實作（`zkpassport-core` 與 `zkpassport-ffi` 的 sans-IO driver，MIT），收在 `native/vendor/zkpassport`（以 git 相依取得時，上游子模組的 SSH 網址會讓 Cargo 失敗，所以收進 repo，`src/` 不改）。電路的選擇、順序與輸入都與官方 App 相同。
- `diw-zk-ffi` 匯出 `ZkPassportProofSession`（driver 的 next／provide）與 `zkpassport_prove`（執行電路並以 bb v6 證明，回傳公開輸入接證明的 hex 與 vkey；先做上一節的 vkey 雜湊核對，不符回 `circuit_vkey_mismatch`）。compare_age 在 x86_64 release 約 4 秒（含 vkey 計算）。
- Kotlin `ZkPassportProver`（jvmCommonMain）：鏈上 `latestRoot` 取最新憑證根，憑證包要雜湊到該根，manifest 的電路根要在註冊表有效，之後下載電路逐一證明；註冊表檔案以網址快取（憑證包以根、manifest 以版本、電路以雜湊命名，不會過期），只接受 zkpassport.id 的 HTTPS 主機。bridge 的 `proof` 訊息補上 SDK 需要的 `vkeyHash` 與 `version`。鹽為每次新產生的 248 位元亂數。
- 預設電路版本 `0.22.0`（第一個以 bb v6 產生 vkey 的版本，尚未發佈）；0.21.1 的電路在 vkey 核對就會停下，因為 bb v6 算出的 vkey 與發佈的不同（4.2）。若使用者決定加入 bb v5，這裡改為依電路包的 `bb_version` 選擇後端。
- 測試：原生 `cargo test -p diw-zk-ffi --features zkpdf`（含以 compare_age 實際證明並驗證的 ignored 測試）；`ZkPassportProverTest` 以真實憑證包與 0.21.1 manifest 檢查核對順序與錯誤碼。完整流程需要真實護照與 0.22.0 電路，排在實機驗證。

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

實作狀態（2026-11-06，第 2、4 項依賴 Z3 的手機端證明，排在 Z3 之後）：

- 第 1 項：`TravelDocumentFields`，衍生憑證 vct `urn:diw-wallet:vct:travel-document-derived:1`，欄位全部來自 DG1（所有名字都保留），證據 `TravelDocumentPassiveAuthentication` 記錄錢包當時的被動驗證、CSCA 信任等級、晶片驗證與主動驗證、DG1 與 SOD 的 SHA-256。持有者可另外揭露 `travelDocumentDg1` 與 `travelDocumentSod`：查驗方先核對雜湊，再重做被動驗證並比對每個揭露欄位與 DG1。zkPassport 證明作為證據的部分隨 Z3 加入。
- 第 3 項：`TravelDocumentPhotoId`，檔案頁「產生 Photo ID」。doctype `org.iso.23220.photoid.1`；`org.iso.23220.1` 放姓、名、出生日期、出生年、年齡門檻（13、15、16、18、21、25、60、65，只會由否變是，不會誇大）、相片（DG2）、效期、發證國與國籍（ISO 3166-1 alpha-2，`D` 轉 DE、`RKS` 轉 XK，非國家代碼不放）、性別（ISO/IEC 5218）、證件號碼；`org.iso.23220.datagroups.1` 放 dg1、dg2、sod 原文。發行者是錢包的文件發行金鑰，憑證為自簽的文件簽發者憑證（keyUsage digitalSignature、EKU mdlDS），效期一年且不超過護照效期，信任為 T3。走既有的 OpenID4VP DCQL、ISO 18013-5 與 DC API 出示，與 zkPassport 方言隔離。本專案查驗端（`PresentationVerifier`）遇到未錨定的 Photo ID 時視為持有者錢包的聲明（T3），以揭露的 dg1、sod（與 dg2）重做被動驗證並比對揭露欄位；持有者綁定仍是錢包的聲明，結果另列一行說明。App 的感應查驗多了「護照 Photo ID（ISO 23220）」要求，同樣以晶片檔案重做被動驗證並列出證據。
- 第 5 項：`TravelDocumentLinks`，護照檔案頁列出文字中記載同一護照號碼的已存文件（PDF 文字層、文字與 XML），英文姓氏也相同時標示；只在本機比對，不放進憑證。零知識關聯電路仍為後續研究。

### 5.5 本專案的 FaceMatch 與加鹽唯一識別碼（2026-11-05 使用者決定）

zkPassport 的這兩項只能被它自己的查驗端接受，這裡做的是同樣強度、但信任本專案的版本。電路沿用 zkPassport 的公開電路，不改電路，只換電路外核對的值。

**FaceMatch**（`facematch/android` 電路）【確認：電路參數】：

- 電路驗證 Android 金鑰證明鏈（Google 根金鑰）、裝置金鑰對 client data 的簽章（含 DG2 雜湊與比對模式）、Play Integrity 權杖的簽章，並把 app id、Play Integrity 驗證公鑰、環境、模式放進參數承諾。
- 本專案的值：app id 為本 App 的套件名稱；Play Integrity 驗證公鑰是本專案在 Play Console 取得的值（公開常數，寫進查驗端）；權杖的解密金鑰是私密值，存在 diw-wallet-server 的 secret（例如 `DIW_PLAY_INTEGRITY_DECRYPTION_KEY`，Cloud Run 用 Secret Manager、Cloudflare 用 secret），由伺服器解密後把 Google 簽署的權杖交回手機放進電路，不放進 APK。
- 人臉比對在手機上做：DG2（JPEG 2000）與現場自拍以 Multipaz `multipaz-facenet` 比對，活體檢查沿用 zkPassport 的「轉頭」流程概念。比對結果與模式由裝置金鑰簽進 client data，電路只證明簽章與承諾，不證明比對演算法本身；這與 zkPassport 的信任假設相同（信任 App 與裝置）。
- 前提：Play Integrity 只在 Google Play 安裝的版本可用，所以 FaceMatch 只在 Play 版提供；GitHub Release 或側載的 APK 顯示停用列並寫明原因。本專案的 Google Play 上架正在另一串進行。
- iOS 版（P6）用 App Attest 的同一套電路，屆時再補。

**加鹽唯一識別碼（OPRF）**【確認：`oprf-auth` 電路與 `zkpassport-utils/src/oprf`】：

- zkPassport 的流程：手機以 `oprf-auth` 電路證明盲化查詢對應的私密 nullifier 與基礎證明的承諾一致，送到 TACEO 的三個 OPRF 節點（門檻 2），節點檢查 FaceMatch 證明後回傳盲化結果與 DLEQ 證明，揭露電路驗證 DLEQ 並輸出加鹽識別碼與 OPRF 公鑰雜湊。查驗端核對公鑰雜湊等於 TACEO 的公鑰。
- 本專案的版本：diw-wallet-server 新增 OPRF 評估端點，金鑰（BabyJubJub 純量）存在 secret（例如 `DIW_OPRF_KEY`），公鑰與公鑰雜湊公開並內建在 App 與查驗端；端點只回盲化結果與 DLEQ 證明，看不到 nullifier 與證件資料。
- 授權規則（伺服器端）：驗證 `oprf-auth` 證明與基礎證明的承諾一致、基礎證明的憑證樹根有效，並要求同一承諾的本專案 FaceMatch 證明（strict）；沒有 FaceMatch 的版本（非 Play 版）可以改用「裝置金鑰證明＋速率限制」取得較低等級的加鹽識別碼，查驗結果標示「未經人臉比對」。
- 之後可改成多台主機的門檻 OPRF（TACEO 的 `oprf-nr` 協定），降低單一金鑰外洩的風險；第一版先單一金鑰，金鑰外洩時以輪替公鑰（key id）處理，舊識別碼全部失效，聲明中寫明。
- 不在 APK 內放 OPRF 金鑰：任何人都能從 APK 取出，等於沒有加鹽。若要離線使用，只能接受未加鹽識別碼。

實作狀態（2026-11-06）：

- OPRF：原生 `oprf` 功能（`zkpdf` 會一併開啟）以 TACEO `taceo-oprf-core` 0.6.3（MIT／Apache-2.0）實作單一金鑰 OPRF 與 Chaum-Pedersen 證明：`oprf_public_key`（含電路輸出的 `oprf_pk_hash`）、`oprf_evaluate`（伺服器端）、`oprf_blind`、`oprf_finalize`（錢包端，核對證明後產生電路的 `oprf_proof` 與輸出）。已實測：zkPassport 的 compare_age 電路以本專案的證明與輸出（`nullifier_secret`）執行成功，改動證明或輸出即失敗；`oprf_pk_hash` 的算法對上 zkPassport 自己的金鑰雜湊常數。
- 錢包：`ZkPassportProver.Job.oprf` 有值時，揭露電路證明前把私密 nullifier 盲化送到服務端，回答須對設定的公鑰通過證明，輸出填入 `nullifier_secret`；`ZkPassportOprfClient` 讀 diw-wallet-server 的 `/oprf/v1/key` 並以伺服器權杖呼叫 `/oprf/v1/evaluate`。查驗端以 `ZkPassportConfig.oprfKeyHash` 指定接受的金鑰雜湊：App 每次查驗時從自己服務端的 `/info`（`features` 含 `oprf`）讀取 `oprf.pk.hash`；沒有服務端或服務端未提供 OPRF 時不接受任何加鹽識別碼（錯誤 `oprf_key`）。
- 伺服器端點與金鑰 secret 在 diw-wallet-server（`oprf` 功能）。第一版的授權是伺服器權杖加每個位址的次數上限；FaceMatch 授權等 Play Integrity 金鑰（需使用者在 Play Console 產生）後加入，在此之前的識別碼標示「未經人臉比對」。

**互通性**：上述證明只有本專案的查驗端（Z2、diw-wallet-server 的查驗網頁）接受；zkPassport 的 SDK 會因 app id 或 OPRF 公鑰雜湊不符而拒絕【確認：`public-input-checker.ts`】。畫面與聲明都要寫明。

## 6. 對外服務與法律聲明

依使用者 2026-11-05 的要求，與 TWDIW、Microsoft Verified ID 類似、依賴特定營運方服務的支援，需要專門的法律聲明與確認頁，不同意即停用。zkPassport 屬於此類：

| 服務 | 用途 | 看得到什麼 | 不用時的替代 |
|---|---|---|---|
| bridge `wss://bridge.zkpassport.id` | Z2、Z3 傳送 | IP、時間、bridge ID、密文大小；密文本身看不到 | 自架相容 bridge（`packages/bridge`，Apache-2.0，可放 diw-wallet-server）只能用在雙方都是本錢包的情況，官方 App 與網站固定用官方 bridge |
| 電路 CDN、憑證包、制裁清單 | 下載電路、憑證包 | IP、下載的電路與憑證樹根（可推得證件國家與簽章演算法） | IPFS 閘道（憑證包有 CID）；本專案鏡像並以雜湊核對 |
| Ethereum RPC | 讀註冊表根 | RPC 提供者看得到查詢的合約 | 使用者自訂 RPC 或自己的節點 |
| 查驗 API | 本機驗證失敗時退回 | 整份證明與查詢結果 | 預設關閉 |
| 雲端證明器 | `compressed` 模式 | 子證明（不是證件原始資料）【推論】 | 預設不做 |
| 本專案 OPRF 端點（diw-wallet-server） | 本專案的加鹽識別碼（5.5） | IP、時間、盲化查詢與授權用的證明；看不到 nullifier 與證件資料 | 不用時只能用未加鹽識別碼 |
| Google Play Integrity、本專案的權杖解密端點 | 本專案的 FaceMatch（5.5） | Google 看得到裝置完整性查詢；本專案伺服器看得到完整性結果，看不到人臉與證件資料 | 非 Play 版不提供 FaceMatch |

聲明要寫明：zkPassport 不是本專案的服務、上述各項的資料流向、本專案的 FaceMatch 與加鹽識別碼只被本專案的查驗端接受、zkPassport 服務條款允許營運方隨時變更或停止服務（Terms 第 11、17 節）、以及未加鹽唯一識別碼可被發證國推算。聲明頁與停用開關由「法律聲明與初始化頁面」那串統一設計；Z1 不依賴 zkPassport，不受此停用影響。

## 7. 安全與隱私審查重點

- **bridge 的固定 nonce**：同一工作階段所有訊息共用一個 GCM nonce，金鑰也沒有經過 KDF。看得到密文的一方（bridge 營運者或網路上的人）可以由兩則密文推得明文的 XOR，並可能偽造訊息【確認：`zkpassport-bridge/src/lib.rs`；推論：GCM nonce 重用的已知後果】。本錢包為了互通只能照做，但要：每次請求用新的 ECDH 金鑰對、不在 bridge 上傳送任何未經 ZK 處理的個資、查驗端只信任驗證通過的證明而不信任 `done` 的明文結果。已決定經 GitHub 私密漏洞回報向 zkPassport 回報（第 8 節）。
- **網域未經驗證**：網址的 `d` 由建立請求的人填寫，惡意網站可以填別人的網域，取得綁定該網域的證明後轉送給真正的網站使用。持有端要比對 bridge 回報的建立者 origin 與 `d`，不一致時強提示；查驗端（Z2）以自己控制的網域建立請求。
- **唯一識別碼的可連結性**：未加鹽識別碼對同一服務固定，且發證國可推算；同意畫面要寫明。
- **DG2 相片與完整 DG1** 不得寫入紀錄、log 或當機報告（沿用 p4-zkp.md 第 10 節的私密輸入規則）。
- **測試證件**：ZKR 模擬護照與 Sepolia 註冊表只在測試環境，與正式結果在畫面上區分。
- **電路來源**：只接受 manifest 內、雜湊相符、且 manifest 根等於鏈上電路註冊表根的電路；這也是信任 zkPassport 營運方的地方，聲明中要寫明。

## 8. 決定（2026-11-05）

| # | 事項 | 決定 |
|---|---|---|
| 1 | 範圍 | Z1 到 Z4 全做，Z3（本錢包直接回應 zkPassport 請求）最後完成 |
| 2 | 時程 | P4 完成後開始，作為 P4 的延伸工作包；Z1 不依賴 ZK |
| 3 | 查驗 API 退回 | 預設關閉，使用者可在設定開啟 |
| 4 | Ethereum RPC | 內建一個公開 RPC，允許自訂 |
| 5 | NFC 實作 | Kotlin 自行實作 BAC／PACE；JMRTD（LGPL-3.0）只作測試對照 |
| 6 | bridge nonce 問題 | 向 zkPassport 回報，經 GitHub 私密漏洞回報（`zkpassport-packages` 的 Security 頁），由使用者送出 |
| 7 | OPRF 與 FaceMatch | 仍要完成，改用本專案的值，私密值以 secret 保存（5.5） |
| 8 | bb 版本 | 升級到 v6.0.0，全專案只留一套（4.2），在 P4 收尾前（M4b 正式範圍凍結前）由 P4 完成 |

順序：（P4 內完成 bb 升級）Z1、Z2、Z4、5.5、Z3。

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

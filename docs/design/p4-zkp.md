# P4 零知識證明：總體設計與約定

撰寫日期：2026-10-16。狀態：D1 到 D6 已於 2026-10-16 決定（第 2 節），實作依 [p4-work-packages.md](p4-work-packages.md) 分包進行；電路細節見 [p4-circuits.md](p4-circuits.md)。本文的「約定」是所有工作包（含交給 ChatGPT Codex 的部分）共同遵守的介面與規則，修改時要同步更新三份文件與 AGENTS.md。

標記：**【確認】** 已讀過原始碼、規格或實測；**【推論】** 依已知資料推論，尚待工作包實測。

## 1. 結論

P4 要讓錢包與查驗端都能產生與驗證四種零知識證據，全部掛在既有的「一張衍生憑證、多層證據」架構上，不另開新的出示協定：

| 證據 | 證明什麼 | 證明系統 | 第一批對象 | 產生時機 |
|---|---|---|---|---|
| zkPDF | 某機關簽章的 PDF，第 1 頁在指定標籤之間寫著這些值（或值滿足述詞），不交出整份文件 | Noir 電路，Barretenberg UltraHonk（零知識版本） | 福州大學學籍（在學）證明；大陸國家移民管理局出入境記錄、通行證與居住證關聯證明 | 產生衍生憑證時做一次，之後每次出示重用 |
| zkTLS | 官方查驗頁在一次真實的 TLS 連線中回了這些內容 | TLSNotary（alpha.15，Proxy 模式為預設） | 學信網學籍在線驗證報告；台灣移民署入出國日期證明書查驗頁 | 出示當下由查驗方一起執行（即時模式） |
| 年齡證明（OpenAC） | 隱藏的出生日期不晚於查驗方給的日期 | 引用 Bonds 的 OpenAC 年齡述詞（zkID `jwt_2k` 與 `show`，Spartan2）；是可替換的後端之一，也是第一個端對端測試 | TWDIW 有生日欄位的卡片、Bonds 身分證卡 | 出示當下 |
| mdoc ZK（Longfellow） | ISO mdoc 的指定欄位（如 age\_over\_18）由發行端簽過，隱藏 MSO 與簽章 | Multipaz `multipaz-longfellow` | 測試發行端的 mDL、PID | 出示當下 |

離線時，zkTLS 無法即時執行，改用兩種非即時證據（已於 2026-10-11 決定）：裝置證明的 TLS 紀錄（T3，畫面寫明「不是 zkTLS」），以及使用者自架 notary 簽發的網頁證明憑證（T3，持有人控制的 notary 對第三方等同自我聲明）。

## 2. 決定（2026-10-16）

| # | 問題 | 決定 | 落實方式 |
|---|---|---|---|
| D1 | zkPDF 第一版要隱藏到什麼程度 | 接受建議：隱藏頁面內容串流與 QR 影像，字型與 ToUnicode 對照表公開 | 洩漏分析見 p4-circuits.md 第 3.9 節；連字型一起隱藏留給之後的「高隱私模式」 |
| D2 | zkPDF 證明系統 | 接受建議：Noir＋UltraHonk（零知識版本） | p4-circuits.md 第 1.1 節 |
| D3 | 裝置算力不足時 | 不擋下，提示後由使用者決定 | 第 8 節：算力檢查只給估計與建議，畫面列出「仍在這台裝置產生」「在電腦版產生後匯入」「送到自架主機產生」「不加零知識證據」，各寫明代價 |
| D4 | zkTLS 即時模式的查驗方 | 電腦版與測試伺服器當查驗方只是過渡；目標是手機也能當查驗方 | 第 5.2 節：持有端與查驗端之間改用端對端加密通道，可走同一個區域網路或只轉送密文的中繼；WP6 分成 M6a（過渡）與 M6b（手機查驗方），兩者都在 P4 完成 |
| D5 | OpenAC 年齡證明 | Bonds 的 OpenAC 只是其中一種電路；因為有現成電路與資產，先引入並當作第一個端對端測試 | 第 4 節：證明後端以 `ZkProofEngine` 抽象，不綁定 OpenAC；WP7 是原生建置管線（WP0）完成後第一個端對端測試 |
| D6 | 分工 | 大致接受，逐步完成；電路細節由 Claude 管控；P3 的文件解析可作為 zkPDF 欄位標籤的參考 | 電路規格與審查由 Claude 負責，里程碑可逐步交給 Codex，完成後附電路實作報告供檢查（p4-work-packages.md 第 1.1、4 節）；描述檔自己定義欄位與錨點，標籤參考 P3（p4-circuits.md 第 3.11 節） |

## 3. 範圍

做：

- 共用的 ZK 原生執行環境（Rust 工作區、uniffi 綁定、Android 與桌面）、電路與金鑰的下載與釘選、裝置分級與退回。
- zkPDF：版型描述檔、遮蔽套件、Noir 電路、持有端產生與查驗端驗證、衍生憑證的證據與揭露。
- zkTLS：TLSNotary 持有端（Android、桌面）與查驗端（Android、桌面、測試伺服器），端對端加密通道（區域網路、中繼），查驗頁描述檔，即時模式；裝置證明紀錄與自架 notary 的網頁證明憑證。
- OpenAC 年齡證明：引用 Bonds，含 Bonds 請求 QR、證明包與 BLE、HTTPS 傳送；查驗端同樣支援。
- Longfellow：`mso_mdoc_zk` 的出示（OpenID4VP、ISO 18013-5 近距離、DC API）與查驗。

不做（列為停用列並寫明原因，或留到後續）：

- 加密 PDF 以 AES 加密且有使用者密碼的版型（電路要做 AES，成本高一個等級；MyData 的加密 PDF 本身沒有簽章，也不適用）。
- 無文字層的 PDF（臺北市畢業證書），zkPDF 只能證明簽章，不提供。
- Bonds 持證證明（cert\_chain\_rs4096＋user\_sig\_rs2048）：依賴行動自然人憑證 SP，且簽章材料可重放（Bonds 自列限制），維持停用列。
- 手機當 zkTLS 查驗方、多 notary 門檻、zkTLS 對隱藏值的述詞（GovBind 的綁定電路，見 p4-circuits.md 第 4.5 節）。
- BBS／bbs-2023（發行端要改簽章演算法），只保留介面位置。
- iOS（P6）。

## 4. 架構

```
app (Compose)
  FilesModel / WalletModel / ReaderModel / ZkModel(新)
        |
core (commonMain)                         core (jvmCommonMain)
  zk/        ZkCapability, ZkAssets,        zk/native/  uniffi 產生的 Kotlin 綁定（JNA），
             ZkProofEngine 介面                         Android 與 JVM 共用
  document/zkpdf/  版型、遮蔽套件、驗證
  zktls/           查驗頁描述檔、即時模式、網頁證明憑證
  profile/bonds/   BondsAgeProof（Bonds 年齡證明請求與證明包）
  oid4vp, verifier (標準路徑：mso_mdoc_zk 走 Multipaz ZkSystemRepository)
        |
native/ (Rust workspace，新)
  diw-zk-ffi    cdylib，uniffi 匯出；feature: tlsn, zkpdf, openac
  zkpdf-prover  Noir 電路執行與 UltraHonk 證明、驗證
  zktls         tlsn prover／verifier 包裝（proxy、mpc）
  openac-age    Bonds OpenACAge overlay（predicate.rs）與 zkID ecdsa-spartan2
  circuits/pdf_text_v1   Noir 原始碼（電路本身）
```

- 證明後端不綁定特定電路：`ZkProofEngine` 以後端名稱（`noir-ultrahonk`、`openac-spartan2`、`tlsn`、`longfellow`）與電路識別碼區分，之後新增或替換電路（例如以 Noir 自建的年齡述詞）不改呼叫端。OpenAC 先引入是因為已有可用的電路與資產，可以最早驗證原生建置、資產下載與 Android 打包整條管線（D5）。
- uniffi 產生的 Kotlin 綁定使用 JNA，同一份程式碼在 Android 與桌面 JVM 都能用，所以綁定放在 `core/src/jvmCommonMain`，不必寫兩份 expect／actual。原生函式庫：Android 打包 `arm64-v8a` 與 `x86_64`（模擬器）；桌面打包 linux-x86\_64、windows-x86\_64、macos-aarch64。【推論：Windows 的 barretenberg 與 tlsn 交叉編譯需在 WP0 確認】
- Longfellow 由 Multipaz 提供，不經過 `native/`。Multipaz 的 Longfellow 只有 Android arm64-v8a、x86\_64 與 JVM（macOS、linux-x86\_64），Windows 桌面版顯示為停用列。【確認：Maven 上有 `org.multipaz:multipaz-longfellow:0.101.0` 的 android 與 jvm 版本】
- 標準路徑既有的 `ResponseBuilder.findZkSystem` 與 `PresentationVerifier(zkSystemRepository)` 已能處理 `mso_mdoc_zk`，只是沒有註冊任何 ZkSystem；P4 補上註冊，不改標準流程。【確認：`core/.../oid4vp/ResponseBuilder.kt` 第 188–215 行】

### 4.1 套件邊界

| 位置 | 內容 | 不可以做的事 |
|---|---|---|
| `core/zk` | 能力偵測、資產清單與下載驗證、`ZkProofEngine` 介面、執行緒與記憶體檢查 | 不含任何文件、網站或卡片的業務邏輯 |
| `core/zk/native`（jvmCommonMain） | uniffi 產生的綁定與薄包裝 | 不手改產生的檔案；包裝只做型別轉換與錯誤對應 |
| `core/document/zkpdf` | 版型描述檔、遮蔽規劃、SHA-256 中間狀態、遮蔽套件、查驗端的結構檢查與輸出解碼 | 不在這裡驗 CMS 或信任，改呼叫既有 `DocumentInspector` 與 `TrustRegistry` |
| `core/zktls` | 查驗頁描述檔、即時模式訊息、端對端加密通道（Noise）與傳輸路徑、揭露規劃、網頁證明憑證與裝置證明紀錄 | 不放 TWDIW、Bonds 方言 |
| `core/profile/bonds/BondsAgeProof*` | Bonds 年齡證明的請求 QR、證明包、驗證 | 方言只在 Bonds 擁有的 session 生效 |
| `native/` | 證明與驗證的密碼學、電路 | 不做 I/O 決策（下載、存檔、網路連線目標由 Kotlin 決定，tlsn 的網路連線除外） |

### 4.2 標準與方言隔離（P4 補充）

- `mso_mdoc_zk`（OpenID4VP DCQL、ISO 18013-5 第二版 ZkRequest）是標準路徑，只透過 Multipaz 的 `ZkSystemRepository` 接入。
- zkPDF、zkTLS 證據都包在 IETF SD-JWT VC 裡，用一般的選擇性揭露與 KB-JWT 出示；查驗端看不懂證據時，衍生憑證仍可照一般 SD-JWT VC 驗證（證據顯示「本錢包不認識這種證據」）。
- Bonds 年齡證明的 QR 與證明包是 Bonds 自訂格式，放在 `profile/bonds`，與 TWDIW、Bonds 其他方言一樣常駐啟用、不設開關。
- 新的 vct 與證據型別名稱都用 `urn:diw-wallet:` 或本文件定義的常數，不冒用其他組織的命名空間。

## 5. 資料格式約定

### 5.1 zkPDF 證據

zkPDF 證據放在 P3 的文件衍生憑證（vct `urn:diw-wallet:vct:document-derived:1`）裡，形式是兩種 disclosure，讓持有人出示時可以選擇要不要帶：

- `zkPdf`：值為「zkPDF 證據包」（JSON 物件，見下）。只有查驗方要求這個 claim 時才揭露。
- `zkOpen:<欄位名>`：值為 `{"slot": <int>, "salt": "<base64url 16 bytes>", "src": "<base64url>"}`，是欄位 `<欄位名>` 的零知識開啟資料。持有人揭露某個 zk 欄位時，同時揭露同名欄位與它的 `zkOpen:`。

欄位本身（例如 `name`、`studentId`）仍是一般 disclosure，值是解碼後的文字；不懂 zkPDF 的查驗端照常讀取，只是無法確認它來自文件。

證據包（`ZkPdfEvidence`，JSON，鍵名固定）：

| 鍵 | 型別 | 說明 |
|---|---|---|
| `v` | 整數 | 固定 `1` |
| `type` | 字串 | 固定 `ZkPdfProof` |
| `profile` | 字串 | 版型描述檔識別碼與版本，例如 `cn.fzu.student-status/1` |
| `circuit` | 物件 | `{"name":"pdf_text_v1_1p","acirSha256":"…","vkSha256":"…","noir":"…","bb":"…"}`；查驗端只接受程式內釘選的組合 |
| `binding` | 字串 | base64url(SHA-256(衍生憑證 `cnf.jwk` 的 RFC 7638 thumbprint 的 UTF-8)) |
| `document` | 物件 | 遮蔽後的 PDF：`{"size":<原檔大小>,"zlib":"<base64url，遮蔽後檔案以 zlib 壓縮>","windows":[…]}`；私密區段在遮蔽檔中以 0x00 填滿 |
| `windows[]` | 陣列 | 每個私密區段：`{"role":"content"|"opaque","offset":<檔案位移>,"length":<位元組數>,"midIn":"hex32","midOut":"hex32","blocks":<SHA-256 區塊數>}` |
| `outputs` | 物件 | 電路的公開輸出：錨點（字型名稱、原始字串位元組、序數、總數）、欄位承諾（每個 slot 32 bytes）、述詞結果；查驗端以自己重算的值組成公開輸入，這裡只供除錯與顯示 |
| `proof` | 字串 | base64url 的 UltraHonk 證明 |
| `createdAt` | 字串 | ISO 8601 |

遮蔽後的檔案約為原檔大小（福州大學樣本 520 KB，大部分是影像與字型），所以 `zkPdf` disclosure 只適合線上出示（OpenID4VP direct\_post、DC API）與 BLE；QR 出示不帶 zkPDF 證據，畫面寫明原因。後續可用「版型資源包」把每份文件都相同的影像（學校標誌、印章）改成以 SHA-256 參照，縮小證據包。【推論】

### 5.2 zkTLS

即時模式（查驗方自己參與 TLS 連線）：

1. 查驗方顯示 QR 或連結 `diw-zktls://v1?request=<JWS>`。JWS 的 header `typ` 為 `zktls-req+jwt`，以查驗方金鑰簽章（`x5c` 或 `kid` 指向 DID），信任判定沿用 OpenID4VP 的查驗方規則。payload：`sid`、`transport`（見下）、`ck`（查驗方這次的 X25519 公鑰，base64url）、`profile`（查驗頁描述檔識別碼）、`fields`（要揭露的欄位名）、`nonce`（至少 16 bytes 隨機）、`purpose`、`mode`（`proxy`、`mpc`）、`iat`、`exp`（最長 10 分鐘）。
2. 錢包顯示同意畫面：查驗方身分、目標網站、會揭露與不會揭露的內容、需要使用者輸入的項目（例如圖形驗證碼）。
3. 需要準備步驟時（圖形驗證碼、cookie），錢包以內嵌頁面取得，內容只存在記憶體。
4. 錢包連到 `endpoint`，以 tlsn 執行 Proxy（預設）或 MPC 模式；請求內的證號、驗證碼、cookie 一律不揭露。
5. 錢包依描述檔計算揭露範圍並送出；查驗方驗證後顯示結果。查驗方在 Proxy 模式下自己連線到目標網站，所以目標網站看到的是查驗方的 IP。

持有端與查驗端之間的通道（D4，手機也能當查驗方）：

- 通道一律端對端加密：Noise `NK_25519_ChaChaPoly_SHA256`，回應方靜態公鑰為請求內的 `ck`，prologue 為請求 JWS 的 SHA-256，所以通道綁定到這一次已簽章的請求。傳輸層只負責搬運密文，不參與信任判定。
- `transport` 是陣列，列出查驗方可用的路徑，錢包依序嘗試：
  - `{"type":"wss","url":"wss://…"}`：查驗方是伺服器或電腦版（M6a，過渡方案）。
  - `{"type":"lan","host":"<私有 IPv4>","port":<埠>}`：查驗方手機在同一個區域網路（Wi-Fi 或熱點）的每個位址開啟 TCP 伺服器，直接傳 Noise 位元組，不加 WebSocket 框架（Noise 自己有長度欄位；2026-10-23 實作時由 ws 改為 TCP，Android release 不需要明文 HTTP 堆疊）。只接受 `BondsAgeRequest.lanHost` 允許的私有位址。查驗方先讀第一段資料確認是 Noise 握手再開始驗證。
  - `{"type":"relay","url":"wss://…","room":"<隨機 16 bytes base64url>"}`：雙方都連到中繼，中繼以 `room` 配對後只轉送位元組，看不到內容。中繼可由使用者的主機或測試伺服器提供（`test-servers` 內附可部署的實作），不需要信任。
- Proxy 模式下查驗方手機要能連到目標網站；MPC 模式的傳輸量大（數十 MB【推論】），手機查驗方預設 Proxy。BLE 頻寬不足，P4 不採用；WP1 量測後再評估 Proxy 模式小頁面是否可行。
- 手機查驗方的結果與電腦版相同，查驗分頁的「官方網站即時查驗」在 Android 與桌面都提供。裝置沒有 tlsn 引擎時改由查驗主機（年齡查驗主機的設定，測試環境為測試伺服器）建立請求並驗證，畫面標明結果來自主機。
- 查驗頁描述檔隨 GitHub Release 發布（2026-10-23 使用者決定）：`templates/` 的檔案由 CI 打包成 `zk-templates.jwt`（`typ` 為 `zk-templates+jwt` 的 ES256 JWS，簽章金鑰為 repo Secret `ZK_TEMPLATES_KEY`，公鑰釘選在 `ZkTemplatePack.TRUSTED_KEYS`），附在 nightly 預先發布版。App 每天檢查一次，只安裝比已安裝版本新的版型包。版型只描述版面與揭露範圍，電路仍釘選在 App 內。不在版型包內的查驗頁只能隨請求附上（`profile_def`），只在測試環境接受。

離線與存證：

| 憑證 | vct | 簽發者 | 信任 |
|---|---|---|---|
| 網頁證明（自架 notary） | `urn:diw-wallet:vct:web-proof:1` | notary 服務的 DID（使用者的主機）。notary 先以即時模式當查驗方，再把揭露的欄位簽成 SD-JWT VC，經同一條 WebSocket 交給錢包，`cnf` 是錢包提供的持有者金鑰 | T3；查驗方把該 DID 加入信任後為 T2 |
| 裝置證明的網頁紀錄 | `urn:diw-wallet:vct:web-record:1` | 錢包本身，以 Android Keystore 硬體金鑰簽章，`x5c` 為金鑰證明憑證鏈 | T3，標示「裝置證明，不是零知識證明」；D1 實測 root 機可偽造金鑰證明 |

兩種憑證的明文 claim：`source`（`host`、`profile`、`retrievedAt`、伺服器憑證鏈 SHA-256、TLS 版本與加密套件）與 `method`（`zktls-proxy`、`zktls-mpc`、`device-attested`），欄位值放 disclosure。

### 5.3 OpenAC 年齡證明（Bonds 相容）

完全沿用 Bonds 的格式【確認：Bonds-iOS `backupTW/Presentation/AgePredicateProof.swift`、`docs/zkp-web-verification-2026-09-04.md`】：

- 請求 QR：`{"a":<最低年齡>,"b":"<UUID>","c":"<nonce>","d":"<cutoff YYYY-MM-DD>","p":"<用途>","s":"g"|"s","t":<秒>,"u":"<回應網址，可省略>","v":1}`。`s=g` 為政府皮夾卡片，`s=s` 為自發卡。
- 證明包：`AgePredicateProofPackage` v1（JSON、鍵排序、日期為毫秒），欄位 `version`、`requestNonce`、`credentialSource`、`claimName`、`claimFormat`（2 為 ISO，3 為民國 YYYMMDD）、`cutoffDate`、`minimumAge`、`issuerDID`、`prepareProof`、`showProof`、`prepareMilliseconds`、`showMilliseconds`、`createdAt`。單一證明上限 2,000,000 bytes。
- 傳送：Bonds BLE（既有 `BTWVP1` 之外的 ZK 配對流程，證明包約 400 KB，只能走 BLE）或 HTTPS POST 到 `u`。`u` 只接受允許清單上的主機（預設 `verifier.mashbean.net`、本專案測試伺服器與使用者自行加入的主機），只接受 https、無帳密、無 fragment。
- 自發卡：由 Bonds 身分證卡（`BondsNationalId`）以 BONDS\_SELF\_ISSUED did:key 派生只含 `birthdate` 的 ES256 SD-JWT，再對它做證明；結果永遠標示「自發，非政府背書」。

### 5.4 mdoc ZK

只用標準格式：OpenID4VP DCQL `format: "mso_mdoc_zk"` 與 `meta.zk_system_type`，ISO 18013-5 的 `ZkRequest` 與 `ZkDocument`，由 Multipaz 處理。

## 6. 信任與判定

| 證據 | 判定依據 | 信任等級 | 畫面說法 |
|---|---|---|---|
| zkPDF | 遮蔽套件中的 CMS 簽章與憑證鏈，用 `TrustRole.DOCUMENT` 判定（例：福州大學經國富安 GFA 為 T2；國家移民管理局經 BJCA Global Root CA3 為 T2）；ZK 證明只負責「內容在簽章範圍內」 | 簽署者的等級，不會是 T1；外層衍生憑證仍為 T3 | 「○○簽章的文件第 1 頁寫著……（零知識證明）」 |
| zkTLS 即時 | 查驗方自己參與連線；伺服器憑證以系統憑證庫與內建公開根憑證驗證 | T2（`SYSTEM_ANCHOR`）；網站是否官方由描述檔的主機清單標示，不升為 T1 | 「查驗方剛剛向 ○○ 網站確認……（zkTLS，Proxy 模式）」 |
| 網頁證明（自架 notary） | notary 的 DID | T3，查驗方信任該 DID 後為 T2 | 「由持有人控制的公證服務簽發」 |
| 裝置證明紀錄 | Android 金鑰證明鏈、App 簽章憑證摘要、verified boot | T3 | 「裝置證明，不是零知識證明」 |
| OpenAC 年齡 | 證明內的發行端公鑰須等於查驗方獨立取得的公鑰（TWDIW 信任清單或 did:key） | 發行端的等級（TWDIW 已列名且鏈上相符為 T1）；自發卡 T3 | 「已滿 N 歲（零知識）」，自發卡加「自發，非政府背書」 |
| Longfellow | MSO 簽章由電路證明；IACA 憑證鏈在電路外用既有信任錨判定 | 發行端的等級 | 「已滿 18 歲（零知識）」 |

驗證失敗一律 T4，不能以勾選覆寫；信任不足（T3）時沿用 `RiskConfirmDialog`。狀態清單不適用於 zkPDF、zkTLS（文件與網頁沒有狀態清單），畫面顯示文件自身的效期欄位（例如證明的列印日期、查詢日起 30 天有效）並由查驗方政策判斷。

## 7. 隱私與可連結性

| 證據 | 查驗方看得到 | 看不到 | 可連結性 |
|---|---|---|---|
| zkPDF（D1-A） | 揭露的欄位、簽署機關與憑證、簽章值與文件摘要、檔案大小與物件結構、字型子集與 ToUnicode（可推得頁面用到的字元集合）、影像（QR 除外） | 頁面內容串流（未揭露欄位的值與位置）、QR 內容（證明編號與驗證密鑰）、未揭露欄位的長度（承諾以固定長度補齊） | 簽章值與文件摘要對同一份文件固定，不同查驗方可以串連；同一份文件無法做到不可連結 |
| zkTLS 即時 | 揭露的回應片段、網站主機、請求的方法與路徑、揭露片段的位置與長度 | 請求中的證號、驗證碼、cookie；回應的其他部分 | 揭露的欄位本身可能可連結 |
| OpenAC 年齡 | 是否已滿 N 歲、發行端 DID、claim 名稱 | 出生日期與其他欄位、持有者金鑰 | 自發卡的發行端 DID 是穩定假名（Bonds 已列為限制） |
| Longfellow | 揭露的欄位與發行端 | MSO、發行端簽章、裝置金鑰 | 證明本身不可連結；揭露的欄位可能可連結 |

zkPDF 的完整洩漏分析見 p4-circuits.md 第 3.9 節。同意畫面要以一句話列出主要洩漏，例如「查驗方可得知文件使用了哪些字元，但不知道排列與欄位」。

## 8. 裝置分級與使用者選擇

| 等級 | 條件（初始值，WP1 實測後調整） | 預設建議 |
|---|---|---|
| A | arm64-v8a 且實體記憶體至少 8 GB | 在這台裝置產生 |
| B | arm64-v8a 或 x86\_64，記憶體至少 6 GB | Longfellow、zkTLS、OpenAC（記憶體峰值 2.27 GiB）在這台裝置產生；zkPDF 依 WP1 的量測結果建議 |
| C | 其他（含 32 位元 ARM、記憶體不足） | 建議在電腦版產生 |

- 等級只決定「建議」，不禁止（D3）。開始證明前，`ZkCapability` 依電路的量測資料估計記憶體峰值、時間與下載大小，與裝置可用的記憶體、磁碟比較，算力不足時顯示選擇畫面：
  - 仍在這台裝置產生：寫明預估時間與記憶體、可能被系統中止、可隨時取消；
  - 在電腦版產生後匯入：電腦版匯出 `.zkpdf`（或其他證據檔），手機以文件 SHA-256 對上同一份文件後匯入；
  - 送到自架主機產生（只有 zkPDF；在設定的「零知識證明」頁加入主機後才出現）：主機會看到整份文件，以 `RiskConfirmDialog` 列出風險，勾選後才送出；主機以與電腦版相同的原生程式庫在無頭模式執行，回傳的證明在手機上先驗證再使用；
  - 不加零知識證據：衍生憑證照一般方式產生，並寫明隱私較低。
- 只有原生函式庫無法載入或架構不支援（沒有對應 ABI）時才無法在本機產生；畫面寫明原因，其他選項照常提供。驗證不受等級限制。
- 證明在背景執行，可取消，逾時（預設 zkPDF 10 分鐘、OpenAC 3 分鐘、zkTLS 2 分鐘，使用者選擇「仍在這台裝置產生」時改為 30 分鐘）就停止並保留可重試狀態。
- Android 以前景服務執行長時間證明，避免被系統終止【推論】；原生記憶體不受 `largeHeap` 影響。

## 9. 電路與金鑰資產

- 清單原始檔 `native/assets.json`，建置時成為資源 `zk/assets.json`（由程式碼常數 `ZkAssetManifest` 釘選它的 SHA-256）：每個項目有 `id`、`backend`、`role`（prover、verifier）、`urls`、壓縮檔 SHA-256 與大小、安裝後 SHA-256 與大小、授權。
- 下載前顯示大小並取得同意；可續傳；壓縮檔與安裝後檔案兩層都比對 SHA-256，不符就刪除；設定頁可查看與刪除。不從清單以外的位置載入任何電路或金鑰。
- 預估大小：

| 資產 | 角色 | 下載 | 安裝後 | 來源 |
|---|---|---|---|---|
| OpenAC `jwt_2k.r1cs`、`show.r1cs`、prepare／show proving key | 持有端 | 約 53 MB | 約 815 MB | Bonds `openac-age-v1`【確認】 |
| OpenAC `jwt_2k`、`show` 見證計算圖 | 持有端 | 約 30 MB | 約 94 MB | 本專案 `openac-age-graph-v1`（WP7） |
| OpenAC prepare／show verifying key | 兩端（持有端自驗） | 約 24 MB | 約 437 MB | 同上【確認】 |
| zkPDF ACIR 與驗證金鑰 | 兩端 | 數 MB【推論】 | 數 MB | 本專案建置，隨 App 或 release 發布 |
| UltraHonk 的 BN254 SRS（Aztec 公開儀式） | 持有端 | 依電路大小，2^22 點約 256 MB【推論】 | 同左 | Aztec 公開檔案，SHA-256 釘選 |
| Longfellow 電路 | 兩端 | 約 1 MB | 同左 | Multipaz 內建【確認】 |
| tlsn | 兩端 | 0（只有原生程式碼） | — | — |

## 10. 介面約定（摘要）

Kotlin 介面以 p4-work-packages.md 為準，這裡只列共同規則：

- 所有證明 API 是 `suspend` 函式，在 `Dispatchers.Default` 以外的專用執行緒池執行，回傳 `ZkResult<T>`（成功、可重試失敗、不可重試失敗、使用者取消）。
- 產生證明後一律在本機先驗證一次，失敗就丟棄（Bonds 實測上游 prover 在約束不成立時仍會產出同大小的證明）。
- 查驗端不信任證明包附帶的公開輸入，一律自己重算後交給驗證器。
- 私密輸入（PDF 內容、cookie、證號、出生日期、鹽值）只在記憶體與 App 私有目錄的暫存檔，證明結束即刪除；不得寫進紀錄、log、例外訊息或當機報告。
- 錯誤訊息給使用者看的部分用繁體中文，原生層的錯誤碼對應在 `core/zk` 的一個表裡。

## 11. UI 約定

依 AGENTS.md 規則 10、11，不另開專區：

- 文件分頁：文件詳情的「產生 zkPDF 證明」在有對應版型時啟用，否則維持停用列並寫明原因（沒有對應版型、文件已被修改）。算力不足時不停用，改顯示第 8 節的選擇畫面。產生衍生憑證時多一個選項「加入 zkPDF 證據」。「產生 zkTLS 證明」在文件有對應查驗頁時啟用。
- 使用分頁：「年齡證明（零知識）」掃描 Bonds 年齡請求 QR；「以官方網站證明（zkTLS）」掃描查驗方 QR。
- 查驗分頁：查驗結果的證據卡新增 zkPDF、zkTLS、裝置證明紀錄、OpenAC、Longfellow；Android 與電腦版都有「官方網站即時查驗」；年齡查驗產生 Bonds 相容 QR。
- 加入證件畫面的「年齡證明（零知識）」與文件畫面的兩個停用列，在功能完成後改為啟用。
- 設定：「安全與隱私」組（`SettingsSection.SECURITY`）加入「零知識證明」頁，顯示裝置等級、已下載的資產與大小、刪除、各後端版本與自架主機；設定清單的摘要列出裝置等級。
- 證據卡沿用判定卡設計，「部分」不可看起來像「通過」；ZK 證據另以文字標示「零知識證明」，不用新顏色。
- 紀錄只寫欄位名稱與證據種類，不寫值。

## 12. 驗收（P4 整體）

- 中階 Android 機（等級 B）完成：zkTLS 即時出示（學信網）兩次，一次電腦版當查驗方、一次另一支手機當查驗方（區域網路與中繼各一次）；一次 OpenAC 年齡證明出示並由本 App 與 Bonds 查驗通過、一次 Longfellow mDL 年齡出示並驗證。
- zkPDF：福州大學在學證明產生證據（手機或電腦版，畫面標明在哪裡產生），另一台裝置查驗通過，只揭露選定欄位；竄改遮蔽套件的任一位元組、換用他人的 `cnf`、改錨點序數都會被拒絕。
- 所有負向測試列在 p4-circuits.md 的測試清單，並在 `test-servers` 以合成文件與測試 PKI 執行。
- 驗收紀錄寫在 `docs/acceptance/p4-acceptance.md`。

## 13. 風險

| 風險 | 影響 | 對策 |
|---|---|---|
| zkPDF 在手機的記憶體與時間 | 等級 B 以下可能做不出來 | WP1 先量測；證明只做一次；由使用者選擇本機、電腦版或自架主機（第 8 節） |
| 手機查驗方的連線 | 兩支手機不在同一網路、電信商 NAT | 區域網路與中繼兩條路徑；中繼只轉送密文，可自架 |
| TLSNotary 仍是 alpha，行動 SDK 未發布，TLS 1.3 暫停 | 目標網站改 TLS 1.3 就不能用；API 變動 | 釘選 commit；描述檔記錄 TLS 版本；網站升級時顯示停用原因 |
| Barretenberg 預設的 UltraHonk 不是零知識版本【推論】 | 證明可能洩漏私密輸入 | WP1 確認 bb 的零知識設定，驗收時以版本與參數記錄 |
| OpenAC 資產大（安裝後約 1.35 GB，含見證計算圖），峰值 2.27 GiB | 低階機無法使用 | 下載前同意、可刪除、裝置分級 |
| 查驗頁或版型改版 | 描述檔失效 | 描述檔有版本，失效時停用並寫明原因；測試用合成樣本 |
| zkTLS 結果無法定效力 | 使用者誤解 | 畫面寫明「技術證據，不等於官方證明書」 |
| 原生函式庫讓 APK 變大 | 下載與安裝負擔 | 依 ABI 分包；CI 變更以完整檔交給你貼上 |

## 14. 參考

- 既有研究：[document-credentials.md](document-credentials.md)、[architecture-and-roadmap.md](architecture-and-roadmap.md)、[../research/zkp-verifier.md](../research/zkp-verifier.md)、[../research/bonds.md](../research/bonds.md) 第 7 節。
- [TLSNotary releases](https://github.com/tlsnotary/tlsn/releases)：v0.1.0-alpha.15 加入 Proxy 模式；alpha.13 移除 notary-server，attestation 移到不再新增功能的獨立 crate；alpha.11 起有 SHA-256 承諾。
- [TLSNotary Proxy mode](https://tlsnotary.org/blog/2026/04/22/proxy-mode/)、[TLSNotary 介紹](https://tlsnotary.org/docs/intro/)（只支援 TLS 1.2）。
- [GovBind，eprint 2026/2206](https://eprint.iacr.org/2026/2206)：對私密區段分別承諾、公開其餘位元組、要求完整分割，並在版型專用的證明內約束 DEFLATE 解壓縮。
- [Noir 黑箱函式](https://noir-lang.org/docs/libraries/standard_library/black_box_fns)：`sha256_compression(input: [u32; 16], state: [u32; 8])`。
- [Mopro 效能](https://zkmopro.org/docs/0.2/performance/)：Pixel 6 上 Noir RSA 約 1.1 秒。
- [Bonds-iOS Native/OpenACAge](https://github.com/bonds-tw/Bonds-iOS/tree/main/Native/OpenACAge)（Apache-2.0）、zkID commit `b395e09c225ff45b003f0087c28e2e208e22f944`。
- [privacy-ethereum/zkID](https://github.com/privacy-ethereum/zkID)（MIT）。

# 全專案 Review 後續規劃（2026-10-29）

來源是外部 Agent 的全專案 Review 報告（使用者 2026-10-29 提供）。每一項都先對照 P4 整合分支的程式碼查證，報告與現況不同的地方以本文件為準。A 類已修正，B、C 類是研究與規劃，實作順序由使用者決定。

## 查證結果

| 報告項目 | 查證 | 處理 |
|---|---|---|
| OpenID Federation 不支援 | 屬實：`RequestValidator` 遇到 `openid_federation` 用戶端識別直接拒絕 | B5 |
| JWE 要求物件無法解密 | 已過時：PR #11 起 `Oid4vpHolder` 有解密金鑰登錄，加密要求物件可用 | 無 |
| `withHashAlgorithm` 補償 | 屬實，為相容 Multipaz 回應格式的刻意補償 | 無 |
| TrustManager 只接受 EC | 部分屬實：自訂 TrustManager 只處理 EC，RSA 憑證鏈由平台 PKIX 驗證補上，結果正確 | 無 |
| SD-JWT VC 一定要 nbf | 找不到要求 nbf 的程式路徑，沒有 nbf 的憑證可正常匯入 | 無 |
| Twdiw-Signature 未實作 | 已過時：`TwdiwDialect.outboundCredentialHeaders` 已用本 App 自己的金鑰簽；缺的是向 `api/did` 註冊裝置金鑰 | TWDIW 註冊 |
| `.en`、`.esw` 不支援 | 屬實：電子公文只認 DI、SI、SW、CO、DM | B6 |
| CI Action 未釘選、下載檔未驗證 | 屬實 | A1 已修正 |
| 依賴 CVE | 見 A4 | A4 已處理 |

## A. 已修正

1. **CI 供應鏈**：第三方 Action 全部釘 commit SHA，circom 等直接下載的執行檔加 SHA-256 驗證。依賴更新改由 Renovate 開 PR，minor 與 patch 在發布滿三天且 CI 通過後自動 Squash 合併；major、Kotlin、Compose、AGP、Multipaz、Ktor、Credential Manager 與 DC API 需人工核准。安全性更新由 Dependabot 處理並自動合併（非 major）。
2. **Multipaz 測試發證端（issuer.multipaz.org）**：根因是伺服器只信任 Multipaz 自己的用戶端金鑰、錢包證明與金鑰證明根憑證，任何第三方錢包都會在 PAR 被拒。新增預設關閉的「Multipaz 測試身分」（設定 → 開發者），只在測試環境、只對 issuer.multipaz.org 使用 Multipaz TestApp 公開的測試金鑰。2026-10-29 實測 `pid_sd_jwt` 與 `pid_mdoc` 領卡成功（attest_jwt_client_auth 加 DPoP）。
3. **用戶端驗證與 DPoP 顯示**：每張卡記錄 token 端點的用戶端驗證方式與存取權杖類型，詳細資訊頁顯示。DPoP（RFC 9449）原本就已實作，AS 與 RS 呼叫都附 DPoP，`use_dpop_nonce` 重試一次。
   - 同時修正兩個 Credo（Animo）互通問題：AS 中繼資料沒列驗證方法時也送錢包證明；proof 有 `key_attestation` 時一併放 `jwk`。Animo playground 13 種卡型領卡成功；信任等級為 T3，因為 Animo 的根憑證（CN=Animo, C=NL）不在錨點內，可視需要加為測試錨點。
4. **依賴 CVE**（OSV 資料庫，2026-10-29）：
   - App 本體（Android release、桌面版 runtime classpath）：沒有命中。
   - Netty 4.2.7（Ktor 3.3.3 帶入，只用於測試伺服器、桌面測試與正式服務端）：34 筆，含 1 筆 Critical（CVE-2026-75595 SNI 路由繞過）與多筆 HTTP 請求走私。以 Netty BOM 釘到 4.2.19.Final，OSV 查無公告。正式服務端在 diw-wallet-server PR #9。
   - 原生 Rust crate：沒有高風險命中。crypto-bigint 0.5.5（RUSTSEC-2026-0387 時序，經 elliptic-curve 0.13）、block-buffer 0.10.4（中）、tracing-subscriber 0.2.25（低，CVE-2025-58160）與幾個已停止維護的 crate，都要等上游升級。

## TWDIW 生態系簽章註冊

- 現況：Twdiw-Signature 由本 App 自己的金鑰簽，預設只對 moda.wallet.gov.tw 加上；後端回 500/11021 的原因推測是金鑰沒有註冊。
- 做法：用本 App 的 Android Keystore 金鑰（StrongBox 優先，否則 TEE，沒有硬體時用軟體兜底金鑰）呼叫 `api/did` 註冊並保存 keyId；簽章前向 `api/ext/nonce/generate?type=ecosyst` 取 nonce；標頭依官方 App 格式（ES256、payload 七欄依字母排序後 compact、簽章為 64 位元組 r||s）。
- 界線：appHash、appPlatform、appVersion 填本 App 自己的值。後端若因此拒絕，記錄結果，不改成冒充官方 App。
- 需要使用者提供：官方 App 1.0.14 的 `api/did` 請求與回應（欄位、標頭、錯誤碼），以及 nonce 完整網址與回應（確認 `type=ecosyst` 是否完整）。

## B. 標準補全

### B5 OpenID Federation 1.0（2026-10-29 已實作出示端）

- 已完成：`core/federation` 的 `FederationResolver`（信任鏈建立與驗證、`trust_chain` 標頭、constraints、metadata 覆寫）與 `MetadataPolicy`（七個標準運算子的合併與套用、`metadata_policy_crit`）；`RequestValidator` 以解析後的 Verifier jwks 驗證 `openid_federation:` 請求；「自訂信任」可加入 Trust Anchor（顯示金鑰指紋確認，USER 為 T2、TEST 為 T3）。測試在 `test-servers` 的 `FederationTest`（Trust Anchor、中介、Verifier 三層，涵蓋政策、離線鏈、錯誤金鑰、無錨點、路徑長度與政策衝突）。
- 尚未做：`signed_jwks_uri`／`jwks_uri`、Trust Mark 驗證（目前只記錄類型）、發證端中繼資料走聯邦、TrustRegistry 層的統一錨點類型（目前在 federation 模組內以相同 tier 規則判定）。
- 以下為原規劃。

- 規格：OpenID Federation 1.0 已於 2026-02-17 定稿；OpenID4VP 1.0 的 `openid_federation:` 用戶端識別依此驗證。EUDI 的信任框架也規劃用它。
- 做法：
  - 取 Entity Configuration（`/.well-known/openid-federation`，`application/entity-statement+jwt`），沿 `authority_hints` 向上取 Subordinate Statement，直到使用者信任的 Trust Anchor。
  - 驗每一層簽章、`exp`、`jwks`，套用 `metadata_policy`（`value`、`add`、`default`、`one_of`、`subset_of`、`superset_of`、`essential`）與 `constraints`（`max_path_length`、`naming_constraints`），最後得出 `openid_credential_verifier` 或 `openid_credential_issuer` 的中繼資料。
  - Trust Mark 只顯示，不影響信任等級。
- 接入：`TrustRegistry.decide` 增加「Federation Trust Anchor」錨點類型（含 TEST 環境），結果與 X.509 錨點同樣分 T1 到 T3。`RequestValidator` 改為解析後驗證，不再直接拒絕；發證端中繼資料也可走同一條路。
- 函式庫：Sphereon 的 OpenID-Federation 是 Kotlin Multiplatform（Apache-2.0），但同時含伺服器、依賴多。建議自行實作解析與驗證（約 600 到 900 行），沿用既有的 JOSE 與 HTTP 程式碼，再用 Sphereon 或 Nimbus 產生的測試資料比對。
- 測試：test-servers 加一個 Trust Anchor、一個中介、一個 Verifier 的聯邦；驗收要涵蓋 policy 合併、過期、迴圈與深度限制。
- 工作量：中（3 到 4 個工作階段）。

### B6 電子公文 `.en`、`.esw`

- 性質：依《文書及檔案管理電腦化作業規範》，EN 是信封檔（XML，記收發文機關與文書資訊），ESW 是加密交換表單檔（記收文機關憑證卡號與加密後內容）。兩者都是公文交換系統以機關憑證（GCA）產生的交換用檔案，不是個人簽核文件。
- 建議範圍：
  - EN：匯入、解析、結構化預覽，放進公文容器並與 DI、SW 關聯（沿用「加入前由使用者確認」的規則）。
  - ESW：辨識格式並顯示收文機關憑證卡號；只有使用者持有該機關憑證的私鑰（PKCS#12 或卡片）時才解密，解密後內容依 SW 處理。
  - 產生與加密封裝：需要機關憑證與交換中心註冊，個人錢包不做。
- 需要使用者提供：EN、ESW 樣本各一份（可去識別化），以及規範附件中的 DTD 版本。
- 工作量：小到中（EN 1 個工作階段；ESW 視樣本而定）。

### B7 NFC 近距離出示實機測試

- 現況：`WalletNfcService`（HCE，ISO 18013-5 NFC 交握）已實作，但沒有完整的實機互通紀錄。
- 做法：以 Multipaz Verifier App 或 EUDI 參考 Verifier 對實機測 NFC 交握加 BLE 資料傳輸，以及 NFC 靜態交握；測試項目補進 `docs/research/device-test-checklist.md`。
- 需要使用者：兩台裝置或一台裝置加讀卡機。
- 工作量：小（測試為主，修正視結果而定）。

## C. 新需求（請使用者排序）

### C8 PIV（YubiKey）簽章

- 函式庫：Yubico YubiKit for Android 3.2.1（2026-09-08，Apache-2.0，minSdk 21，本專案為 29）。透過 USB 或 NFC 建立 `SmartCardConnection`，`PivSession` 驗 PIN 後用 9C（Digital Signature）槽簽章；也提供 JCA Provider，可直接接 `DocumentSigner`。
- 做法：新增 `PivDocumentSigner`（Android 專用，放 androidMain），讀 9C 槽憑證當簽署者憑證，支援 RSA 2048 與 P-256／P-384；簽章時提示插入或靠卡，PIN 錯誤次數顯示剩餘次數。桌面版可用 PC/SC（javax.smartcardio）走同一套 APDU，列為次要。
- 接入：PAdES、CAdES、XAdES 與 .si 簽核點都經 `DocumentSigner`，不需要各別修改；信任評定沿用簽署者憑證鏈。
- 需要使用者：一支已在 9C 槽放好憑證的 YubiKey 做實機驗收。
- 工作量：中（2 個工作階段）。

### C9 匯出直接分享（2026-10-29 已實作）

- 文件、文件與證據、公文容器、OpenCerts 附件與身分證卡都加上「分享」（Android）。尚待實機確認分享到常用 App（Gmail、LINE、雲端硬碟）時檔名與內容正確。


- 現況：Android 只處理收到的 `ACTION_SEND`；匯出一律存檔。
- 做法：匯出時寫入 App 快取下的專用分享目錄，用 `FileProvider` 產生 content URI，以 `ACTION_SEND`／`ACTION_SEND_MULTIPLE` 分享（中文檔名放在 `EXTRA_TITLE` 與 `ClipData`，保持 UTF-8）。分享畫面關閉、App 回到前景或下次啟動時清空目錄。桌面版維持另存新檔。
- 工作量：小（1 個工作階段）。

### C10 CSC API 補全與 CSC Profile

- 現況：`Csc.kt` 已支援 CSC API v2 的 OAuth 2.0 授權碼、`credentials/list`、`credentials/info`、`credentials/authorize`、`signatures/signHash`，相容 v1 的 PIN 與 OTP 欄位，內建 EUDI 測試服務。
- 補全：CSC API v2 後續版本的 `oauth2/pushed_authorize`（PAR）、RFC 9396 `authorization_details`（credential 範圍授權）、`signatures/signDoc`、`signatures/timestamp` 與非同步簽章回應。實作前以 CSC 官網最新版 PDF 逐一核對端點與參數。
- CSC Profile：讓使用者只輸入服務網址，其餘從 `info` 與 RFC 8414 中繼資料自動推導；常見服務（EUDI、各國 QTSP）提供內建 Profile 檔（端點、client_id、redirect URI、支援的 authType 與簽章演算法）。台灣目前沒有公開的 CSC 服務，先保留 Profile 格式讓之後加入。
- 工作量：中（2 到 3 個工作階段），需要能測的服務；沒有的部分以 test-servers 模擬。

### C11 C2PA 與 CAWG

- 函式庫：Content Authenticity Initiative 的 c2pa-android 1.0.0（Kotlin 包裝 c2pa-rs C API，Apache-2.0 或 MIT，minSdk 28），可從檔案或串流讀取並驗證 manifest。
- 做法：圖片與 PDF 檢視時讀取 C2PA manifest，顯示簽署者、產生工具、動作紀錄（actions）、成分（ingredients）與驗證結果；CAWG 身分斷言顯示身分與綁定方式。簽署者憑證以現有 TrustRegistry 評定，並加入 C2PA 信任清單作為錨點來源。
- 限制：原生函式庫會增加 APK 大小（需實測），桌面版需另外打包 c2pa-rs；先只做讀取與驗證，不做寫入。
- 工作量：中（2 個工作階段）。

### C12 PDF 可見簽章

- 現況：簽署時的簽章欄位 Rect 為零（不可見）；驗證時列出簽章但不顯示位置。
- 檢視：解析每個簽章 widget 的頁碼與 Rect，在預覽頁上框出位置並可點選對應的驗證結果。
- 加入可見簽章（可選）：使用者在預覽頁選頁與位置，產生外觀串流（簽署者姓名、時間、可選圖片），寫入 `/AP`；其餘流程不變。
- 工作量：檢視小（1 個工作階段），加入可見簽章中（1 到 2 個工作階段）。

### C13 Payment（2026-10-29 已實作）

- 已登錄 `PaymentTransaction`（`WalletTransactionTypes`），同意畫面列出交易內容，KB-JWT 帶交易資料雜湊；端對端測試 `paymentTransactionIsDescribedAndBound`。尚待以 Multipaz 付款測試卡加真實 Verifier 驗收。


- 標準：EUDI TS12「SCA Implementation with the Wallet」的交易資料型別 `urn:eudi:sca:payment:1`；EMVCo 2026-06 公布的 Digital Payment Credential Schema Framework 草案仍在徵詢意見。
- 現況：OpenID4VP 的 `transaction_data` 已支援（目前登錄 QES 兩種型別）。Multipaz 0.101 的 multipaz-doctypes 已有 `PaymentTransaction`（TS12），issuer.multipaz.org 也提供 `payment_sca_mdoc` 與 `payment_sca_sd_jwt` 測試卡，開啟 Multipaz 測試身分即可領。
- 做法：登錄 `PaymentTransaction`，出示同意畫面顯示收款方、金額、幣別、交易時間與 PISP，回應附交易資料雜湊；EMVCo DPC 等定稿後再補。
- 工作量：小（1 個工作階段），可先以 Multipaz 測試卡加測試 Verifier 驗收。

### 互通對象：France Identité

- playground 的流程需要錢包先完成合作夥伴登錄，之後以 `https://idp.france-identite.gouv.fr/credentials-request#...` 深層連結經 Credential Manager 收卡（協定 `openid4vci1.0`），交換包含 challenge、token（DPoP 加用戶端證明）、nonce 與加密的 credential request／response（JWE）。
- 本錢包的協定都已具備，缺的是合作夥伴登錄。登錄是對外申請，需要使用者決定是否進行。

## 建議順序

C13 Payment 與 C9 直接分享（小、可立即驗收）→ TWDIW 註冊（等使用者提供資料）→ B5 OpenID Federation → C12 可見簽章 → C8 PIV → C10 CSC → B6 `.en`／`.esw`（等樣本）→ C11 C2PA → B7 NFC 實機測試（等裝置）。

# AGENTS.md

給在此 repo 工作的程式代理（與新進開發者）的說明。使用者文件見 [README.md](README.md)，設計、研究與驗收文件的索引見 [docs/README.md](docs/README.md)。

## 溝通與輸出

- 與使用者交談一律使用繁體中文；程式碼註解、識別字、commit 訊息使用英文。
- 程式碼不可使用 emoji 或特殊符號；App 介面字串使用繁體中文。
- 交付完整實作，不留框架或 TODO 佔位。
- 在 Windows 執行指令前確保 UTF-8（`chcp 65001`、`-Dfile.encoding=UTF-8`）。

## 模組

| 模組 | 內容 |
|---|---|
| `core/src/commonMain` | 協議與信任核心，不依賴 UI |
| `core/src/jvmCommonMain` | JVM 與 Android 共用的密碼學實作 |
| `app/src/commonMain` | Compose Multiplatform App：`WalletModel`（狀態、流程、紀錄）、`TaiwanModel`（TWDIW 平台服務與 Bonds）、`MsIssuanceModel`（Verified ID）、`ProximityModel`（ISO 18013-5 出示與 DC API Annex C）、`ReaderModel`（ISO 18013-5 查驗）、`StatusMonitor`、`History`（紀錄）、`FilesModel`（文件保存、檢查、時戳、簽署、衍生憑證、取件入口）、`ui/` |
| `app/src/androidMain`、`desktopMain` | 平台實作（相機掃描、硬體金鑰、DC API、Bonds BLE、圖片解碼、NFC：Android 的 HCE `WalletNfcService`、讀卡模式與 USB CCID `AndroidNfcReaders`，桌面的 PC/SC `PcscReaders`；取件入口 `PortalWebView`、檔案選取與儲存） |
| `app/src/desktopTest` | 以桌面 JVM 跑 App 流程測試 |
| `test-servers` | 測試用發證端、驗證端、Wallet Provider，以及全部協議測試 |

`core` 內的主要套件：

| 套件 | 職責 |
|---|---|
| `oid4vci` | OpenID4VCI 1.0 用戶端（`Oid4vciClient`），中繼資料、offer、DPoP、wallet attestation |
| `oid4vp` | OpenID4VP 1.0（`Oid4vpHolder`、`RequestValidator`、`ResponseBuilder`） |
| `oid4vp/ext` | 1.0 以外的出示：Presentation Exchange、自有 DCQL、舊版要求、SIOPv2、W3C 出示 |
| `compat` | 發證方言：`Draft11Dialect`、`Draft13Dialect`、`TwdiwDialect`、`EudiDialect` |
| `oid4vp/compat` | 出示方言：`TwdiwPresentationDialect`、`MsVerifiedIdPresentationDialect` |
| `profile/twdiw` | TWDIW 信任清單、Arbitrum 錨定、入口解析、平台服務（卡片目錄、DWVP-05 離線條碼） |
| `profile/bonds` | Bonds 離線出示、BTWVP1 QR 與 BLE 分幀、vc+moica 驗證、身分證卡（`BondsNationalId`）、vc+moica 線上出示（`BondsMoicaOnline`）；來源 `a`（本錢包擴充：IETF SD-JWT VC、W3C SD-JWT 與 JWT VC） |
| `profile/msvid` | Microsoft Entra Verified ID 發行、Linked Domains |
| `document` | 文件檢查（`DocumentInspector`、`DocumentReport`）：PAdES、CAdES（.p7s / .p7m）、XAdES 與 XMLDSig、ASiC、OFD 與 SES 電子印章、RFC 3161 時戳、OpenCerts、國密 SM2 |
| `document/pdf` | 純 Kotlin PDF 解析（加密含使用者密碼、增量更新、xref stream）、文字擷取（`PdfTextExtractor`）、增量簽署（`PdfWriter`）、產生 PDF（`PdfComposer`）、預覽用的解密副本（`PdfPlain`） |
| `document/sign` | 簽署（`DocumentSigning`：PAdES B-B 到 B-LTA、CAdES、ASiC-E、XAdES、公文線上簽核點、自簽憑證）、`DocumentSigner`、TSA（`TsaServices`、`TsaClient`）、長期驗證資料（`ValidationCollector`、`ValidationData`） |
| `document/card` | 自然人憑證卡（`GpkiCard`，第一代與第二代含 SCP03）、`GpkiTapSigner`（NFC 兩次感應）、`CardChannel` |
| `document/derived` | 文件衍生憑證（`DerivedCredentials`：SD-JWT VC 與 vc+moica）、由文件內容解析欄位（`DocumentFields`）、證據查驗（`DerivedEvidence`） |
| `document/opencerts` | OpenCerts（OpenAttestation v2／v3）完整性、欄位整理（`OpenAttestationDocument`）、以太坊與 DNS 線上查驗（`OpenAttestationOnline`）、發證機構顯示程式宿主頁（`OpenCertRenderer`） |
| `document/official` | 電子公文「函」XML（`OfficialLetter`，DTD 104_2_utf8） |
| `w3c`、`status`、`trust`、`did`、`holder` | W3C VC、狀態清單、信任錨與 DID 信任、DID 解析、錢包層級持有者金鑰 |

## 已定的設計規則

1. **標準優先，方言隔離。** 標準路徑（OpenID4VCI / OpenID4VP 1.0、SD-JWT VC、mdoc）不含任何方言邏輯。方言只在標準會停下的位置透過 hook 介入（`IssuanceDialect`、`PresentationDialect` 的介面註解列出每個 hook），而且只對它擁有的 session 生效。
2. **所有方言常駐啟用，不提供開關。** TWDIW 官方實作與 Bonds 必須完整支援；新增方言時加入 `WalletModel` 的方言清單，不新增設定。
3. **信任分層。** T1 官方清單並經額外驗證（TWDIW 已列名且 Arbitrum 註冊相符、標為官方的正式錨點）；T2 連到信任根（內建 GPKI、系統憑證庫與內建公開根憑證、AATL 與 EUTL、內建的正式發行端、Linked Domains、使用者匯入的根憑證與信任的 DID，以及 TWDIW 已列名但鏈上註冊無法確認或角色不符）；T1 與 T2 視為高可信（`TrustTier.highlyTrusted`）；T3 可驗證但沒有連到信任根（未列名 DID、不在任何清單的憑證鏈）與所有測試錨；T4 驗證失敗（簽章或憑證鏈不成立、未簽章要求、清單與鏈上不符、網域連結失效）。中繼憑證（`BuiltInPublicRoots.intermediates`，含 e簽寶等線上簽核平台，或使用者匯入）只補足憑證鏈，等級由最後連到的根憑證決定；`importableRoots` 是不在任何計畫內的根憑證，只用來補鏈，使用者匯入後才信任。低信任的操作不禁止：`ui/RiskConfirm.kt` 的 `RiskConfirmDialog` 列出風險，勾選承擔後才可繼續（使用者可能有自己的特殊環境）。畫面上的說明集中在 `ui/TrustViews.kt`（`tierAdvice`、`issuerTrustLine`、`TierLegend`），修改分層時一併更新。正式與測試環境在同一個 App 內，UI 必須區分；測試環境的決策永遠不是官方。
   - 內建的 GPKI 錨點（`trust/BuiltInAnchors`，由 grca.nat.gov.tw 取得的運作中根憑證與中繼憑證）只確認身分，判定為 T2 並標示 `IDENTITY_VERIFIED`；MOICA（自然人憑證）用於查驗方與文件簽章，不用於發行端。
   - 系統憑證庫（`TrustEnvironment.SYSTEM`，設定可關閉）只確認網域，判定為 T2（`SYSTEM_ANCHOR`）。同一個環境還包含三組內建公開根憑證（`trust/BuiltInPublicRoots`，比對由 `trust/PublicRoots` 負責）：
     - 常用服務憑證鏈的根憑證，跟著系統憑證庫的開關；
     - 中國大陸憑證機構，有獨立開關，預設開啟，加上 `MAINLAND_CHINA_CA` 標籤。內容包括 Mozilla 或 Microsoft 根憑證計畫收錄的 CFCA、GDCA、SHECA、BJCA、iTrusChina、TrustAsia，以及持牌 CA 在官網公布的國密 SM2 根憑證。
     - 時間戳記憑證機構：CCADB 中 Microsoft 根憑證計畫收錄且 EKU 含 Time Stamping 的根憑證，只用於 `TrustRole.TSA`，跟著系統憑證庫的開關。
     - `BuiltInPublicRoots.kt` 由 `tools/trust-roots/update_roots.py` 產生，不手動修改：CCADB 依 `roots.json` 的機構挑選中國大陸 CA；服務主機實際連線取得憑證鏈的根憑證（連不上時沿用 `services.lock.json`）；SM2 根憑證以 `tools/trust-roots/sm2/*.pem` 與 SHA-256 釘選；不在 CCADB 的其他根憑證列在 `roots.json` 的 `pinned`（`tools/trust-roots/pinned/*.pem`，SHA-256 釘選、須自簽且為 CA，歸入中國大陸憑證機構），例如 BJCA Global Root CA3（國家移民管理局電子文件經 BJCA DocSign CA3 簽發）與 ZJCARoot（e簽寶時戳服務 timestamp.esign.cn 經 ZJCA OCA3 簽發）。e簽寶合作 CA 由 `roots.json` 的 `bundles` 取得：從 e簽寶說明頁（`page`，連結以 `\u002F` 跳脫寫在 `window.__INITIAL_STATE__` 內）找出最新的「eSign-Partnered-CA-Root-Certificates-日期.zip」（阿里雲 OSS），資料夾名稱為 GBK，`exclude` 排除模擬與測試 CA；新的正式 CA 憑證自動加入設定並存成 `tools/trust-roots/esign-partners/<名稱>-<SHA-256 前 8 碼>.pem`（自簽 SM2 根憑證歸入 `sm2`、其他根憑證歸入 `pinned`、其餘為中繼憑證，以 `subjectDN` 區分同名憑證），新的根憑證發出警告要人核對，中繼憑證只記錄。目前內建 12 個合作根憑證（CFCA、國富安 GFA、天威誠信、浙江 ZJCA、e簽寶、安徽、河北、黑龍江、西部、北京數字認證 SmartCA、珠海 ZHCA 等）與 35 個中繼憑證，包含學校簽章用的 OPERATION CA04 FOR GFA TRUST NETWORK（RSA 與 SM2），所以 e簽寶平台上國富安簽發的文件連到 GFA 根憑證，判定為 T2。國富安官網只提供根憑證，中繼憑證取自這個憑證包。中繼憑證可由另一個已接受的中繼憑證簽發（多層），執行時 `TrustRegistry.extendFromPool` 也會逐層補鏈。openssl 3 驗證 SM2 憑證簽章要加 `-vfyopt distid:1234567812345678`。每次執行都以各項目的 `url` 核對釘選檔：同一把金鑰重新簽發的根憑證、由內建或可匯入根憑證簽發的同名中繼憑證自動替換檔案與 `roots.json` 的 SHA-256；不同金鑰的新根憑證不替換，沒有 `sha256` 的新項目首次取得時寫入並發出警告，都要人核對；來源無法連線時沿用釘選檔。GPKI 只檢查並回報（以公鑰比對，GRCA 換金鑰的連結憑證不算新憑證）。內容沒有變更時不改檔案與 `UPDATED` 日期。測試檢查指紋、自簽章（SM2 以 BouncyCastle）與 `UPDATED` 當天的有效期；執行時已過期的內建根憑證不再當成錨點。
   - 國密憑證（SM2 金鑰、SM3withSM2 簽章，OID 1.2.156.10197）由 `Pkix` 改用 BouncyCastle 驗證；provider 以實例使用，不註冊為全域。JOSE 與 COSE 沒有定義 SM2，這些錨點目前只用於憑證鏈驗證。
   - Multipaz 的 TrustManager 只支援 EC 金鑰，RSA 憑證鏈在它丟出例外時改用 PKIX（`trust/SystemTrustStore` 的 `Pkix`）驗證。
   - 文件簽章信任清單（`trust/TrustLists`、`trust/TrustListLoader`，App 的 `TrustListsModel`；設定可分別關閉，預設開啟），只用於 `TrustRole.DOCUMENT` 與 `TSA`，在 USER 之後、SYSTEM 之前比對，結果為 PRODUCTION 非官方（T2），標籤 `AATL`、`EUTL`、`EU_QUALIFIED`：
     - AATL：`tl12.acrobatsecuritysettings` 是 PDF，簽章須涵蓋整個檔案並連到 SHA-256 釘選的 Adobe Root CA G2，清單取自內嵌的 SecuritySettings.xml；Identity 列出 CertificatePolicies 時，憑證鏈須帶有其中一個 OID。
     - EUTL：LOTL（ETSI TS 119 612）的 XAdES 簽署憑證須是釘選的 6 張之一，或上一份已驗證的 LOTL 公告的簽署憑證；各國清單須由 LOTL 指向該國的憑證簽署，且國別相符（德國清單用 RSASSA-PSS，`XmlDsig` 支援 `sha*-rsa-MGF1`）。CA/QC 只供文件簽章，只服務網站憑證的 CA 排除；TSA/QTST 只供時戳。依 ServiceStatus 與 ServiceHistory 中 granted、undersupervision、accredited、supervisionincessation 的期間判定簽署當時是否核准。
     - 快照（`TrustListSnapshot`）存在儲存區 `DiwTrustLists`，開啟 App 時載入；每週（或過了清單公告的下次更新）以 ETag／Last-Modified 條件下載，LOTL 未變時各國清單以上次記錄的簽署憑證指紋更新。失敗時保留上一份並在設定顯示原因。EUTL 首次下載約 27 MB、快照約 8 MB、約 3500 個服務。
     - LOTL 簽署憑證含歐盟職員姓名，repo 只放 SHA-256；AATL 檔案不放進 repo。`TrustListsTest` 以測試 PKI 產生清單。
   - Microsoft Verified ID 依 Microsoft 錢包程式庫的規則：Linked Domains 驗證成功為 T2（`LINKED_DOMAIN`），與 Authenticator 一樣不需要額外勾選警示；驗證失敗為 T4。使用者自行信任的 DID 排在 Linked Domains 之前，連結暫時失效不會蓋過使用者的決定。
   - 內建 Multipaz 錨點（`trust/BuiltInTestAnchors`）包含 Multipaz 測試 App、Identity Reader 與 Multipaz Wallet 預設信任的發行端與查驗端；測試錨點存在 TEST 環境，Google Wallet ID pass（美國、美國以外）與 Apple Digital ID 為 PRODUCTION 非官方錨點（T2，顯示發行者名稱）。
   - TWDIW 信任清單同時查正式、官方 sandbox（UAT，一律啟用並標示測試）與自訂測試平台；測試清單的離線快照存在另一個表格，不會被當成正式清單讀回。
   - 信任來源改變（匯入、移除錨點或 DID）時，`StatusMonitor.reevaluateIssuers` 重新判定已持有證件的發行端並記錄。
   - 出示同意畫面先檢查請求的 verifier_info（`oid4vp/VerifierInfoCheck`，OpenID4VP 1.0 第 5.11 節，例如 ETSI TS 119 475 的 `rc-wrp+jwt` 註冊憑證）：簽署者信任、是否綁定送出請求的查驗方、請求的欄位是否超出註冊範圍。
4. **did:key 與 did:jwk 的任何 fragment 都指向 DID 自身的唯一金鑰**（`DidResolver.resolveKey`），因為金鑰就編碼在 DID 內；TWDIW 平台的查驗方以 `<did:key>#0` 簽要求物件。kid 指向其他 DID 時仍拒絕。
5. **憑證不跟隨 jku；狀態清單可用 jku，但要先綁定發行端。** 憑證的簽章金鑰只能來自 x5c、DID、Data Integrity proof 或 JWT VC issuer metadata。狀態清單沒有其他金鑰來源時才用 jku（`trust/JkuKeys`），只接受 https，並依序綁定：JWK 的 x5c 連到任一啟用中的信任錨（不限 TWDIW）、jku 主機就是簽署者自己的主機（did:web 或 https 識別碼）、信任來源把主機綁到該 DID（TWDIW 已列名組織的主機與 wallet.gov.tw 平台、Linked Domains）。都綁不上時仍可驗證，但保證降為 `TLS_ONLY`，不可當成已驗證。
6. **狀態顯示規格原文。** 不自創狀態名稱，可展開細節；發證端未提供在地化時使用快取的關鍵字翻譯。是否接受某個狀態由 `status/StatusPolicy` 依用途風險（低、中、高）決定：撤銷一律拒絕；清單讀不到或簽章未驗證時，低風險接受、中風險需留意、高風險拒絕；`TLS_ONLY` 到中風險都可接受；過時或來自測試環境的「通過」降為需留意。證件自身的風險依分類（身分證件高、政府卡片中、其他低）；出示請求的風險取欄位敏感度（`credential/ClaimSensitivity`，揭露整張憑證時以實際含有的全部欄位與證件分類計算）與查驗方信任等級的較高者；查驗時由查驗者選擇用途風險。判定為拒絕的證件不能以勾選覆寫，只能重新查詢狀態（撤銷則不提供）。jku 無條件只接受 https，測試環境的本機 HTTP 例外不適用。
7. **兜底實作。** 平台或 SDK 不支援時改用純軟體實作（軟體金鑰、純 Kotlin QR 編碼），模擬器、AOSP、桌面都要能用。
8. **金鑰證明只確認金鑰有效，不檢查 RKP。**
9. **CI release 產物必須經 R8 / ProGuard 最佳化**，不可只是 debug 建置。
10. **介面以 EUDI Wallet 與 Bonds 的設計為準，不為發行端或 Profile 另開專區。** 首頁五個分頁：證件（所有證件同一清單，分組與篩選）、文件（文件保存、檢查、簽署、衍生憑證、取件入口）、使用（出示、臨櫃條碼、加入證件）、查驗（App 作為查驗方）、紀錄（只存欄位名稱，不存內容）；設定在右上齒輪，依用途分為七組（`SettingsSection`：安全與隱私、證件與出示、文件與簽章、信任、互通、開發者與測試、一般與關於），清單每列顯示目前的設定，點選進入該組的頁面（`Screen.SettingsPage`）；新增設定時放進對應的組並更新清單的摘要。方言帶來的功能併入這些共同位置：卡片目錄在「從清單選擇」、臨櫃條碼在「使用」、信任清單在設定。
11. **設計 token 沿用 Bonds**（`ui/UiKit.kt`）：互動主色為靛色，綠、橙、紅只用於判定（判定卡為 0.14 透明度色底、符號與文字三者並用，「部分」不可看起來像「通過」）；空狀態附直達動作；尚未實作的功能顯示為停用列並寫明原因，不隱藏；結果用畫面或判定卡呈現，警示對話框只用於確認有後果的動作。
12. **狀態主動更新，信任錨點不限 TWDIW。** `StatusMonitor` 在開啟與回到 App 時，於背景查詢逾時的狀態（依證件風險，同時最多 3 張），結果存在儲存區供離線使用；查詢失敗保留前一次有意義的結果並註明；狀態或發行端信任改變時通知並寫入紀錄（`HistoryKind.STATUS`）。所持 TWDIW 卡片的發行端每 12 小時重新查驗信任清單與 Arbitrum 註冊，離線或鏈上無法查詢時不變更。使用者可匯入任何 X.509 根憑證（USER 環境）或自行信任 DID（`trust/UserDidTrust`），兩者都是 T2，不會顯示為官方。

13. **近距離與 NFC。** mdoc 近距離出示與查驗都走 ISO/IEC 18013-5，同意畫面與一般出示共用（`requestedDocuments`、`riskAcknowledgement`）。只有「感應出示」畫面開著時，NFC 感應才會回應查驗設備。PC/SC 讀卡機只能讀取，電腦不提供 NFC 出示。

## 近距離（ISO 18013-5）與 NFC 要點

- Multipaz `NfcTransportMdocReader.open()` 在呼叫者的作用域啟動 I/O 迴圈，不可包在 `withTimeout` 內（會等到逾時）；連線逾時以另一個 coroutine 在逾時後關閉傳輸。
- Multipaz `NfcTransportMdoc` 的靜態實例只在 `NfcTransportMdoc.onDeactivated()`（感應場消失）時移除，`close()` 不會。Android 由 HCE 服務呼叫；測試的 `LoopbackTag.close()` 也要呼叫，否則下一個測試會出現兩個實例。
- NFC 是半雙工：最後一個 ENVELOPE 的回應就是持有者的 DeviceResponse，會等到使用者同意後才送出。
- PC/SC：只用短 APDU（`maxTransceiveLength` 261）；關閉 JDK 的自動 GET RESPONSE（`sun.security.smartcardio.t0GetResponse` / `t1GetResponse` 設為 false），由 18013-5 的 61XX 流程自行處理；Linux 自動尋找 `libpcsclite.so.1`；Windows 在沒有讀卡機時會停止智慧卡服務，重新列出時以反射重設 JDK 快取的 context（需要 `--add-opens java.smartcardio/sun.security.smartcardio=ALL-UNNAMED`）。
- `java.smartcardio` 不在 class path 預設解析的模組內：桌面編譯加 `-Xadd-modules=java.smartcardio`，執行與測試加 `--add-modules=java.smartcardio`，jlink 模組清單也要列入。
- Android 讀卡模式依 Multipaz：NFC-A/B、略過 NDEF 檢查、無系統音效，標籤在 callback 內處理，transceive 逾時 20 秒；Activity 回到前景時重新開啟讀卡模式。
- DC API 的 `org-iso-mdoc`（ISO 18013-7 Annex C）由 `ProximityModel.presentDcApi` 處理，Android 註冊時要列出這個 protocol。
- 查驗端用 Multipaz 驗證 ISO 回應內的 SD-JWT VC（OtherDocument，ISO 18013-5 第二版）時，`nbf` 是必要欄位（`OtherDocument.verifySdJwtVc`）；SD-JWT VC 規格中 `nbf` 是選填，EUDI 的 PID 沒有這個欄位，查驗端會回「No nbf claim」。這是查驗端程式庫的限制，錢包端無法補上。

## 文件、簽章與衍生憑證要點（P3）

- 文件保存在 `FilesModel`（儲存區表格 `DiwFiles` 中繼資料、`DiwFileData` 內容），以 SHA-256 去重，單檔上限 64 MB。Multipaz 的 Android 儲存區以 5 MB 的 CursorWindow 讀取一列，所以大的值（文件內容、信任清單快照）以 `Blobs` 每 1 MB 分段存放，舊的單列資料照常讀取。每次開啟重新檢查簽章，信任判定用 `TrustRole.DOCUMENT` 與 `TrustRole.TSA`（GPKI、MOICA、系統憑證庫與使用者匯入的根憑證），AIA 補中繼憑證只抓 http(s)、上限 256 KB。
- 檢查結果是 `DocumentReport`：每個簽章分完整性、憑證鏈信任、時戳與後續變更（`LaterChanges`），判定 `VALID`、`PARTIAL`、`INVALID`、`UNSIGNED`，信任等級沿用 T1 到 T4。自簽憑證只能證明完整性，判定為 `PARTIAL`。
- 時戳：使用者在設定選 TSA（預設 DigiCert），可開啟「保存時自動加時戳」；時戳是對文件 SHA-256 的 RFC 3161 token，與文件分開保存，開啟文件時依目前的信任錨點重新判定。設定「時戳與簽章一併保存撤銷資訊」（`timestampRevocation`，預設開）會在取得時戳時以 `DocumentSigning.timestampValidation` 收集時戳機構的憑證鏈與撤銷資訊，存在 `StoredTimestamp.validation`，舊時戳可在文件詳情補取；時戳可由使用者移除（`removeTimestamp`，例如舊版沒有保存撤銷資訊的時戳）後重新取得。
- 文件內簽章的撤銷資訊：保存含簽章的檔案時（設定開啟時在背景）以每個簽章的憑證鏈與簽章時戳的憑證鏈呼叫 `collectValidation`，合併存在 `StoredFile.signatureValidation`；文件詳情可重新取得，公文容器可一次取得容器內全部含簽章檔案與尚未保存撤銷資訊的時戳（`collectContainerValidation`）。背景工作完成時以 `FilesModel.patch` 在鎖內更新最新的紀錄，`save` 也走同一把鎖，避免覆蓋同時寫入的欄位（例如加入容器）。
- 長期驗證資料（`ValidationCollector`）：以 AIA caIssuers（與內建中繼憑證）補齊憑證鏈，每張非根憑證先問 OCSP（POST，回應須由發行者或其授權的回應者簽署），取不到才用 CRL 分發點（簽章須由發行者簽署）；狀態為 GOOD、REVOKED、UNKNOWN、UNAVAILABLE。
- 簽章檢查的寬鬆處理：CMS 只讀第一個 ASN.1 物件（e簽寶等服務在 BER 後多寫結束標記），完整性以憑證公鑰驗證（BouncyCastle 不再以 signingTime 檢查憑證效期）；CMS 沒有 signingTime 時以 PDF 簽章字典的 `/M` 當作宣稱的簽署時間；PKIX 依序嘗試較短的憑證鏈前段，因為附上的憑證可能含交叉簽署的根憑證。簽章卡的信任說明只描述簽署者（`signerTrustLine`）。
- 簽署方式：自然人憑證卡（Android NFC 兩次感應：先讀憑證、再簽章；USB CCID 與桌面 PC/SC 一次完成）、PKCS#12 檔案、錢包金鑰（`HolderIdentities.DOCUMENT_SIGNER`，自簽憑證）。PIN 不保存。簽完以憑證公鑰檢查簽章值，不符就不寫入。
- CSC 遠端簽章（`document/sign/Csc.kt`、App 的 `CscModel`）：CSC API v2，OAuth 授權碼加 PKCE，先以 `scope=service` 登入並讀 `credentials/list`，每次簽章再以 `scope=credential`（`credentialID`、`numSignatures`、base64url `hashes`、`hashAlgorithmOID`）授權，最後 `signatures/signHash`（標準 base64、`signAlgo` 優先 ecdsa-with-SHA256 或 sha256WithRSA，EC 的 r||s 轉 DER）；`implicit`／`explicit` 模式改用 `credentials/authorize` 取得 SAD（PIN、OTP 不保存）。內建 EUDI walletcentric 測試服務（demo 與 dev，`wallet-client`、redirect `rqes://oauth/callback`），使用者可自行加入服務並標示測試或正式，存在設定的 `cscServices`。登入由 `CscModel` 以自己的 cookie 跟隨轉址，遇到 OpenID4VP 連結（含只放一個錢包連結的頁面）就由 `WalletModel.presentForAuthorization` 在一般同意畫面出示 PID，取得驗證端回傳的 redirect_uri 後繼續；EUDI 的授權會帶 CSC `qes-approval` transaction_data（`QesApprovalTransaction`），同意畫面列出要簽的份數。有 transaction_data 時 KB-JWT 必須寫出 `transaction_data_hashes_alg`（Multipaz 在 sha-256 時省略，EUDI 驗證端回「must be sha-256」），由 `ResponseBuilder` 補上。需要網頁登入時改開瀏覽器，Android 接收 `rqes://oauth/callback` 與 `diw-wallet://csc/callback`，電腦版貼上最後網址。登入權杖只存在這次執行。
- 簽署格式：PDF 為 PAdES（增量更新，保留既有簽章），XML 為 XAdES enveloped（含 `DataObjectFormat`，符合 baseline B），其他檔案為 CAdES 分離或封裝、ASiC-E。加密或已鎖定（certification 不允許變更）的 PDF 拒絕簽署。
- 保證層級：PAdES 由使用者選 B-B、B-T（簽章時戳）、B-LT（再加 DSS：簽署者與時戳機構的憑證、OCSP、CRL，VRI 以 CMS 的 SHA-1 大寫十六進位為鍵）、B-LTA（再加 `/Type /DocTimeStamp`、SubFilter `ETSI.RFC3161` 的文件時戳），選擇記在設定 `padesLevel`；B-LT 以上取不到撤銷資訊時不寫入。B-B、B-T 與其他格式可勾選「附加撤銷資訊」：CAdES 把憑證放進 SignedData.certificates、CRL 與 OCSP（RFC 5940 otherRevInfo）放進 crls，XAdES 寫 `CertificateValues` 與 `RevocationValues`。簽署畫面可展開技術細節。
- 電子公文線上簽核（.si，文書及檔案管理電腦化作業規範 109 年版附錄 3 表 3-5、附錄 4 的 `104_sign_utf8.ent`、附錄 5 之三的 DTD；規則與結構整理在 `docs/research/official-document-files.md`）不是 XAdES：根元素 `線上簽核`，每個 `簽核點定義` 內是不帶命名空間的 XMLDSig `Signature`（C14N 20010315、rsa-sha256），Reference 依序為以檔名指向的公文與附件（分離、原始位元組的 SHA-256，摘要 URI 可能是 `xmldsig-more#sha256`）、自己的 `Object`（異動資訊：簽核人員、異動別、簽核意見、民國年月日時分的簽章時間；簽核資訊：檔案清單）、前一個簽核點。`ApprovalSignatures` 驗證每個簽核點（格式 `OFFICIAL_APPROVAL`，檔案不在錢包時註明無法比對），`DocumentSigning.signApproval` 加一個簽核點（`ApprovalPoint`，沒有 .si 時建立新檔），公文與附件本身不改動；公文的簽署格式因此只有「電子公文簽核」與 CAdES、ASiC-E。加簽時寫入 DTD 的必要欄位：`簽核人員`（機關?、單位、職稱、姓名、帳號、角色?，未填寫的必要欄位寫空白）、`簽核文稿清單`（.di 為文稿，交換表單以外的其他檔案為第一份文稿的附件，TIFF 為一般頁面檔格式附件）與每個檔案的 `原始檔序號`；異動別最多 10 字。驗證時另註明不符規範之處（非 RSA-SHA256、非 Canonical XML 1.0、URI 指向不存在的簽核流程、借卡而沒有補簽追認），不影響判定。規範要求經核定憑證機構的憑證，錢包金鑰（自簽 ECDSA）加簽時畫面會警告。線上簽核檔的標題是「線上簽核檔（N 個簽核點）」，不用簽核意見。公開範例檔的檔案摘要相符但簽章值是佔位，驗證結果會顯示簽章值不符。
- 在學證明（`StudentStatusProof`，中國大陸高校在學證明的格式）與通行證關聯查詢結果（`MainlandPermitLink`，國家移民管理局，台胞證與居住證）由 `ParsedCertificate.parse` 解析，預覽為結構化畫面，欄位供衍生憑證使用。
- 衍生憑證：每份文件可產生 IETF SD-JWT VC（vct `urn:diw-wallet:vct:document-derived:1`），發行端是錢包的 `HolderIdentities.DOCUMENT_ISSUER` did:key，信任等級 T3、環境 USER。明文 claim 為 `document`（SHA-256、類型、大小）與 `evidence`；可揭露欄位為 disclosure：錢包自己的欄位（姓名、文件標題、檔名、簽署者、簽署時間、來源）與 `DocumentFields` 從文件內容解析的欄位（OpenCerts 資料、公文「函」的發文機關、受文者、日期、字號與主旨、PDF 文字層的「標籤：值」，加密 PDF 以這次輸入的密碼開啟），上限 30 個。持有人自填的欄位要另外展開才能加，名稱前綴 `holderStated:`。證據依序為文件簽章檢查（發行錢包的陳述，查驗端不重算）、文件時戳（查驗端以 SHA-256 重驗）、自然人憑證簽章（vc+moica，`_sd` 與文件雜湊須與 SD-JWT VC 相同，揭露的姓名須等於憑證 CN）。
- vc+moica 與 Bonds 相容：payload 以 JCS 序列化，卡片簽 `"bonds-tw-credential-v1:" + hex(sha256(payload))`（RS256），issuerJWS 為 BONDS_SELF_ISSUED did:key 的 ES256。Bonds 請求 `k=s` 時列出有自然人憑證證據的衍生憑證；MOICA G3 與 GRCA G3 固定在 `MoicaCa.PRODUCTION`，測試以 `MoicaCa(moica, root)` 注入。
- Bonds 身分證卡（`BondsNationalId`）：MyData `personal/detail/API.idPhotoRev` 的 PDF 以身分證統一編號為使用者密碼（依 Bonds 先試輸入原樣，再試去空白轉大寫）；`PdfTextExtractor` 依 ToUnicode、Identity-H 與 Uni*-UCS2／UTF16 CMap 擷取文字並依基線分行。欄位依標籤（統號、姓名、出生日期、戶籍地址，全形或半形冒號，同一行可有兩個欄位，地址可跨行）解析；出生日期只接受「民國 083年03月06日」形式，`over18AtIssuance` 以臺北時間在生日當天成立，讀不懂日期時不加這個欄位。內容與 Bonds 相同：W3C VC 2.0、`@context` 第二項是 `https://bonds.tw/ns/credentials#` 的受保護詞彙、type `NationalIDCredential`、issuer 與 credentialSubject.id 都是 BONDS_SELF_ISSUED did:key、全部欄位為 disclosure、`_sd` 排序且沒有 `_sd_alg`。以實體自然人憑證卡簽署（Bonds 用行動自然人憑證），簽署前檢查憑證 CN 等於姓名。卡片存在來源檔案的 `StoredFile.nationalId`，列在證件分頁最上方，回應 Bonds `k=s`；`BondsCard` 的 `document` 與 `credential` 因此可為 null。
- Bonds 自發卡線上出示：TWDIW 形式的 OpenID4VP 請求，Presentation Exchange 的 descriptor 格式全為 `vc+moica` 時由 `BondsMoicaOnline` 處理（`PreparedMoica`，不會改用政府皮夾卡片）。卡片來自身分證卡與有自然人憑證證據的衍生憑證；回應是 BONDS_SELF_ISSUED 金鑰簽的 jwt_vp（header `jwk`、sub/iss 為 did:key jwk_jcs、30 天），只帶請求的 disclosure（線上不強制揭露姓名，與 Bonds 相同），`path_nested` 格式 `vc+moica`、路徑 `$.vp.verifiableCredential[i]`。
- asdt 只保存原檔（加密給戶政司，錢包無法解開）。
- 電子公文容器（`document/official/OfficialBundles`）：.di 等公文可放入關連檔（.sw 交換表單、.si、.dm、附件），存在成員的 `StoredFile.bundleOf`，文件清單只列公文並標示關連檔數。簽核檔（.si）以摘要把公文、.doc 與頁面影像（TIFF 等）歸入同一容器，匯入的 .si 會帶入它列出的已保存檔案，已保存的 .si 列出新匯入的檔案時也一起提出；簽核點加在容器內最新的 .si 之後，新的 .si 放進容器、舊版移出但保留。一起匯入的檔案含 .si 時先依簽核檔建立容器（`placeByApproval`）：取參照最多的 .si，它列出的第一份公文（內容摘要相符）為容器主體，已有容器的公文優先；.si 與它以檔名和摘要簽署的檔案直接放入，不必確認，其餘檔案再進入確認畫面。其他情況檔案無法確定屬於哪份公文，所以先列出依據再由使用者勾選確認：檔名相同、交換表單的發送對象（全銜或機關代碼，○ 佔位不算）與公文受文者、正本、副本相符、簽核檔列出公文、公文附件欄列出檔名為支持；發送對象全不相符、另一份同類公文為反對；只有支持、沒有反對才預先勾選。含公文交換檔的 ZIP 收到後立即解出並刪除 ZIP（`#Uxxxx` 檔名轉回中文）；分別匯入時可在公文詳情「匯入關連文件」或「從已保存的文件加入」。刪除公文時成員預設改回獨立檔案，勾選後一併刪除（沿用自簽署前公文的成員不刪）。
- 容器的兩層顯示（`FilesModel.containerLayout`）：以容器內簽核點最多的 .si 為準，`OfficialBundles.approvalPoints` 讀出每個簽核點自己的 Signature 參照的檔案；每個檔案列在第一個以相同摘要簽署它的簽核點下，之後的簽核點只計「另簽核前面已列出的檔案」；同名但摘要不同列為「內容與這個簽核點簽署時不同」（常是之後修改的版本），不在容器內列為遺失；簽核檔沒列出的檔案另列。上方的健檢摘要對應檔案管理局電子封裝檔工具箱的檢測類別：外部檔案（齊全、遺失、與簽核時不同）、簽章（每個簽核點的簽章判定）與撤銷資訊保存數。說明見 `docs/research/official-document-files.md`。
- 匯出：「匯出」另存原檔；有時戳或撤銷資訊時可「匯出文件與證據」（ZIP：原檔、`時戳N.tsr`、`簽章-憑證N.cer`、`OCSPN.der`、`CRLN.crl`、`說明.txt`）；公文容器「匯出公文容器」把全部檔案以原檔名放在 ZIP 最上層（.si 以檔名參照，其他系統才能驗證；同名不同內容加摘要前 8 碼），證據放在 `證據/<檔名>/`，`說明.txt` 列出每個檔案的摘要與檢查結果和依簽核點的分組。ZIP 由 `DocumentSigning.zip` 以 UTF-8 檔名寫出，錢包重新匯入時忽略資料夾。
- 檔名編碼（`util/TextEncodings`）：沒有 UTF-8 旗標的 ZIP 項目名稱依序嚴格試 cp950、Big5-HKSCS、Big5、GB18030、GBK、Shift_JIS、EUC-KR，取怪字元最少者；下載檔名依 Content-Disposition（含 `filename*`），被誤以 ISO-8859-1 解讀的 UTF-8 或 Big5 檔名會還原（`repairName`）。中文檔名必須全程正確保存與顯示。
- 圖片：TIFF 以純 Kotlin 解碼（`document/image/TiffDecoder`：CCITT G3／G4、LZW、PackBits、Deflate），預覽與卡片影像共用；ASiC-E 與 ZIP 內的項目可從容器直接開啟。
- 匯入可一次選多個檔案（`PlatformServices.pickFiles`，Android `OpenMultipleDocuments`、桌面多選）；多個檔案時逐一保存，含公文時進入容器確認，否則回到文件分頁。
- 分年度的文件：MyData 檔案讀得出期間（所得年度、「113 年度」）時記在 `StoredFile.period` 並加進檔名（「綜合所得稅各類所得資料（113 年度）.pdf」），內容不同的檔案以 SHA-256 區分，不會互相覆蓋。文件分頁可「依保存時間」或「依項目」排列，依項目時同類檔案依期間由新到舊。Bonds 持有人衍生查驗依序試所有候選文件，查驗方問的年度不在已保存的資料時，錯誤訊息列出已有的年度。
- XML 解析（`XmlParsing`）：Android 內建 DOM 只接受 ASCII 名稱，中文元素或 DOCTYPE 的公文會失敗，所以 Android 改用 Xerces 2.12.2；Xerces 需要的 DOM events、ranges、traversal、ElementTraversal、StAX 等介面 Android 沒有，`core` 的 `androidDomExtras` 只從 xml-apis 取出 android.jar 沒有的類別打包，不覆蓋平台類別。
- 入出國日期證明書（`EntryExitCertificate`）：表格左右兩半印在同一行，依項次讀出出境與入境日期；衍生欄位為個人與證明書欄位、最後出入境日期、最近一次出境是否已入境、查詢期間最後一天是否在境內與整份紀錄（一個欄位）；產生衍生憑證時可指定日期加入「該日是否在境內」（`inTaiwanOn_<日期>`，查詢期間外不提供）。預覽以結構化畫面呈現。
- 中國大陸出入境記錄（`MainlandEntryExitRecord`，國家移民管理局「出入境记录查询结果（电子文件）」，BJCA 簽章）：每列為「序號 出境|入境 日期 證件號碼 口岸 [航班號]」，證件名稱折行印在該列前後（「台湾居民来往大陆」在前、「通行证」在後），陸路與水路沒有航班號，跨頁時有頁尾；序號 1 為最新，同一天以序號排序。衍生欄位為個人與記錄欄位、查詢期間、筆數、最後入境與出境日期、查詢期間最後一天是否在中國大陸境內與整份紀錄；指定日期為 `inMainlandOn_<日期>`。兩種記錄共用 `MovementRecord`（`MovementRecord.parse` 先試台灣證明書），「該日是否在境內」以該日或之前最後一筆移動判斷，之前沒有移動時以之後第一筆反推。比對漢字用 `[\u4e00-\u9fff]`，不用 `\p{IsHan}`（Android 的 regex 不支援）。
- 戶籍衍生答案與欄位只用比對出的持有人本人（身分證卡或設定的身分證統一編號），單人戶也要比對；沒有持有人資料或比對不到時拒答。預覽（`profile/bonds/HouseholdTranscript`）逐位列出住戶，可切換，比對出的本人排第一。
- 行動自然人憑證 SP：編譯時由 `DIW_MOICA_SP_SERVICE_ID`、`DIW_MOICA_SP_AES_KEY`、`DIW_MOICA_SP_ENV`（UAT 或 PRODUCTION）環境變數或 Gradle 屬性產生 `BuiltInSp`（build 目錄，不提交）；設定的「手動輸入 SP 帳號（開發者）」改用簽署畫面輸入、只存在記憶體的帳號。
- OpenCerts（`document/opencerts`）：`OpenAttestationDocument` 檢查 v2（salted 值、flatley 路徑）與 v3（proof.salts、`a.b[0]` 路徑、葉數須等於 salt 數）的 Merkle 完整性，並整理出受領人、主要欄位、發行者、簽署人與簽名圖、成績單、圖片、附件與其他欄位（`view()`，不顯示原始路徑）。`OpenAttestationOnline` 依 oa-verify 線上查驗：文件庫 `isIssued`／`isRevoked`（支援 batch 介面 0xdcfd0745）、token registry `ownerOf`、DID 簽章（EIP-191 對 Merkle root，secp256k1 還原成 did:ethr 位址）與撤銷（NONE、REVOCATION_STORE、OCSP_RESPONDER）；發行者身分看 DNS-TXT（`openatts net=ethereum netId addr`）、DNS-DID 與 OpenCerts 官方登錄，任一成立即通過。DNS 走 DoH（dns.google、cloudflare-dns.com），鏈依 DNS 紀錄的 netId，RPC 用不需金鑰的公開節點；查不到時為 `NOT_CHECKED`，不判失敗。結果存在 `OpenCertInfo.online`，開啟時超過 12 小時重新查驗，離線時保留上一次有意義的結果；完整性、發行與身分都通過才是 `VALID`，完整性或發行失敗為 `INVALID`。離線顯示（`OpenCertOffline`）：沒有程式碼也不連線的頁面（CSP 只允許行內樣式與 data: 圖片，分頁用 CSS），demo-renderer.opencerts.io 的範本（GOVTECH_DEMO、OPENCERTS_DEMO、TESTIMONIALS、TESTIMONIALS2、CERTIFICATE_OF_AWARD，其他名稱如該顯示程式改用預設）依原樣式重寫，標誌與背景圖不內建、以文字代替；其他證書以 `view()` 排版；發證機構的 HTML 內容（testimonial）先移除程式、事件、外部載入。Android 以關閉 JavaScript 與網路的 WebView 顯示。`OpenCertRenderer` 產生 decentralized renderer 的宿主頁（自寫 penpal v5／v4 握手、`RENDER_DOCUMENT`、`UPDATE_HEIGHT`、`UPDATE_TEMPLATES`、`SELECT_TEMPLATE`），只接受 https 的 template URL；Android 以 WebView `loadDataWithBaseURL` 開啟，桌面寫入暫存檔後用系統瀏覽器開啟。內容只在使用者點「以發證機構樣式顯示」時送到發證機構的顯示程式。測試樣本是以 open-attestation 6.9.7 包裝的虛構資料（`test-servers/src/test/resources/documents/opencerts/generate.js`）。
- MyData：檔名依 Bonds 的項目辨識（`MyDataFiles`），伺服器的不透明檔名改為項目名稱。MyData 的 ZIP 不論是 App 內下載、其他 App 分享或手動選取，收到後立即解出並刪除 ZIP，每個檔案各自保存；來源只寫「MyData・項目名稱」（未經 App 內下載時加「（依檔名判斷）」），取得方式另記「App 內下載」或「從壓縮檔解出」與壓縮檔名；舊資料載入時改成短來源。含國民身分證資料時直接進入身分證卡畫面。MyData 網頁以 XHR 取得 blob、點 `<a download>` 後立刻 revoke 並離開頁面，`PortalWebView` 在每頁注入腳本保留 blob 並經 `DiwVault` 介面交給錢包。
- MyData 自動填入（Bonds `MyDataAutofillProfile`，`profile/bonds/MyDataProfile`）：設定可存身分證統一編號（檢查碼）與出生日期（民國 7 碼或西元 8 碼），只在 https 且主機正好是 mydata.nat.gov.tw 的頁面執行填入腳本。MyData 的加密 PDF 依序以身分證卡的統號與這個編號自動開啟。
- PDF 文字欄位（`DocumentFields.fromText`）：標籤為中文字（可帶括號或斜線）或最多四個英文字，可接括號內的翻譯與「/English」；值在全形逗號、句號、分號或四個以上空白處結束；標籤在行尾時取下一行開頭。「NO.xxxx」為文件編號；「出生于 2007 年 02 月 16 日」「于 2025 年 09 月入学」等句子另外解析。標題優先取含證明、證書、謄本、資料、通知、執照或 Certificate、Proof、Transcript 的行。
- 加入證件畫面（「從清單選擇」）：政府皮夾卡片、自己製作（國民身分證卡、用已保存的身分證資料製作、文件衍生憑證、停用的「年齡證明（零知識）」P4）與其他發行端網址。身分證卡與 vc+moica 衍生憑證可展開技術細節（查驗結果、憑證內容、自然人憑證簽章、issuerJWS、disclosures 與摘要）。
- 取件入口（`DocumentSources`）：MyData 各項目（身分證、戶籍、所得、納稅證明、勞保、勞退、健保、地籍，路徑與 Bonds 相同）、MyDoc、教育部大專校院數位證書驗證、數位證明管理中心（dcmc.csie.ncku.edu.tw）、戶政、地政、移民署入出國日期證明書（ncp.immigration.gov.tw/niaweb/entryExitQuery）、財政部稅務入口網（www.etax.nat.gov.tw/etwmain）。Android 以 App 內 WebView 開啟並把下載直接存入文件分頁（含 blob 下載），顯示網站的對話框；`mobilemoica:` 等非 http 連結交給系統（行動自然人憑證 App 登入）。桌面以外部瀏覽器開啟，下載後再匯入。
- 預覽：PDF 以平台繪製前 10 頁（Android `PdfRenderer`，桌面 PDFBox），加密 PDF 先以本次輸入的密碼（MyData 為身分證統一編號）在記憶體產生不加密的副本（`PdfPlain`，不保存、不匯出），並可顯示文字層；圖片、XML、JSON、文字與 .p7m 內含的內容也可預覽。密碼只保存在這次執行的記憶體。
- 圖片欄位：mdoc 的影像位元組與 JSON 憑證裡的 data: URL 或 base64 圖片（`ClaimPictures`）在證件詳情顯示為圖片。
- 卡片影像：向 Digital Credentials API 註冊前，沒有 `cardArt` 的證件由 `WalletModel.ensureCardArt` 產生（名稱、發行端、顏色、標誌；衍生憑證放文件第一頁，有照片欄位時放照片），Android 以 `android.graphics` 繪製，系統選擇器以它列出證件。
- 停用列（寫明原因）：公文交換收發（需要機關的公文電子交換帳號與憑證）、zkPDF 與 zkTLS 證明（P4）。
- EU DSS 交叉驗證：`DIW_SIGNED_OUT=<資料夾> ./gradlew :test-servers:test --tests '*DocumentSigningTest'` 輸出錢包簽出的檔案，再以 `./gradlew -p tools/dss-check run --args=<資料夾>` 用 DSS 6.5 驗證（測試 PKI 沒有撤銷資訊，政策只把缺撤銷資料降為警告）。DSS 拒絕含 DOCTYPE 的 XML，公文「函」改由 JDK 與錢包自身驗證。
- 含個資的真實文件不可提交進 repo；測試樣本只用測試 PKI 產生或 DSS、ofdrw 的公開範例。用真實文件核對解析時，探測程式放在 `test-servers/src/test/kotlin/diw/testservers/local/`（已列在 .gitignore），輸出不放進 repo。

## TWDIW 與 Bonds 要點

- TWDIW 發證：`credential_issuer` 結尾有 `/`，中繼資料以附加方式取得，沒有 AS metadata，token 端點為 `{issuer}token`，表單帶 `client_id=moda_dw`、`authorization_details`、空的 `tx_code`；proof 的 `kid` 是不帶 fragment 的 did:key（jwk_jcs），`iss` 為 client_id；回應 `{credential}`。中繼資料寫 `jwt_vc_json`，實際送 SD-JWT（`typ vc+sd-jwt`，無 `vct`，W3C 內容在 `vc`）。
- 每張 TWDIW 卡片綁定同一把錢包層級金鑰（`HolderIdentities.TWDIW`），才能一起出示。
- TWDIW 出示：client_id 為 did:key，要求物件由該 DID 簽章；回應是一個 jwt_vp（header 帶 `jwk`，有效 30 天），`presentation_submission` 用 `jwt_vp` + `path_nested jwt_vc`，成功判斷為 `code == "0"`。
- TWDIW 主機的 gate 只接受 https 443 埠，測試時以 ktor `MockEngine` 模擬 `*.wallet.gov.tw`（見 `TwdiwPlatformMock`）。
- wallet.gov.tw 的 Cloudflare 會擋 HTTP 函式庫預設 User-Agent，`TwdiwUserAgent` 只對 TWDIW 主機改寫 UA。
- TWDIW 狀態清單（StatusList2021）由 key-2 簽章，金鑰只公布在 jku `https://issuer-vc.wallet.gov.tw/api/keys`；該端點各次回應的 key-2 不一致（上游問題），驗簽失敗時重抓金鑰集，最多 4 次。發行端已列名時 jku 主機屬於平台，綁定成立；未列名（如 demo 發行端）為 `TLS_ONLY`。
- Microsoft Verified ID 狀態：`credentialStatus` 型別為 `RevocationList2021Status`，`statusListCredential` 是 DID URL（`?service=IdentityHub&queries=<base64 查詢>`）。錢包把查詢 POST 到發行端 DID 文件裡 `IdentityHub` 服務的 `instances` 端點，回應 `replies[0].entries[0].data` 經 base64 解碼後是 StatusList2021 的 JWT，由發行端 DID 簽章（可能是 ES256K）。
- Microsoft Verified ID 出示：`openid-vc://?request_uri=...` 沒有外層 client_id，client_id 在已簽章的要求物件內；`claims.vp_token.presentation_definition` 表示回應要帶 vp_token；PE v1 的 `schema[].uri` 是憑證類型。`path_nested` 為 `jwt_vc` 且路徑是 `$.verifiableCredential[i]`（相對於 vp claim，見 `PresentationDialect.nestedPath`），寫成 `$.vp.verifiableCredential[i]` 時驗證端回 401「presentation does not include any verifiable credentials」。
- Bonds：持有者是 BLE GATT 周邊，以要求中的一次性 UUID 廣播；frames characteristic `2B1D0001-…` notify，查驗方寫 `0x01` 到 `2B1D0002-…` 表示收齊。QR 分幀前綴 `BTWVP1`，以 ECC Q 顯示。
- Bonds 請求的 `k`：`g` 政府皮夾卡片、`s` 自然人憑證自發卡、`a` 本錢包擴充（任何綁定金鑰的證件）。回應 `g` 時只列 TWDIW 卡片，保持與 Bonds 相容。`a` 的封裝：`data:application/dc+sd-jwt,`（IETF SD-JWT VC 以 `vct` 辨識，持有者 DID 為 cnf 金鑰的 did:jwk；W3C SD-JWT 沿用 TWDIW 檢查）與 `data:application/vc+jwt,`（W3C JWT VC，`sub` 或 credentialSubject.id 為持有者 DID）。SD-JWT VC 的發行端金鑰依序來自 x5c、DID iss、JWT VC issuer metadata（需要網路）。

## Android 平台要點

- DC API 收卡：以 play-services 的 `IdentityCredentialManager.registerCreationOptions` 註冊（type `androidx.credentials.TYPE_DIGITAL_CREDENTIAL`、id `openid4vci`），matcher 為 CMWallet 的 `assets/openid4vci_provision.wasm`；`DcApiActivity` 處理 `androidx.credentials.registry.provider.action.CREATE_CREDENTIAL`（protocol `openid4vci-v1`、`openid4vci1.0`、`openid4vci`），`WalletModel.receiveDcApi` 把 offer 交給一般領卡流程，完成後回應 `{"protocol":…,"data":{}}`。
- KB-JWT：請求沒有 transaction_data 時不寫出 `transaction_data_hashes`（Multipaz 會寫空陣列，walt.id verifier2 以 transaction-data-hash-check 拒絕），由 `ResponseBuilder` 移除。
- Digital Credentials API：multipaz-dcapi 只把 mdoc 與 SD-JWT VC 註冊給系統選擇器，只有 W3C 格式的卡片（如 TWDIW）不會出現在選擇器，需以 QR 碼或連結出示。Multipaz 會以快取雜湊略過「資料未變」的註冊，系統拒絕時也只寫 log，所以 App 每次啟動強制註冊，並等待系統回覆，結果與「重新向系統註冊」顯示在設定。
- App 圖示：Android 為 `res/mipmap-anydpi-v26` 自適應圖示（含主題圖示）；桌面圖示由 `python3 app/icons/generate_icons.py` 依同一幾何產生，修改圖示時兩者一起更新。

## 建置與測試

```bash
./gradlew :core:compileKotlinJvm               # 快速檢查 core
./gradlew :app:compileKotlinDesktop            # 快速檢查 App 共用程式
./gradlew :test-servers:test                   # 協議、互通、方言測試
./gradlew :test-servers:test --tests 'diw.testservers.TwdiwPlatformTest'
./gradlew :app:desktopTest                     # App 流程測試
DIW_SCREENSHOTS=build/shots ./gradlew :app:desktopTest --tests '*uiScreenshots'   # 離屏渲染主要畫面為 PNG
./gradlew :app:assembleRelease                 # Android release（R8）
python3 -I tools/trust-roots/update_roots.py --report report.md   # 重新產生內建公開根憑證；--check 只檢查，--strict 有警告時回傳 2
./gradlew -p tools/dss-check run --args=<資料夾>   # 以 EU DSS 驗證錢包簽出的檔案（見上方 P3 要點）
```

測試慣例：

- 協議測試都放在 `test-servers/src/test`；真實伺服器用 `TestServers`（http loopback），https-only 的平台用 `MockEngine`。
- 測試方法用 `runBlocking<Unit> { ... }`。最後一行若回傳值（例如 `assertFailsWith`），JUnit 會因方法不是 void 而**靜默略過**該測試。
- 修 bug 先寫出能重現的測試。

## 文件、分支、PR 與 CI

- README 面向使用者（功能、畫面、下載、建置），開發規則與實作要點寫在本檔。功能或畫面有明顯變更時一併更新 README；截圖以 `uiScreenshots` 產生，縮成 412 像素寬、128 色後放在 `docs/images`。
- 設計與研究文件在 `docs/design`、`docs/research`，驗收紀錄在 `docs/acceptance`，新增文件時加入 `docs/README.md` 的索引；文件內不放個資（實機記錄的卡號、UID、憑證效期等先遮蔽）。
- 授權為 Apache-2.0（`LICENSE` 為官方全文），新增第三方元件或內建第三方資料時更新 `NOTICE`。
- 每個階段（P1、P2…）在各自的 `claude/...` 分支開發並開新 PR，PR 合併後不再沿用同一個 PR。
- `.github/workflows` 無法由代理推送（缺 workflow 權限）；需要修改時把完整檔案交給使用者手動貼上。
- CI 的 `test` job 與 `build`（Android）、`desktop` 平行，測試失敗不擋建置；`release`（main 的 nightly）需要三者都成功。`update-trust-roots.yml`（由使用者手動加入）每月重新產生內建公開根憑證並開 PR，有需要人處理的警告時讓該次執行失敗。
- 發佈流程與簽章 secrets 見 [docs/release.md](docs/release.md)。

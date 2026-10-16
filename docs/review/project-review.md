# 專案 Review 指南

給 P4 完成後接手全專案 Review 的代理或審查者。P1 到 P3 的 PR 審查沒有完整進行，這份文件把審查需要的背景、規則對應的程式位置、要優先檢查的地方與已知未驗證項目整理在一起，讓審查可以直接開始。

這份文件只列「要檢查什麼、去哪裡看」，不是審查結論。標為「疑似」的項目是撰寫時讀程式碼推論出來的，需要審查者確認或推翻。

## 1. 閱讀順序

1. [AGENTS.md](../../AGENTS.md)：模組、已定的設計規則 1 到 13、各領域要點。審查以它為規格；程式與 AGENTS.md 不符時，先判斷是哪一邊過時。
2. [design/architecture-and-roadmap.md](../design/architecture-and-roadmap.md)：目標架構與協定支援矩陣。
3. 依審查範圍讀研究文件：[twdiw.md](../research/twdiw.md)、[bonds.md](../research/bonds.md)、[multipaz-eudi-ms.md](../research/multipaz-eudi-ms.md)、[documents-signatures.md](../research/documents-signatures.md)、[official-document-files.md](../research/official-document-files.md)。
4. 驗收紀錄：[p1](../acceptance/p1-acceptance.md)、[p2](../acceptance/p2-acceptance.md)、[p2 後續](../acceptance/p2-followup.md)、[p3](../acceptance/p3-acceptance.md)。每份最後的「需要實機驗證」表是目前沒有被自動測試覆蓋的部分。
5. P4：[design/p4-zkp.md](../design/p4-zkp.md)、[design/p4-circuits.md](../design/p4-circuits.md)（第 7 節是電路的審查重點）、[design/p4-work-packages.md](../design/p4-work-packages.md)。

## 2. 規模與熱點檔案

撰寫時（P4 開始前）約 6 萬行 Kotlin、234 個檔案。最大的檔案也是變更最頻繁、最需要細看的地方：

| 檔案 | 行數 | 內容 |
|---|---|---|
| `app/src/commonMain/kotlin/diw/wallet/app/ui/FilesScreens.kt` | 約 1900 | 文件分頁全部畫面 |
| `app/src/commonMain/kotlin/diw/wallet/app/FilesModel.kt` | 約 1800 | 文件保存、容器、時戳、簽署、衍生憑證 |
| `app/src/commonMain/kotlin/diw/wallet/app/WalletModel.kt` | 約 1600 | 證件、流程、方言清單、紀錄 |
| `core/src/commonMain/kotlin/diw/wallet/core/oid4vci/Oid4vciClient.kt` | 約 1000 | 發證用戶端 |
| `core/src/commonMain/kotlin/diw/wallet/core/profile/bonds/BondsHolderDerived.kt`、`BondsPresentation.kt` | 約 700 | Bonds 出示與持有人衍生查驗 |
| `core/src/commonMain/kotlin/diw/wallet/core/document/pdf/PdfFile.kt` | 約 600 | PDF 解析與解密 |

`core/src/commonMain/kotlin/diw/wallet/core/trust/BuiltInPublicRoots.kt`（約 5500 行）由 `tools/trust-roots/update_roots.py` 產生，審查產生程式與 `roots.json`，不逐行看產物。

## 3. 設計規則對照表

每條規則列出負責的程式位置與審查時要確認的事。路徑以 `core/src/commonMain/kotlin/diw/wallet/core/` 為 `core/`，`app/src/commonMain/kotlin/diw/wallet/app/` 為 `app/`。

| 規則 | 位置 | 要確認 |
|---|---|---|
| 1 標準優先，方言隔離 | `core/compat/IssuanceDialect.kt`、`core/oid4vp/compat/PresentationDialect.kt`、`core/oid4vci/Oid4vciClient.kt`、`core/oid4vp/` | 標準路徑沒有 TWDIW、Bonds、Microsoft 的字串或分支；方言只在介面註解列出的 hook 介入，且只對自己擁有的 session 生效（一個方言的判斷不會改變另一個發行端的流程） |
| 2 方言常駐 | `app/WalletModel.kt` 的方言清單 | 沒有方言開關；新增方言只改清單 |
| 3 信任分層 | `core/trust/TrustTier.kt`、`TrustRegistry.kt`、`SystemTrustStore.kt`、`PublicRoots.kt`、`TrustLists.kt`、`UserDidTrust.kt`；`app/ui/TrustViews.kt`、`app/ui/RiskConfirm.kt` | 每條判定路徑的結果等級與 AGENTS.md 一致；中繼憑證不提高等級；測試錨永遠不是官方；T3、T4 的操作都經過 `RiskConfirmDialog`；畫面說明與分層同步 |
| 3 verifier_info | `core/oid4vp/VerifierInfoCheck.kt` | 註冊憑證的簽署者信任、綁定請求方、欄位超出註冊範圍時的提示 |
| 4 did:key fragment | `core/did/`（`DidResolver.resolveKey`） | 任何 fragment 都只解析到 DID 自身的金鑰；kid 指向其他 DID 時拒絕 |
| 5 jku | `core/trust/JkuKeys.kt`、`core/status/` | 憑證簽章金鑰不會從 jku 來；狀態清單的 jku 只接受 https 並依序綁定；綁不上時保證為 `TLS_ONLY` 且畫面不顯示為已驗證 |
| 6 狀態 | `core/status/StatusPolicy.kt`、`core/credential/ClaimSensitivity.kt` | 撤銷一律拒絕且不可勾選覆寫；用途風險的計算（整張揭露時以實際欄位計算）；測試環境的通過降為需留意 |
| 7 兜底 | `core/holder/`、QR 編碼、平台金鑰 | 硬體金鑰不可用時改用軟體金鑰，模擬器與桌面可完成主要流程 |
| 8 金鑰證明 | 發證的 wallet attestation 與 key attestation | 不檢查 RKP |
| 9 R8 | `app/build.gradle.kts`、`app/proguard-rules.pro` | release 經 R8；keep 規則涵蓋反射與序列化（Xerces、BouncyCastle、kotlinx.serialization、JNA 與 P4 的 uniffi） |
| 10、11 介面 | `app/ui/` | 五個分頁；設定分組（`SettingsSection`）與新設定的摘要；方言功能併入共同位置；停用列寫明原因；判定色只用於判定 |
| 12 狀態主動更新 | `app/StatusMonitor.kt` | 同時最多 3 張；失敗保留前一次有意義的結果；信任來源改變時 `reevaluateIssuers` |
| 13 近距離 | `app/ProximityModel.kt`、`app/ReaderModel.kt`、Android `WalletNfcService` | 只有感應出示畫面開著時 HCE 才回應；PC/SC 只能讀取 |

## 4. 安全審查重點

以下是要檢查的地方，不是已確認的問題。審查者對每一項給出「無問題、問題（含重現）、需要決定」三者之一。

### 4.1 外部輸入解析

| 項目 | 位置 | 要檢查 |
|---|---|---|
| XML 實體展開 | `core/src/jvmCommonMain/kotlin/diw/wallet/core/document/XmlC14n.kt` 的 `parse` | 已關閉外部實體與外部 DTD，實體解析器回傳空內容。公文需要 DOCTYPE，所以 DOCTYPE 不能整個拒絕；但沒有設定 `FEATURE_SECURE_PROCESSING` 或實體展開上限，Android 用的 Xerces 2.12.2 對內部實體的指數展開（billion laughs）是否有限制要確認 |
| ZIP | `core/src/jvmCommonMain/kotlin/diw/wallet/core/document/Containers.kt` | 已有項目數（5000）、總大小（256 MB）與 `..` 路徑檢查；確認單一項目的壓縮比、名稱以 `/` 開頭或含反斜線、cp950 等編碼還原後才出現的 `..` |
| PDF | `core/document/pdf/PdfFile.kt`、`PdfTextExtractor.kt`、`PdfSignatures.kt` | stream 上限 64 MB、運算子上限、Form 深度；確認物件參照循環、xref stream 的巢狀、`/Length` 與實際長度不符、大量增量更新時的時間與記憶體 |
| ASN.1、CMS | `core/document/`、BouncyCastle 呼叫處 | 「只讀第一個 ASN.1 物件」的寬鬆處理不會讓後面附加的內容被當成已簽署 |
| TIFF | `core/src/jvmCommonMain/kotlin/diw/wallet/core/document/image/TiffDecoder.kt` | 影像尺寸乘積溢位、strip 位移超出檔案 |
| 憑證與 JWT | `core/jose/`、`core/x509/` | `alg` 與金鑰型別綁定；`none` 拒絕；x5c 鏈長上限 |

### 4.2 Android 對外介面

| 項目 | 位置 | 要檢查 |
|---|---|---|
| WebView 橋接 | `app/src/androidMain/kotlin/diw/wallet/app/ui/PortalWebView.android.kt` | `DiwVault` 介面對取件入口內載入的任何頁面（含第三方 iframe 與轉址後的網站）都可呼叫，`onBlob` 會把內容存進文件分頁。確認是否應限制來源（例如只在入口清單的主機上注入）、檔名是否經過清理 |
| WebView 外部連結 | 同上的 `shouldOverrideUrlLoading` | http、https 以外的連結都交給系統，包括 `openid4vp:`、`openid-credential-offer:` 等本 App 自己處理的 scheme。確認網頁不能在使用者不知情下啟動出示或領卡（同意畫面仍會出現，但來源要能辨識） |
| Deep link | `app/src/androidMain/AndroidManifest.xml` | OpenID4VP、OpenID4VCI、`diw-wallet://oid4vci/callback`、`diw-wallet://moica/return`、`rqes://oauth/callback`、`diw-wallet://csc/callback`：state 與 PKCE 是否檢查、callback 在沒有進行中的流程時是否忽略 |
| 匯出元件 | 同上，`android:exported="true"` 的元件 | HCE 服務與 DC API Activity 的權限；`DcApiActivity` 只回應系統呼叫 |
| 明文 HTTP（已修正，PR #9） | `core/src/jvmCommonMain/kotlin/diw/wallet/core/document/sign/CleartextHttp.kt`、`core/document/sign/Validation.kt`（`SignedDataHttp`、`SignedDataRoutes`）、`AndroidPlatform.signedDataHttp` | 原問題：release 的網路設定禁止明文，OkHttp 因此拒絕 http 的時戳、OCSP、CRL 與 AIA。修正後只有這幾類回應本身有簽章的 http 網址改走 `CleartextHttp`（socket 上的最小 HTTP/1.1），其他流量仍受網路設定限制。審查時確認：只有 `SignedDataHttp` 的呼叫端能走這條路；回應大小上限、chunked 與標頭解析對惡意回應的處理；轉址只在 http 與 https 之間且不會讓一般流量繞過網路設定；以 release APK 實機取得一次時戳 |

### 4.3 協定與金鑰

| 項目 | 位置 | 要檢查 |
|---|---|---|
| OpenID4VP 要求驗證 | `core/oid4vp/RequestValidator.kt` | client_id 前綴與簽章金鑰的綁定、`response_uri` 與 client_id 的關係、redirect 與 direct_post 的差異；方言放寬的部分只在方言 session |
| 回應 | `core/oid4vp/ResponseBuilder.kt` | KB-JWT 的 nonce、aud、`transaction_data_hashes` 與 `_alg` 的條件；加密回應的金鑰來源 |
| DPoP | `core/oid4vci/Dpop.kt` | nonce 重試次數上限、`htu` 正規化 |
| 持有者金鑰 | `core/holder/HolderIdentities.kt` | TWDIW、BONDS_SELF_ISSUED、DOCUMENT_ISSUER、DOCUMENT_SIGNER 各自隔離，不會被另一個用途拿去簽 |
| CSC | `core/document/sign/Csc.kt`、`app/CscModel.kt` | PKCE、state、權杖只在記憶體；自訂服務的 http 只在測試設定允許時可用；轉址跟隨時的 cookie 不跨主機外洩 |
| PIN 與密碼 | 自然人憑證卡、PKCS#12、PDF 密碼 | 不寫入儲存區與紀錄；錯誤訊息不含 PIN |
| 紀錄 | `app/History.kt` | 只存欄位名稱，不存欄位值與文件內容 |

### 4.4 信任判定

- 等級只能由錨點決定：檢查每個 `TrustTier.T1` 的產生點，確認只來自 TWDIW 已列名且 Arbitrum 相符或標為官方的正式錨點。
- 使用者匯入的根憑證與 DID 是 T2，不會顯示為官方。
- 已過期的內建根憑證不再當成錨點。
- `TrustRegistry.extendFromPool` 逐層補鏈時不會讓中繼憑證自己變成錨點。
- AATL 與 EUTL 只用於 `TrustRole.DOCUMENT` 與 `TSA`，不會讓網站或發行端因此升級。

## 5. 已知未驗證項目

- 各階段驗收文件最後的「需要實機驗證」表。P3 的實機項目（NFC 自然人憑證簽章、MyData 自動流程、PortalWebView 下載、DC API 收卡與選擇器）在撰寫時都還沒有完整的實機紀錄。
- TWDIW 正式平台與 Microsoft Verified ID 的互通只在當時的網路狀況下驗過一次（見 [validation-network-2026-10-10.md](../research/validation-network-2026-10-10.md)），平台改版後要重測。
- 公文線上簽核的公開範例檔簽章值是佔位，驗證結果顯示「簽章值不符」是預期行為。
- P4 的所有項目（見 [p4-work-packages.md](../design/p4-work-packages.md) 的驗收條件）。

## 6. 指令

```bash
./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop
./gradlew :test-servers:test
./gradlew :app:desktopTest
./gradlew :app:assembleRelease
DIW_SIGNED_OUT=build/signed ./gradlew :test-servers:test --tests '*DocumentSigningTest'
./gradlew -p tools/dss-check run --args=build/signed
python3 -I tools/trust-roots/update_roots.py --check
```

測試方法寫成 `runBlocking<Unit> { ... }`；最後一行回傳值時 JUnit 會靜默略過，審查時要特別找這類被略過的測試（例如以 `grep -rn "fun .*= runBlocking {" test-servers/src/test` 找出沒有 `<Unit>` 的寫法再逐一確認）。

## 7. P4 審查

P4 完成時補上本節。審查依據：

- 電路：[p4-circuits.md](../design/p4-circuits.md) 第 7 節列出的安全性問題，逐項對照 Noir 程式與測試 Z1 到 Z14。
- 公開輸入：Kotlin 端（`core/document/zkpdf`）重算的公開輸入與電路宣告的順序完全一致；驗證端不採用證明附帶的任何未經重算的值。
- 資產：`core/src/commonMain/resources/zk/assets.json` 的 SHA-256 與大小，下載後先比對再載入。
- 原生程式庫：`native/` 的 Rust 依賴版本鎖定；uniffi 介面的錯誤不會帶出私密輸入；JNA 載入路徑不受外部控制。
- 信任：zkPDF 的等級取簽署者，不會是 T1；zkTLS 即時模式為 T2，notary 與裝置證明紀錄為 T3。

## 8. 回報格式

每個發現一列：

| 欄位 | 內容 |
|---|---|
| 嚴重度 | 高（可被利用或造成錯誤的信任判定）、中（功能錯誤或資料遺失）、低（品質、文件不符） |
| 位置 | `檔案:行號` |
| 情境 | 具體的輸入或操作，以及錯誤的結果 |
| 依據 | 對照的規則（AGENTS.md 第幾條或規格章節）與重現方式（測試名稱或步驟） |
| 建議 | 修正方向；需要使用者決定時寫出選項 |

修正以新的 `claude/...` 分支與 PR 提出，修 bug 先寫能重現的測試。

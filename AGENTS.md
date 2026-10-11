# AGENTS.md

給在此 repo 工作的程式代理（與新進開發者）的說明。使用者文件見 [README.md](README.md)。

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
| `app/src/commonMain` | Compose Multiplatform App：`WalletModel`（狀態、流程、紀錄）、`TaiwanModel`（TWDIW 平台服務與 Bonds）、`MsIssuanceModel`（Verified ID）、`ProximityModel`（ISO 18013-5 出示與 DC API Annex C）、`ReaderModel`（ISO 18013-5 查驗）、`StatusMonitor`、`History`（紀錄）、`ui/` |
| `app/src/androidMain`、`desktopMain` | 平台實作（相機掃描、硬體金鑰、DC API、Bonds BLE、圖片解碼、NFC：Android 的 HCE `WalletNfcService`、讀卡模式與 USB CCID `AndroidNfcReaders`，桌面的 PC/SC `PcscReaders`） |
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
| `profile/bonds` | Bonds 離線出示、BTWVP1 QR 與 BLE 分幀、vc+moica 驗證；來源 `a`（本錢包擴充：IETF SD-JWT VC、W3C SD-JWT 與 JWT VC） |
| `profile/msvid` | Microsoft Entra Verified ID 發行、Linked Domains |
| `w3c`、`status`、`trust`、`did`、`holder` | W3C VC、狀態清單、信任錨與 DID 信任、DID 解析、錢包層級持有者金鑰 |

## 已定的設計規則

1. **標準優先，方言隔離。** 標準路徑（OpenID4VCI / OpenID4VP 1.0、SD-JWT VC、mdoc）不含任何方言邏輯。方言只在標準會停下的位置透過 hook 介入（`IssuanceDialect`、`PresentationDialect` 的介面註解列出每個 hook），而且只對它擁有的 session 生效。
2. **所有方言常駐啟用，不提供開關。** TWDIW 官方實作與 Bonds 必須完整支援；新增方言時加入 `WalletModel` 的方言清單，不新增設定。
3. **信任分層。** T1 正式信任錨、T2 已列名但無法完全驗證、T3 可驗證但非官方（測試錨、使用者匯入、系統憑證庫、Linked Domains、未列名 DID）、T4 驗證失敗。正式與測試環境在同一個 App 內，UI 必須區分；測試環境的決策永遠不是官方。
   - 內建的 GPKI 錨點（`trust/BuiltInAnchors`，由 grca.nat.gov.tw 取得的運作中根憑證與中繼憑證）只確認身分，判定為 T2 並標示 `IDENTITY_VERIFIED`；MOICA 只用於查驗方（自然人憑證），不用於發行端。
   - 系統憑證庫（`TrustEnvironment.SYSTEM`，設定可關閉）只確認網域，判定為 T3（`SYSTEM_ANCHOR`）。
   - Multipaz 的 TrustManager 只支援 EC 金鑰，RSA 憑證鏈在它丟出例外時改用 PKIX（`trust/SystemTrustStore` 的 `Pkix`）驗證。
   - Microsoft Verified ID 依 Microsoft 錢包程式庫的規則：Linked Domains 驗證成功為 T3（`LINKED_DOMAIN`），與 Authenticator 一樣不需要額外勾選警示；驗證失敗為 T4。使用者自行信任的 DID 排在 Linked Domains 之前，連結暫時失效不會蓋過使用者的決定。
   - 信任來源改變（匯入、移除錨點或 DID）時，`StatusMonitor.reevaluateIssuers` 重新判定已持有證件的發行端並記錄。
4. **憑證不跟隨 jku；狀態清單可用 jku，但要先綁定發行端。** 憑證的簽章金鑰只能來自 x5c、DID、Data Integrity proof 或 JWT VC issuer metadata。狀態清單沒有其他金鑰來源時才用 jku（`trust/JkuKeys`），只接受 https，並依序綁定：JWK 的 x5c 連到任一啟用中的信任錨（不限 TWDIW）、jku 主機就是簽署者自己的主機（did:web 或 https 識別碼）、信任來源把主機綁到該 DID（TWDIW 已列名組織的主機與 wallet.gov.tw 平台、Linked Domains）。都綁不上時仍可驗證，但保證降為 `TLS_ONLY`，不可當成已驗證。
5. **狀態顯示規格原文。** 不自創狀態名稱，可展開細節；發證端未提供在地化時使用快取的關鍵字翻譯。是否接受某個狀態由 `status/StatusPolicy` 依用途風險（低、中、高）決定：撤銷一律拒絕；清單讀不到或簽章未驗證時，低風險接受、中風險需留意、高風險拒絕；`TLS_ONLY` 到中風險都可接受；過時或來自測試環境的「通過」降為需留意。證件自身的風險依分類（身分證件高、政府卡片中、其他低）；出示請求的風險取欄位敏感度（`credential/ClaimSensitivity`，揭露整張憑證時以實際含有的全部欄位與證件分類計算）與查驗方信任等級的較高者；查驗時由查驗者選擇用途風險。判定為拒絕的證件不能以勾選覆寫，只能重新查詢狀態（撤銷則不提供）。jku 無條件只接受 https，測試環境的本機 HTTP 例外不適用。
6. **兜底實作。** 平台或 SDK 不支援時改用純軟體實作（軟體金鑰、純 Kotlin QR 編碼），模擬器、AOSP、桌面都要能用。
7. **金鑰證明只確認金鑰有效，不檢查 RKP。**
8. **CI release 產物必須經 R8 / ProGuard 最佳化**，不可只是 debug 建置。
9. **介面以 EUDI Wallet 與 Bonds 的設計為準，不為發行端或 Profile 另開專區。** 首頁五個分頁：證件（所有證件同一清單，分組與篩選）、文件（簽章文件、公文、MyData，保留區域）、使用（出示、臨櫃條碼、加入證件）、查驗（App 作為查驗方）、紀錄（只存欄位名稱，不存內容）；設定在右上齒輪。方言帶來的功能併入這些共同位置：卡片目錄在「從清單選擇」、臨櫃條碼在「使用」、信任清單在設定。
10. **設計 token 沿用 Bonds**（`ui/UiKit.kt`）：互動主色為靛色，綠、橙、紅只用於判定（判定卡為 0.14 透明度色底、符號與文字三者並用，「部分」不可看起來像「通過」）；空狀態附直達動作；尚未實作的功能顯示為停用列並寫明原因，不隱藏；結果用畫面或判定卡呈現，警示對話框只用於確認有後果的動作。
11. **狀態主動更新，信任錨點不限 TWDIW。** `StatusMonitor` 在開啟與回到 App 時，於背景查詢逾時的狀態（依證件風險，同時最多 3 張），結果存在儲存區供離線使用；查詢失敗保留前一次有意義的結果並註明；狀態或發行端信任改變時通知並寫入紀錄（`HistoryKind.STATUS`）。所持 TWDIW 卡片的發行端每 12 小時重新查驗信任清單與 Arbitrum 註冊，離線或鏈上無法查詢時不變更。使用者可匯入任何 X.509 根憑證（USER 環境）或自行信任 DID（`trust/UserDidTrust`），兩者都是 T3，不會顯示為官方。

12. **近距離與 NFC。** mdoc 近距離出示與查驗都走 ISO/IEC 18013-5，同意畫面與一般出示共用（`requestedDocuments`、`riskAcknowledgement`）。只有「感應出示」畫面開著時，NFC 感應才會回應查驗設備。PC/SC 讀卡機只能讀取，電腦不提供 NFC 出示。

## 近距離（ISO 18013-5）與 NFC 要點

- Multipaz `NfcTransportMdocReader.open()` 在呼叫者的作用域啟動 I/O 迴圈，不可包在 `withTimeout` 內（會等到逾時）；連線逾時以另一個 coroutine 在逾時後關閉傳輸。
- Multipaz `NfcTransportMdoc` 的靜態實例只在 `NfcTransportMdoc.onDeactivated()`（感應場消失）時移除，`close()` 不會。Android 由 HCE 服務呼叫；測試的 `LoopbackTag.close()` 也要呼叫，否則下一個測試會出現兩個實例。
- NFC 是半雙工：最後一個 ENVELOPE 的回應就是持有者的 DeviceResponse，會等到使用者同意後才送出。
- PC/SC：只用短 APDU（`maxTransceiveLength` 261）；關閉 JDK 的自動 GET RESPONSE（`sun.security.smartcardio.t0GetResponse` / `t1GetResponse` 設為 false），由 18013-5 的 61XX 流程自行處理；Linux 自動尋找 `libpcsclite.so.1`；Windows 在沒有讀卡機時會停止智慧卡服務，重新列出時以反射重設 JDK 快取的 context（需要 `--add-opens java.smartcardio/sun.security.smartcardio=ALL-UNNAMED`）。
- `java.smartcardio` 不在 class path 預設解析的模組內：桌面編譯加 `-Xadd-modules=java.smartcardio`，執行與測試加 `--add-modules=java.smartcardio`，jlink 模組清單也要列入。
- Android 讀卡模式依 Multipaz：NFC-A/B、略過 NDEF 檢查、無系統音效，標籤在 callback 內處理，transceive 逾時 20 秒；Activity 回到前景時重新開啟讀卡模式。
- DC API 的 `org-iso-mdoc`（ISO 18013-7 Annex C）由 `ProximityModel.presentDcApi` 處理，Android 註冊時要列出這個 protocol。

## TWDIW 與 Bonds 要點

- TWDIW 發證：`credential_issuer` 結尾有 `/`，中繼資料以附加方式取得，沒有 AS metadata，token 端點為 `{issuer}token`，表單帶 `client_id=moda_dw`、`authorization_details`、空的 `tx_code`；proof 的 `kid` 是不帶 fragment 的 did:key（jwk_jcs），`iss` 為 client_id；回應 `{credential}`。中繼資料寫 `jwt_vc_json`，實際送 SD-JWT（`typ vc+sd-jwt`，無 `vct`，W3C 內容在 `vc`）。
- 每張 TWDIW 卡片綁定同一把錢包層級金鑰（`HolderIdentities.TWDIW`），才能一起出示。
- TWDIW 出示：client_id 為 did:key，要求物件由該 DID 簽章；回應是一個 jwt_vp（header 帶 `jwk`，有效 30 天），`presentation_submission` 用 `jwt_vp` + `path_nested jwt_vc`，成功判斷為 `code == "0"`。
- TWDIW 主機的 gate 只接受 https 443 埠，測試時以 ktor `MockEngine` 模擬 `*.wallet.gov.tw`（見 `TwdiwPlatformMock`）。
- wallet.gov.tw 的 Cloudflare 會擋 HTTP 函式庫預設 User-Agent，`TwdiwUserAgent` 只對 TWDIW 主機改寫 UA。
- TWDIW 狀態清單（StatusList2021）由 key-2 簽章，金鑰只公布在 jku `https://issuer-vc.wallet.gov.tw/api/keys`；該端點各次回應的 key-2 不一致（上游問題），驗簽失敗時重抓金鑰集，最多 4 次。發行端已列名時 jku 主機屬於平台，綁定成立；未列名（如 demo 發行端）為 `TLS_ONLY`。
- Microsoft Verified ID 出示：`openid-vc://?request_uri=...` 沒有外層 client_id，client_id 在已簽章的要求物件內；`claims.vp_token.presentation_definition` 表示回應要帶 vp_token；PE v1 的 `schema[].uri` 是憑證類型。`path_nested` 為 `jwt_vc` 且路徑是 `$.verifiableCredential[i]`（相對於 vp claim，見 `PresentationDialect.nestedPath`），寫成 `$.vp.verifiableCredential[i]` 時驗證端回 401「presentation does not include any verifiable credentials」。
- Bonds：持有者是 BLE GATT 周邊，以要求中的一次性 UUID 廣播；frames characteristic `2B1D0001-…` notify，查驗方寫 `0x01` 到 `2B1D0002-…` 表示收齊。QR 分幀前綴 `BTWVP1`，以 ECC Q 顯示。
- Bonds 請求的 `k`：`g` 政府皮夾卡片、`s` 自然人憑證自發卡、`a` 本錢包擴充（任何綁定金鑰的證件）。回應 `g` 時只列 TWDIW 卡片，保持與 Bonds 相容。`a` 的封裝：`data:application/dc+sd-jwt,`（IETF SD-JWT VC 以 `vct` 辨識，持有者 DID 為 cnf 金鑰的 did:jwk；W3C SD-JWT 沿用 TWDIW 檢查）與 `data:application/vc+jwt,`（W3C JWT VC，`sub` 或 credentialSubject.id 為持有者 DID）。SD-JWT VC 的發行端金鑰依序來自 x5c、DID iss、JWT VC issuer metadata（需要網路）。

## 建置與測試

```bash
./gradlew :core:compileKotlinJvm               # 快速檢查 core
./gradlew :app:compileKotlinDesktop            # 快速檢查 App 共用程式
./gradlew :test-servers:test                   # 協議、互通、方言測試
./gradlew :test-servers:test --tests 'diw.testservers.TwdiwPlatformTest'
./gradlew :app:desktopTest                     # App 流程測試
DIW_SCREENSHOTS=build/shots ./gradlew :app:desktopTest --tests '*uiScreenshots'   # 離屏渲染主要畫面為 PNG
./gradlew :app:assembleRelease                 # Android release（R8）
```

測試慣例：

- 協議測試都放在 `test-servers/src/test`；真實伺服器用 `TestServers`（http loopback），https-only 的平台用 `MockEngine`。
- 測試方法用 `runBlocking<Unit> { ... }`。最後一行若回傳值（例如 `assertFailsWith`），JUnit 會因方法不是 void 而**靜默略過**該測試。
- 修 bug 先寫出能重現的測試。

## 分支、PR 與 CI

- 每個階段（P1、P2…）在各自的 `claude/...` 分支開發並開新 PR，PR 合併後不再沿用同一個 PR。
- `.github/workflows` 無法由代理推送（缺 workflow 權限）；需要修改時把完整檔案交給使用者手動貼上。
- 發佈流程與簽章 secrets 見 [docs/release.md](docs/release.md)。

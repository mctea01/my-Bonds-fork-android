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
| `app/src/commonMain` | Compose Multiplatform App：`WalletModel`（狀態、流程、紀錄）、`TaiwanModel`（TWDIW 平台服務與 Bonds）、`MsIssuanceModel`（Verified ID）、`History`（紀錄）、`ui/` |
| `app/src/androidMain`、`desktopMain` | 平台實作（相機掃描、硬體金鑰、DC API、Bonds BLE、圖片解碼） |
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
| `profile/bonds` | Bonds 離線出示、BTWVP1 QR 與 BLE 分幀、vc+moica 驗證 |
| `profile/msvid` | Microsoft Entra Verified ID 發行、Linked Domains |
| `w3c`、`status`、`trust`、`did`、`holder` | W3C VC、狀態清單、信任錨與 DID 信任、DID 解析、錢包層級持有者金鑰 |

## 已定的設計規則

1. **標準優先，方言隔離。** 標準路徑（OpenID4VCI / OpenID4VP 1.0、SD-JWT VC、mdoc）不含任何方言邏輯。方言只在標準會停下的位置透過 hook 介入（`IssuanceDialect`、`PresentationDialect` 的介面註解列出每個 hook），而且只對它擁有的 session 生效。
2. **所有方言常駐啟用，不提供開關。** TWDIW 官方實作與 Bonds 必須完整支援；新增方言時加入 `WalletModel` 的方言清單，不新增設定。
3. **信任分層。** T1 正式信任錨、T2 已列名但無法完全驗證、T3 可驗證但非官方（測試錨、Linked Domains、未列名 DID）、T4 驗證失敗。正式與測試環境在同一個 App 內，UI 必須區分；測試環境的決策永遠不是官方。
4. **憑證不跟隨 jku；狀態清單可用 jku，但要先綁定發行端。** 憑證的簽章金鑰只能來自 x5c、DID、Data Integrity proof 或 JWT VC issuer metadata。狀態清單沒有其他金鑰來源時才用 jku（`trust/JkuKeys`），只接受 https，並依序綁定：JWK 的 x5c 連到任一啟用中的信任錨（不限 TWDIW）、jku 主機就是簽署者自己的主機（did:web 或 https 識別碼）、信任來源把主機綁到該 DID（TWDIW 已列名組織的主機與 wallet.gov.tw 平台、Linked Domains）。都綁不上時仍可驗證，但保證降為 `TLS_ONLY`，不可當成已驗證。
5. **狀態顯示規格原文。** 不自創狀態名稱，可展開細節；發證端未提供在地化時使用快取的關鍵字翻譯。是否接受某個狀態由 `status/StatusPolicy` 依用途風險（低、中、高）決定：撤銷一律拒絕；清單讀不到或簽章未驗證時，低風險接受、中風險需留意、高風險拒絕；`TLS_ONLY` 到中風險都可接受；過時或來自測試環境的「通過」降為需留意。證件自身的風險依分類（身分證件高、政府卡片中、其他低）；出示請求的風險取欄位敏感度（`credential/ClaimSensitivity`）與查驗方信任等級的較高者；查驗時由查驗者選擇用途風險。
6. **兜底實作。** 平台或 SDK 不支援時改用純軟體實作（軟體金鑰、純 Kotlin QR 編碼），模擬器、AOSP、桌面都要能用。
7. **金鑰證明只確認金鑰有效，不檢查 RKP。**
8. **CI release 產物必須經 R8 / ProGuard 最佳化**，不可只是 debug 建置。
9. **介面以 EUDI Wallet 與 Bonds 的設計為準，不為發行端或 Profile 另開專區。** 首頁五個分頁：證件（所有證件同一清單，分組與篩選）、文件（簽章文件、公文、MyData，保留區域）、使用（出示、臨櫃條碼、加入證件）、查驗（App 作為查驗方）、紀錄（只存欄位名稱，不存內容）；設定在右上齒輪。方言帶來的功能併入這些共同位置：卡片目錄在「從清單選擇」、臨櫃條碼在「使用」、信任清單在設定。
10. **設計 token 沿用 Bonds**（`ui/UiKit.kt`）：互動主色為靛色，綠、橙、紅只用於判定（判定卡為 0.14 透明度色底、符號與文字三者並用，「部分」不可看起來像「通過」）；空狀態附直達動作；尚未實作的功能顯示為停用列並寫明原因，不隱藏；結果用畫面或判定卡呈現，警示對話框只用於確認有後果的動作。
11. **狀態主動更新，信任錨點不限 TWDIW。** `StatusMonitor` 在開啟與回到 App 時，於背景查詢逾時的狀態（依證件風險，同時最多 3 張），結果存在儲存區供離線使用；查詢失敗保留前一次有意義的結果並註明；狀態或發行端信任改變時通知並寫入紀錄（`HistoryKind.STATUS`）。所持 TWDIW 卡片的發行端每 12 小時重新查驗信任清單與 Arbitrum 註冊，離線或鏈上無法查詢時不變更。使用者可匯入任何 X.509 根憑證（USER 環境）或自行信任 DID（`trust/UserDidTrust`），兩者都是 T3，不會顯示為官方。

## TWDIW 與 Bonds 要點

- TWDIW 發證：`credential_issuer` 結尾有 `/`，中繼資料以附加方式取得，沒有 AS metadata，token 端點為 `{issuer}token`，表單帶 `client_id=moda_dw`、`authorization_details`、空的 `tx_code`；proof 的 `kid` 是不帶 fragment 的 did:key（jwk_jcs），`iss` 為 client_id；回應 `{credential}`。中繼資料寫 `jwt_vc_json`，實際送 SD-JWT（`typ vc+sd-jwt`，無 `vct`，W3C 內容在 `vc`）。
- 每張 TWDIW 卡片綁定同一把錢包層級金鑰（`HolderIdentities.TWDIW`），才能一起出示。
- TWDIW 出示：client_id 為 did:key，要求物件由該 DID 簽章；回應是一個 jwt_vp（header 帶 `jwk`，有效 30 天），`presentation_submission` 用 `jwt_vp` + `path_nested jwt_vc`，成功判斷為 `code == "0"`。
- TWDIW 主機的 gate 只接受 https 443 埠，測試時以 ktor `MockEngine` 模擬 `*.wallet.gov.tw`（見 `TwdiwPlatformMock`）。
- wallet.gov.tw 的 Cloudflare 會擋 HTTP 函式庫預設 User-Agent，`TwdiwUserAgent` 只對 TWDIW 主機改寫 UA。
- TWDIW 狀態清單（StatusList2021）由 key-2 簽章，金鑰只公布在 jku `https://issuer-vc.wallet.gov.tw/api/keys`；該端點各次回應的 key-2 不一致（上游問題），驗簽失敗時重抓金鑰集，最多 4 次。發行端已列名時 jku 主機屬於平台，綁定成立；未列名（如 demo 發行端）為 `TLS_ONLY`。
- Microsoft Verified ID 出示：`openid-vc://?request_uri=...` 沒有外層 client_id，client_id 在已簽章的要求物件內；`claims.vp_token.presentation_definition` 表示回應要帶 vp_token；PE v1 的 `schema[].uri` 是憑證類型。
- Bonds：持有者是 BLE GATT 周邊，以要求中的一次性 UUID 廣播；frames characteristic `2B1D0001-…` notify，查驗方寫 `0x01` 到 `2B1D0002-…` 表示收齊。QR 分幀前綴 `BTWVP1`，以 ECC Q 顯示。

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

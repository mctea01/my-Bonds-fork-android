# 專案現況

最後更新：2026-11-13（main 到 PR #131，加上 OFD 寫錯名稱的還原）。

這一頁是專案狀態的唯一來源：各階段、各功能目前做到哪裡、還缺什麼、哪些等實機驗證。其他文件不再各自寫「目前狀態」，需要時連到這裡。

**維護規則：** 會改變狀態的提交或 PR（完成或新增功能、留下未完成項目、平台支援改變、決定改變）要在同一個 PR 內更新本頁與「最後更新」的日期；規則見 [AGENTS.md](../AGENTS.md#文件分支pr-與-ci)。本頁只寫結論，細節放在連結的文件。

## 1. 一眼看完

- 版本線 `0.4`（[version.properties](../version.properties)），main 每次更新由 CI 發佈 nightly。
- P1 到 P4 與其後的延伸功能都已合併進 main；P5（驗證者透明與主動驗證）、P6（iOS）尚未開始。
- 平台：Android（API 29 以上）與 Windows、Linux 桌面版為正式發佈；macOS 只提供 jar。
- 正式服務端在另一個 repo [diw-wallet-server](https://github.com/mctea01/diw-wallet-server)，狀態見該 repo 的 `docs/STATUS.md`。
- 多數功能以自動測試與測試伺服器驗收，實機驗證只做了一部分，見第 5 節。

## 2. 階段

| 階段 | 內容 | 狀態 | 紀錄 |
|---|---|---|---|
| P0 | 骨架與風險實測 | 完成（2026-10-10） | [validation-2026-10-10.md](research/validation-2026-10-10.md) |
| P1 | 標準核心：OpenID4VCI 1.0、OpenID4VP 1.0、SD-JWT VC、mdoc、DC API | 完成（PR #1） | [p1-acceptance.md](acceptance/p1-acceptance.md) |
| P2 | OpenID4VC 全組合與相容 Profile（TWDIW、Bonds、Verified ID、草案 11／13、EUDI）、ISO 18013-5 近距離 | 完成（PR #5、#7） | [p2-acceptance.md](acceptance/p2-acceptance.md)、[p2-followup.md](acceptance/p2-followup.md) |
| P3 | 文件、簽章、時戳、衍生憑證、電子公文、取件入口 | 完成（PR #8、#9、#11） | [p3-acceptance.md](acceptance/p3-acceptance.md)、[p1-p3-followup-2026-10-16.md](acceptance/p1-p3-followup-2026-10-16.md) |
| P4 | 零知識證明：zkPDF、zkTLS、年齡證明、mdoc ZK | 完成（PR #12，2026-11-06） | [p4-zkp.md](design/p4-zkp.md)、[p4-work-packages.md](design/p4-work-packages.md) |
| P5 | 驗證者透明與主動驗證（查驗方身分、代表關係、線上查驗） | 未開始；出示端的 verifier_info 檢查已在 P3 完成 | [architecture-and-roadmap.md](design/architecture-and-roadmap.md) |
| P6 | iOS | 未開始 | 同上 |

P4 之後合併的工作：

| 工作 | 狀態 | 設計與紀錄 |
|---|---|---|
| 全專案 Review 後續（OpenID Federation、PIV、CSC 補全、C2PA、可見簽章、付款交易、交換檔、直接分享） | 完成，剩餘項目見第 4 節 | [review-followups.md](design/review-followups.md) |
| OpenPGP 與 OpenPGP 卡 | 完成 | [openpgp.md](design/openpgp.md) |
| TWDIW 新版應用簽章（1.0.14 格式） | 實作完成；官方平台是否接受未驗收 | [twdiw-application-signature.md](acceptance/twdiw-application-signature.md) |
| 法律聲明、首次啟動同意、專門聲明（PR #80） | 完成 | [legal/README.md](legal/README.md) |
| i18n：英文與繁體中文（PR #89） | 完成 | [i18n.md](design/i18n.md) |
| Google Play 上架準備（PR #84） | 文件、圖像與自動提交 workflow 已在 main；實際上架進度以 Play Console 為準 | [google-play.md](google-play.md) |
| 電子護照讀取與 zkPassport（Z1 到 Z4、PR #121、#127） | 完成；人臉比對不提供 | [zkpassport.md](design/zkpassport.md) |
| 原生依賴跨平台：Windows zkPDF（無 GPL 執行階段）、Linux ARM64、Android 32 位元（PR #121） | 完成 | [native-dependencies](research/native-dependencies/README.md) |
| OFD 預覽、發票欄位、簽署與 SES 電子印章（PR #122） | 完成 | [AGENTS.md](../AGENTS.md) 規則 3 與 P3 要點 |
| OFD 寫錯元素或屬性名稱的檔案還原（`OfdRepair`） | 完成；以一份真實檔案在本機核對過，與同一份文件的 PDF 版一致 | [AGENTS.md](../AGENTS.md) 的 `document/ofd` |
| bbs-2023（含三種可選功能，PR #123） | 完成 | [bbs-2023.md](design/bbs-2023.md) |
| 桌面版 GraalVM 原生執行檔（PR #125） | 實驗：Linux、Windows 由 CI 建置並通過自我檢查，只上傳為 Artifact；macOS 不支援。JVM 版仍是正式發行 | [release.md](release.md)、[AGENTS.md](../AGENTS.md) 的零知識證明要點 |

## 3. 功能狀態

狀態用語：**可用**（已在 main、有自動測試）、**部分**（列出缺的部分）、**停用列**（畫面上顯示為停用並寫明原因）、**未做**。

### 3.1 數位憑證

| 功能 | 狀態 | 備註 |
|---|---|---|
| OpenID4VCI 1.0 與草案 11 至 13 領卡 | 可用 | 用戶端驗證依授權伺服器選擇（錢包證明、private_key_jwt、公開用戶端） |
| 格式：mdoc、SD-JWT VC、W3C VC（JWT、JSON-LD、Data Integrity、bbs-2023） | 可用 | bbs-2023 可選功能的發證是 DIW 擴充 |
| OpenID4VP 1.0（DCQL、transaction data）與舊版草案 | 可用 | 加密的 request object 會被拒絕（App 沒有登錄解密金鑰） |
| Digital Credentials API 出示與收卡 | 可用 | 只有 W3C 格式的卡片（如 TWDIW）不會出現在系統選擇器 |
| ISO 18013-5 近距離出示與查驗（NFC、QR、BLE；PC/SC 只讀） | 可用 | 兩機 NFC 互通待實機驗證 |
| OpenID Federation 1.0（查驗方與發證端） | 可用 | |
| 狀態清單（Token Status List、Bitstring、StatusList2021、RevocationList2020、IdentifierList） | 可用 | |
| 查驗分頁：離線挑戰、感應查驗、年齡、網站查驗、zkPassport | 可用 | |
| 查驗分頁：線上查驗（OpenID4VP）、以誰的身分查驗 | 停用列 | 屬 P5 |

### 3.2 相容 Profile

| Profile | 狀態 | 備註 |
|---|---|---|
| TWDIW（數位憑證皮夾） | 可用；需同意專門聲明 | 舊版發證端可領卡；新版夥伴卡平台（moda.wallet.gov.tw）是否接受本 App 的應用簽章未驗收 |
| Bonds（離線出示、查驗、身分證卡、年齡證明） | 可用 | |
| Microsoft Entra Verified ID | 可用；需同意專門聲明 | |
| EUDI 參考實作、OpenID4VCI 草案 11／13 | 可用 | |
| MyData、行動自然人憑證、zkPassport | 可用；各需同意專門聲明 | 行動自然人憑證需要 SP 帳號，發布版本不內建 |

### 3.3 文件與簽章

| 功能 | 狀態 | 備註 |
|---|---|---|
| 檢查：PAdES、CAdES、XAdES、ASiC、.si、OFD 與 SES、RFC 3161、OpenCerts、SM2、OpenPGP、C2PA | 可用 | C2PA 不含 BMFF（影片、HEIC）、PDF 內嵌與 `c2pa.hash.boxes` |
| 簽署：自然人憑證卡、PIV、OpenPGP 卡、PKCS#11、PKCS#12、系統金鑰、錢包金鑰、CSC、行動自然人憑證 | 可用 | CSC 的 `authorization_details`（RFC 9396）未做 |
| 保證層級 B-B 到 B-LTA、PDF 認證簽章、可見簽章、延長保存 | 可用 | |
| OFD 預覽、發票欄位、數位簽章與電子印章 | 可用 | SM2 金鑰只用於 OFD；名稱寫錯的頁面與資源檔會還原並加註，頁面清單以外的結構檔（Document.xml 等）寫錯則不處理 |
| 電子公文容器、線上簽核點、交換檔（.en、.esw）讀取 | 可用 | .esw 不解密；交換檔尚無真實樣本比對 |
| 公文交換收發 | 停用列 | 需要機關的公文電子交換帳號與憑證 |
| 衍生憑證（SD-JWT VC、vc+moica）、Bonds 身分證卡 | 可用 | |
| 電子護照（BAC、PACE、被動驗證）、護照衍生憑證、Photo ID mdoc | 可用 | 尚未以實體護照完整驗收 |
| 取件入口（MyData、MyDoc、移民署、稅務入口網等） | 可用 | 桌面版以外部瀏覽器開啟 |

### 3.4 零知識證明

| 功能 | 狀態 | 備註 |
|---|---|---|
| 年齡證明（OpenAC，與 Bonds 相容） | 可用 | 主機、藍牙、區網、動態 QR |
| 網站查驗證明（zkTLS，TLSNotary） | 可用 | 查驗頁：學信網學籍報告（中、英文）、移民署入出國日期證明書 |
| mdoc 零知識出示（Longfellow） | 可用 | 只支援 P-256 發行端；Windows 沒有 Longfellow 函式庫 |
| zkPDF | 可用；手機上很慢 | 版型：福州大學在學證明、國家移民管理局通行證關聯查詢結果；v1 只證明第 1 頁。手機建議改在電腦版或自架主機產生 |
| zkPassport 查驗與回應 | 可用 | 回應可在手機、自架證明器或臨時證明器產生；要求人臉比對的請求只能拒絕 |

### 3.5 平台

| 平台 | 發佈 | 零知識後端 |
|---|---|---|
| Android arm64-v8a、x86_64 | APK、AAB、分割 APK 組 | 全部；Barretenberg 5（舊 zkPassport 電路）在 Play 版是隨選模組 |
| Android armeabi-v7a、x86 | 同一個 APK | 沒有證明後端，只有相片解碼 |
| Windows x86_64 | .msi、jar | 年齡證明、zkTLS、zkPDF、zkPassport；沒有 Longfellow |
| Linux x86_64 | .deb、jar | 全部 |
| macOS arm64（14 以上） | 只有 jar | 全部 |
| Linux ARM64 | 沒有安裝檔與 CI | 原生函式庫可交叉建置 |
| iOS | 未開始（P6） | |

## 4. 未完成與待決定

| 項目 | 說明 | 等待 |
|---|---|---|
| P5 驗證者透明與主動驗證 | 查驗方聲明、代表身分、線上查驗、衍生憑證與 ZK 證明的查驗政策 | 排程 |
| P6 iOS | | 排程 |
| TWDIW 新版夥伴卡 | 應用簽章格式已照 1.0.14 實作（appHash 為 `tw.gov.moda.diw`，簽章金鑰是本錢包自己的應用配對），官方平台准入與端到端領卡沒有驗收 | 合法的應用金鑰或官方契約 |
| P4 驗收文件 | P4 沒有寫獨立的驗收文件，結果記在 [p4-work-packages.md](design/p4-work-packages.md) 第 2.1 節與 [p4-benchmarks.md](research/p4-benchmarks.md) | 視需要補 |
| zkPDF 手機效能 | 一次實測在 611 秒逾時、峰值約 2.5 GB；完整時間未量到 | 實機量測（可選） |
| zkPDF 多頁文件 | v1 只接受單頁，2 頁的出入境記錄沒有版型 | 排程 |
| zkPassport 人臉比對與加鹽唯一識別碼 | 人臉比對不提供；本專案 OPRF 的服務端已實作 | Play Integrity 金鑰、排程 |
| zkPassport 離線註冊表模式 | 離線時無法查驗 | 排程 |
| 加密 request object 的解密金鑰登錄 | 程式路徑已有，App 沒有登錄金鑰 | 排程 |
| CSC `authorization_details` | RFC 9396 | 可測的服務 |
| C2PA 其他容器與寫入 | BMFF、PDF 內嵌、`c2pa.hash.boxes`、身分彙整服務的簽章 | 排程 |
| France Identité 互通 | 協定已具備，缺合作夥伴登錄 | 使用者決定是否申請 |
| 關於頁的第三方元件清單 | 只列主要元件，完整清單在 [NOTICE](../NOTICE) | 視需要補 |
| 台灣 G2C | 尚無公開標準，只留接口 | 外部 |

不規劃：Android HTTPS App Links、TWDIW 高安全皮夾、zkOFD、戶政司電子戶籍謄本的 zkTLS（查驗頁不回內容）。

## 5. 待實機驗證

雲端環境沒有實機，下列項目只有自動測試或桌面模擬。步驟與判定在 [device-test-checklist.md](research/device-test-checklist.md)。

| 範圍 | 項目 |
|---|---|
| 近距離 | 兩支手機的 NFC 交握（協商式、靜態）、NFC 資料傳輸、HCE 與多錢包並存、感應查驗（N1 至 N7） |
| DC API | 多重簽章請求、系統選擇器多張證件、收卡 |
| 發證與出示 | 公開發證端（EUDI）以錢包證明或公開用戶端領卡、mdoc transaction_data、付款交易、VICAL 與 RICAL |
| TWDIW | 新版夥伴卡領卡、平台改版後的出示重測 |
| 簽章 | 自然人憑證卡與 CSC 的 B-LTA、延長保存、PDF 可見簽章（以 Acrobat 檢查）、PIV、OpenPGP 卡（YubiKey NFC 與 USB） |
| 文件 | 交換檔真實樣本、C2PA 相機與編修軟體樣本、分享到常用 App 的檔名 |
| 零知識 | 兩機年齡證明（藍牙、區網、動態 QR）、zkTLS 手機查驗方（區網與中繼）、Longfellow 近距離、release APK 的原生函式庫載入、zkPDF 手機完整時間 |
| 電子護照 | 實體護照與台胞證的完整流程、zkPassport 與官方 App 互通 |
| 桌面 | PC/SC 讀卡機、PKCS#11、Windows 與 Linux 安裝檔 |

已有實機紀錄：D1 裝置的金鑰證明與 NFC 讀取自然人憑證（[device-results-D1-2026-10-10.md](research/device-results-D1-2026-10-10.md)）。開發期間使用者回報過的實機結果（TWDIW 舊版發證端領卡、DC API 選擇器、Verified ID 出示的修正）記在各階段的驗收與後續文件，沒有整理成完整的實機紀錄，平台改版後要重測。

## 6. 外部條件

這些不是程式缺陷，沒有對應的資格就無法驗收：

- 內政部行動自然人憑證 SP 帳號（開發者沒有；發布版本不內建）。
- 合格信任服務提供者（QTSP）的正式 CSC 服務；目前只有 EUDI 測試服務。
- 機關的公文電子交換帳號與憑證。
- TWDIW 官方平台對第三方 App 的准入。
- Google Play 的審查與 Play Integrity。

## 7. 相依與工具版本

| 項目 | 版本 |
|---|---|
| Kotlin、AGP、Compose Multiplatform | 2.4.21、8.13.2、1.10.1 |
| Multipaz | 0.102.0 |
| Ktor | 3.6.1（OkHttp 固定 5.4.0） |
| Bouncy Castle | 1.86 |
| JDK | 21（Android 目標為 17） |
| Android | compileSdk 36、minSdk 29、targetSdk 36、NDK 28.2.13676358 |
| Rust | 1.99.1（`native/rust-toolchain.toml`） |
| Barretenberg、Noir | 6.0.0（另有 5.0.0 選用元件）、1.0.0-rc.3 |
| TLSNotary | 0.1.0-alpha.15 |

版本以 `gradle/libs.versions.toml`、根目錄 `build.gradle.kts` 與 `native/Cargo.lock` 為準；升級由 Renovate 開 PR。

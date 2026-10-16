# 文件索引

設計與研究文件記錄的是撰寫當時的判斷，之後的決定以 [AGENTS.md](../AGENTS.md) 為準（例如階段順序、方言常駐啟用、信任分層的細節）。內容已與實作不同的設計與驗收文件，開頭有「現況（2026-10-16）」說明哪些部分已改變；研究文件與實機紀錄保留原貌。P4 尚未實作的部分以 P4 的三份設計文件為準。研究中提到的 `validation/` 原始記錄（實機 log、APK、伺服器輸出）只存在專案的共用資料夾，沒有收入 repo。

## 設計

| 文件 | 內容 |
|---|---|
| [design/architecture-and-roadmap.md](design/architecture-and-roadmap.md) | 技術背景與跨平台轉換規劃：參考來源、TWDIW 官方 App 現況、目標架構、協定支援矩陣、驗證者身分與目的、ZKP 策略、電子文件、軟體兜底、PKI 分區、判定模型、P2 實作規劃、分階段路線圖、P0 驗證與風險 |
| [design/document-credentials.md](design/document-credentials.md) | 文件憑證方案：每份文件產生衍生憑證再疊加證據；zkPDF、zkTLS、Bonds、OpenCerts 的比較，各類台灣與中國大陸文件的樣本分析與查驗方式，主動簽署、自然人憑證卡與行動自然人憑證 |
| [design/p4-zkp.md](design/p4-zkp.md) | P4 零知識證明總體設計與約定：四種證據（zkPDF、zkTLS、年齡證明、mdoc ZK）、D1 到 D6 的決定、架構與套件邊界、資料格式、信任與隱私、裝置分級、資產、驗收與風險 |
| [design/p4-circuits.md](design/p4-circuits.md) | P4 電路規格：樣本結構量測、zkPDF 電路（SHA-256 中間狀態窗口、inflate、lexer、錨點、欄位承諾、日期述詞）、zkTLS 揭露規則、OpenAC 與 Longfellow 的引用方式、安全審查重點 |
| [design/p4-work-packages.md](design/p4-work-packages.md) | P4 工作包拆分（Codex 與 Claude 分工）：分支與 PR 規則、WP0 到 WP10 的介面、相依、驗收條件與交接範本 |

## 研究

| 文件 | 內容 |
|---|---|
| [research/twdiw.md](research/twdiw.md) | TWDIW 官方 App 與平台的發證、出示、信任清單與互通細節 |
| [research/bonds.md](research/bonds.md) | Bonds 的離線出示、自發卡（vc+moica）、MyData 流程與已知問題 |
| [research/multipaz-eudi-ms.md](research/multipaz-eudi-ms.md) | Multipaz、EUDI 參考實作與 Microsoft Entra Verified ID |
| [research/documents-signatures.md](research/documents-signatures.md) | 簽章電子文件格式（PAdES、CAdES、XAdES、OFD、ASiC、時戳）與驗證 |
| [research/official-document-files.md](research/official-document-files.md) | 電子公文檔案結構（DI、SI、外部檔案、文稿頁面檔）、SI 簽核點，以及檔案管理局健檢類別與錢包的對應 |
| [research/zkp-verifier.md](research/zkp-verifier.md) | ZKP 全景、驗證者身分與意圖揭露、信任分級 UI |
| [research/validation-2026-10-10.md](research/validation-2026-10-10.md) | P0 本地驗證結果 |
| [research/validation-network-2026-10-10.md](research/validation-network-2026-10-10.md) | 需要外部網路的補驗結果 |
| [research/device-test-checklist.md](research/device-test-checklist.md) | 實機測試清單 |
| [research/device-results-D1-2026-10-10.md](research/device-results-D1-2026-10-10.md) | D1 實機結果（金鑰證明、NFC 讀取自然人憑證） |

## 驗收

| 文件 | 內容 |
|---|---|
| [acceptance/p1-acceptance.md](acceptance/p1-acceptance.md) | P1 標準核心 |
| [acceptance/p2-acceptance.md](acceptance/p2-acceptance.md) | P2 OpenID4VC 全組合與相容 Profile |
| [acceptance/p2-followup.md](acceptance/p2-followup.md) | P2 後續：狀態、風險與信任錨點 |
| [acceptance/p3-acceptance.md](acceptance/p3-acceptance.md) | P3 文件、簽章與衍生憑證 |
| [acceptance/p1-p3-followup-2026-10-16.md](acceptance/p1-p3-followup-2026-10-16.md) | P1 到 P3 補強：OpenID4VCI 用戶端驗證、DC API 多重簽章、加密要求物件、mdoc transaction_data、VICAL 與 RICAL、CSC |

## Review

| 文件 | 內容 |
|---|---|
| [review/project-review.md](review/project-review.md) | 全專案審查指南：閱讀順序、熱點檔案、設計規則對照的程式位置、安全審查重點、已知未驗證項目、P4 審查依據與回報格式 |

## 使用與發佈

| 文件 | 內容 |
|---|---|
| [guides/windows-local-test.md](guides/windows-local-test.md) | 在 Windows 啟動本機測試伺服器，設定錢包、領卡與出示 |
| [release.md](release.md) | CI 發佈的檔案與簽章 secrets |

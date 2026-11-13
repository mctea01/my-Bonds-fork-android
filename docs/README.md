# 文件索引

## 先讀什麼

| 想知道 | 讀這份 |
|---|---|
| 專案現在做到哪裡、還缺什麼、哪些待實機驗證 | [STATUS.md](STATUS.md)（單頁，狀態的唯一來源） |
| 有哪些功能、怎麼下載與建置 | [../README.md](../README.md) |
| 開發規則、模組職責、各領域的實作要點 | [../AGENTS.md](../AGENTS.md) |
| 某個領域的設計規格 | 下方「設計」中標為現行規格的文件 |
| 第三方元件與授權 | [../NOTICE](../NOTICE)、[../LICENSE](../LICENSE) |

多數工作只需要前三份。設計、研究與驗收文件在要動到該領域時才讀。

## 文件的性質

每份文件屬於下列一種，索引的「性質」欄標明：

- **現行**：與 main 的程式一致，功能改變時要一起更新。與程式不一致時視為文件的缺陷。
- **規格**：某個領域的設計約定，仍然有效；實作狀態不寫在裡面，見 STATUS.md。
- **紀錄**：撰寫當時的研究、規劃、驗收或實機結果，保留原貌、不回頭改寫。開頭註明日期，內容與現況不同處以 STATUS.md 與 AGENTS.md 為準。

研究中提到的 `validation/` 原始記錄（實機 log、APK、伺服器輸出）只存在專案的共用資料夾，沒有收入 repo。正式服務端在另一個 repo [diw-wallet-server](https://github.com/mctea01/diw-wallet-server)。

## 現況、使用與發佈

| 文件 | 性質 | 內容 |
|---|---|---|
| [STATUS.md](STATUS.md) | 現行 | 階段、功能狀態、平台、未完成項目、待實機驗證、外部條件、相依版本 |
| [release.md](release.md) | 現行 | CI 發佈的檔案、版本號規則、Android 選用元件、簽章 secrets、TWDIW 應用金鑰、縮減規則 |
| [google-play.md](google-play.md) | 現行 | Google Play 上架：上架前檢查、簽署金鑰、自動提交 workflow、商店資訊、資料安全與內容分級答案 |
| [legal/README.md](legal/README.md) | 現行 | 隱私權政策、用戶協議與專門聲明的網頁版（由 App 內文字產生，中文與英文） |
| [guides/windows-local-test.md](guides/windows-local-test.md) | 現行 | 在 Windows 啟動本機測試伺服器，設定錢包、領卡與出示 |
| [research/device-test-checklist.md](research/device-test-checklist.md) | 現行 | 實機測試清單：步驟與判定 |
| [../templates/README.md](../templates/README.md) | 現行 | 零知識證明版型包（zkTLS 查驗頁與 zkPDF 版型）的格式、簽章與發佈 |
| [../native/README.md](../native/README.md) | 現行 | 原生函式庫的建置、目標平台與 CI |

## 設計

| 文件 | 性質 | 內容 |
|---|---|---|
| [design/p4-zkp.md](design/p4-zkp.md) | 規格 | 零知識證明總體設計：四種證據、資料格式、信任與隱私、裝置分級、資產 |
| [design/p4-circuits.md](design/p4-circuits.md) | 規格 | 電路規格：zkPDF 電路與分段證明、zkTLS 揭露規則、OpenAC 與 Longfellow 的引用方式、安全審查重點 |
| [design/zkpassport.md](design/zkpassport.md) | 規格 | 電子護照與 zkPassport：請求與 bridge 協定、查驗與信任、Z1 到 Z4、自己的證明器、OPRF、法律聲明 |
| [design/bbs-2023.md](design/bbs-2023.md) | 規格 | bbs-2023：原生 BBS、JSON-LD 與 RDFC-1.0、可選功能的 DIW 發證擴充、出示與查驗 |
| [design/openpgp.md](design/openpgp.md) | 規格 | OpenPGP 與 OpenPGP 卡：APDU、簽署與解密、公開金鑰清單與信任等級 |
| [design/i18n.md](design/i18n.md) | 規格 | 多語系：字串資源機制、語言切換、core 訊息代碼化、術語表 |
| [design/review-followups.md](design/review-followups.md) | 紀錄 | 2026-10-29 全專案 Review 的查證結果與各項的處理 |
| [design/p4-work-packages.md](design/p4-work-packages.md) | 紀錄 | P4 工作包拆分、介面、驗收條件與各工作包的完成紀錄（P4 已完成） |
| [design/document-credentials.md](design/document-credentials.md) | 紀錄 | 2026-10-11 文件憑證方案比較：衍生憑證、zkPDF、zkTLS、Bonds、OpenCerts 與樣本分析 |
| [design/architecture-and-roadmap.md](design/architecture-and-roadmap.md) | 紀錄 | 2026-10-10 P0 規劃：參考來源、目標架構、協定支援矩陣、信任與判定模型、分階段路線圖 |
| [review/project-review.md](review/project-review.md) | 規格 | 全專案審查指南：閱讀順序、熱點檔案、規則對應的程式位置、安全審查重點、回報格式 |

沒有獨立設計文件的領域（文件與簽章、OFD、電子公文、TWDIW 與 Bonds、近距離、信任分層、法律聲明）以 AGENTS.md 的對應章節為規格。

## 研究

全部是紀錄。

| 文件 | 內容 |
|---|---|
| [research/twdiw.md](research/twdiw.md) | TWDIW 官方 App 與平台的發證、出示、信任清單與互通細節 |
| [research/twdiw-1.0.14/](research/twdiw-1.0.14/README.md) | 官方 App 1.0.14 的應用簽章分析（8 份，資料夾內有結論與導覽） |
| [research/bonds.md](research/bonds.md) | Bonds 的離線出示、自發卡（vc+moica）、MyData 流程與已知問題 |
| [research/multipaz-eudi-ms.md](research/multipaz-eudi-ms.md) | Multipaz、EUDI 參考實作與 Microsoft Entra Verified ID |
| [research/documents-signatures.md](research/documents-signatures.md) | 簽章電子文件格式（PAdES、CAdES、XAdES、OFD、ASiC、時戳）與驗證 |
| [research/official-document-files.md](research/official-document-files.md) | 電子公文檔案結構、線上簽核點、檔案管理局健檢類別與錢包的對應 |
| [research/zkp-verifier.md](research/zkp-verifier.md) | ZKP 全景、驗證者身分與意圖揭露、信任分級 UI |
| [research/p4-benchmarks.md](research/p4-benchmarks.md) | P4 證明系統的效能量測 |
| [research/native-dependencies/](research/native-dependencies/README.md) | 原生依賴跨平台研究與 PoC（資料夾內有結論與導覽） |
| [research/validation-2026-10-10.md](research/validation-2026-10-10.md)、[research/validation-network-2026-10-10.md](research/validation-network-2026-10-10.md) | P0 本地驗證與需要外部網路的補驗 |
| [research/device-results-D1-2026-10-10.md](research/device-results-D1-2026-10-10.md) | D1 實機結果（金鑰證明、NFC 讀取自然人憑證） |

## 驗收

全部是紀錄，記的是該階段合併當時的測試結果。

| 文件 | 內容 |
|---|---|
| [acceptance/p1-acceptance.md](acceptance/p1-acceptance.md) | P1 標準核心 |
| [acceptance/p2-acceptance.md](acceptance/p2-acceptance.md) | P2 OpenID4VC 全組合與相容 Profile |
| [acceptance/p2-followup.md](acceptance/p2-followup.md) | P2 後續：狀態、風險與信任錨點 |
| [acceptance/p3-acceptance.md](acceptance/p3-acceptance.md) | P3 文件、簽章與衍生憑證 |
| [acceptance/p1-p3-followup-2026-10-16.md](acceptance/p1-p3-followup-2026-10-16.md) | P1 到 P3 補強：用戶端驗證、DC API 多重簽章、加密要求物件、mdoc transaction_data、VICAL 與 RICAL、CSC |
| [acceptance/twdiw-application-signature.md](acceptance/twdiw-application-signature.md) | TWDIW 新版應用簽章與舊版領卡相容、應用金鑰與建置驗證 |

P4 與其後的工作沒有獨立的驗收文件：結果記在各設計文件與 [STATUS.md](STATUS.md)。

## 新增或修改文件

- 狀態只寫在 STATUS.md。設計文件寫約定與理由，不寫「目前進度」；需要提到時連到 STATUS.md。
- 新文件加入本索引並標明性質。紀錄類文件在第一行之後註明撰寫日期。
- 文件內不放個資：實機記錄的卡號、UID、憑證效期、姓名與證號先遮蔽；含個資的真實文件不可提交。
- 已被取代的內容直接刪除或改寫，不保留「以下為原規劃」之類的舊段落；歷史在 git 裡。

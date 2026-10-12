# P3 驗收結果（2026-10-11）

分支 `claude/p3-documents-signing-8bjk64`。P3 加入文件分頁：保存與檢查簽章文件、時戳、以自然人憑證卡或其他憑證簽署、製作 PDF 與電子公文，以及把文件轉成衍生憑證（SD-JWT VC，可匯出 vc+moica）。零知識證明（zkTLS、zkPDF）屬於 P4，不在本階段。

## 本地自動測試

| 範圍 | 指令 | 結果 |
|---|---|---|
| 文件檢查：PAdES B-B、B-T、B-LT、B-LTA 等級判定，竄改偵測，國密 SM2 的 PDF 與分離式 CMS，CAdES-T、XAdES-T，OFD（GB/T 38540 SES v4）電子印章與竄改，RFC 3161 時戳 | `:test-servers:test --tests '*DocumentInspectorTest'` | 6/6 通過 |
| 簽署：PAdES（RSA 加 TSA、第二個 EC 簽章保留第一個、xref stream 的 PDF）、拒絕加密 PDF、CAdES 分離與封裝、ASiC-E、XAdES（RSA 與 EC，另以 JDK 的 XML 簽章驗證）、電子公文「函」XML 加 XAdES、錢包金鑰自簽憑證（只證明完整性，判定為部分） | `:test-servers:test --tests '*DocumentSigningTest'` | 7/7 通過 |
| 自然人憑證卡：第一代與第二代卡（SCP03 金鑰衍生與安全通道測試向量）簽章、PIN 錯誤時回報剩餘次數 | `:test-servers:test --tests '*GpkiCardTest'` | 4/4 通過 |
| 衍生憑證：SD-JWT VC 帶時戳與自然人憑證證據經 Bonds 離線出示並驗證（正式 MOICA 鏈判定證據失敗）、vc+moica 以 `k=s` 出示、證據的 `_sd` 與另一張憑證不符時失敗、非 RSA 卡片拒絕產生 vc+moica | `:test-servers:test --tests '*DerivedCredentialTest'` | 4/4 通過 |
| Bonds 身分證卡：Identity-H 字型加 ToUnicode（含 bfrange、TJ 字距、同一行兩個欄位）與 PdfComposer 的 UniCNS-UCS2-H 字型文字擷取；PDFBox 以 RC4 40、RC4 128、AES-128、AES-256 加密後以身分證統一編號開啟（小寫加空白也可），錯誤編號回報；Bonds 的解析案例；民國日期與臺北時間的 18 歲判定；NationalIDCredential 內容與 Bonds 相同，以 `k=s` 只揭露年齡並驗證；姓名與憑證不符時拒絕簽署 | `:test-servers:test --tests '*BondsNationalIdTest'` | 7/7 通過 |
| App 流程（身分證卡）：讀取身分證資料、姓名不符的卡片被拒、以 RSA 憑證代替卡片簽署、證件分頁與 Bonds `k=s` 出示（只揭露年齡）並驗證 | `:app:desktopTest --tests '*bondsNationalIdCard'` | 通過 |
| App 流程：匯入 PDF、相同檔案去重、錢包金鑰 PAdES 簽署、製作公文並 XAdES 簽署、產生衍生憑證、以 Bonds 擴充（`k=a`）出示並由另一個錢包驗證、`k=s` 沒有衍生憑證時的引導訊息 | `:app:desktopTest --tests '*documentVaultSignDeriveAndPresent'` | 通過 |
| 全部協議與互通 | `:test-servers:test` | 128 項：114 通過、14 項需 `DIW_INTEROP=1` 略過 |
| 全部 App 流程 | `:app:desktopTest` | 21 項：18 通過、2 項需網路略過、截圖測試需 `DIW_SCREENSHOTS` |
| 主要畫面離屏截圖（新增文件分頁、文件內容、簽署、衍生憑證、身分證卡） | `DIW_SCREENSHOTS=<資料夾> ./gradlew :app:desktopTest --tests '*uiScreenshots'` | 21 張 PNG |

## ETSI 報告比對（EU DSS 6.5）

雙向比對：DSS 產生的樣本由錢包檢查，錢包簽出的檔案由 DSS 驗證。

**DSS 產生、錢包檢查**（P0 時以 DSS 6.5 與本機測試 PKI 產生，DSS 自身判定見 P0 紀錄）：

| 樣本 | DSS 判定 | 錢包判定 |
|---|---|---|
| PAdES-BASELINE-B / T / LT / LTA（RSA） | TOTAL_PASSED，等級同檔名 | 完整性通過、等級相同（B-B、B-T、B-LT、B-LTA），LTA 的文件時戳通過 |
| 竄改的 LTA PDF（金額 100 改 900） | TOTAL_FAILED / HASH_FAILURE | 無效 |
| CAdES-BASELINE-T 封裝、XAdES-BASELINE-T | TOTAL_PASSED | 完整性與時戳通過 |
| OFD SES v4 電子印章與竄改版本（ofdrw 產生，DSS 不支援 OFD） | 不適用 | 通過；竄改版本失敗 |

**錢包簽出、DSS 驗證**（`DIW_SIGNED_OUT=<資料夾> ./gradlew :test-servers:test --tests '*DocumentSigningTest'`，再 `./gradlew -p tools/dss-check run --args=<資料夾>`；測試 PKI 沒有 CRL 或 OCSP，政策只把「缺撤銷資料」由 FAIL 改為 WARN，其餘為 DSS 預設政策）：

| 檔案 | DSS 判定的格式 | 結果 |
|---|---|---|
| PAdES（RSA，含時戳） | PAdES-BASELINE-T | TOTAL_PASSED，簽章與資料完整，時戳完整 |
| 同一份 PDF 再加 EC 簽章 | PAdES-BASELINE-T 與 PAdES-BASELINE-B | 兩個簽章都 TOTAL_PASSED |
| xref stream 的 PDF | PAdES-BASELINE-B | TOTAL_PASSED |
| CAdES 分離式 .p7s（含時戳）、封裝式 .p7m | CAdES-BASELINE-T、CAdES-BASELINE-B | TOTAL_PASSED |
| ASiC-E 容器 | CAdES-BASELINE-T | TOTAL_PASSED |
| XAdES enveloped（RSA 含時戳、EC） | XAdES-BASELINE-T、XAdES-BASELINE-B | TOTAL_PASSED |
| 電子公文「函」.di | 無法讀取 | DSS 拒絕含 DOCTYPE 的 XML（安全設定），公文格式本身需要 DTD 宣告；改由 JDK 與錢包驗證 |

比對中發現並已修正：錢包的 XAdES 原本缺少 `DataObjectFormat`，DSS 判定為 XAdES-T / XAdES-BES 而不是 baseline（EN 319 132-1 baseline B 要求 k）。補上後為 XAdES-BASELINE-B / T。

## 安全與個資

- 測試樣本只有本機測試 PKI 產生的檔案與 DSS、ofdrw 的公開範例；使用者提供的真實文件只在本機檢查，沒有提交進 repo。
- PIN 不保存；自然人憑證簽章完成後以卡片憑證的公鑰檢查簽章值，不符就不寫入檔案。
- 衍生憑證的查驗端重新驗證時戳與自然人憑證簽章；「文件簽章檢查」是發行錢包的陳述，畫面標示為未由查驗端重算。

## 已知限制

- 製作 PDF 時中文使用 PDF 閱讀器內建的 CJK 字型（MSung-Light），沒有嵌入字型；閱讀器沒有該字型時會以其他字型替代。
- 來源網站以表單 POST 觸發的下載，Android WebView 的下載事件只提供網址，錢包以 GET 重抓可能失敗；這時請在網站內改用「另存」或從系統分享到本 App。
- 桌面版沒有內嵌瀏覽器，來源網站以外部瀏覽器開啟，下載後再匯入。
- 行動自然人憑證簽章、CSC 遠端簽章、公文交換收發顯示為停用列並寫明原因。

## 需要實機驗證

| 項目 | 步驟 | 預期 |
|---|---|---|
| 自然人憑證卡 NFC 簽署 PAdES | 文件分頁匯入 PDF，選「簽署」，簽署方式選自然人憑證卡、輸入 PIN，依提示感應兩次 | 簽署完成後文件畫面新增簽章，簽署者為卡片姓名，憑證鏈到 MOICA G3（T2）；匯出的 PDF 以 DSS 或 Adobe 驗證為有效 |
| USB 讀卡機（OTG）與電腦 PC/SC | 同上，在讀卡機清單選 USB 或 PC/SC 讀卡機 | 卡片放在讀卡機上一次完成 |
| 真實文件衍生憑證 | 以真實文件（例如在學證明、入出國日期證明書）產生衍生憑證，勾選自然人憑證證據 | 另一台手機在「查驗」分頁產生挑戰，本機出示後顯示通過，證據列出時戳與自然人憑證簽章 |
| Bonds 身分證卡 | MyData 下載國民身分證資料（ZIP 先解出），開啟 PDF 選「製作 Bonds 身分證卡」，輸入身分證統一編號、確認欄位，以自然人憑證卡簽署；Bonds 查驗方產生 `k=s` 挑戰後出示，只勾選「簽發時年滿 18 歲」 | 欄位與 MyData 內容相同；Bonds 顯示自然人憑證驗證通過，只看到姓名與年齡欄位 |
| Bonds 自發卡 | Bonds 查驗方產生 `k=s` 挑戰，本 App 選有自然人憑證證據的衍生憑證出示 | Bonds 顯示自然人憑證驗證通過 |
| 來源網站取件 | 文件分頁「取得文件」開 MyData 或移民署，登入並下載 | 下載的檔案出現在文件分頁並記錄來源；行動自然人憑證登入時跳到官方 App 後可返回 |
| 分享匯入 | 從其他 App 分享 PDF 或 .p7s 到本 App | 檔案出現在文件分頁並顯示檢查結果 |
| 時戳服務 | 設定「文件與時戳」選不同 TSA，替文件加時戳 | 時戳通過，簽發者顯示該服務 |

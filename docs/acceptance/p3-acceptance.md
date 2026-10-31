# P3 驗收結果（2026-10-11）

分支 `claude/p3-documents-signing-8bjk64`。P3 加入文件分頁：保存與檢查簽章文件、時戳、以自然人憑證卡或其他憑證簽署、製作 PDF 與電子公文，以及把文件轉成衍生憑證（SD-JWT VC，可匯出 vc+moica）。零知識證明（zkTLS、zkPDF）屬於 P4，不在本階段。

> **現況（2026-10-16）：** 本文是 P3 驗收當時的紀錄，P3 已合併（PR #8、#9）。之後的變更：App 內製作 PDF 與電子公文已移除（2026-10-15，改由外部產生，PdfComposer 只留在測試）；行動自然人憑證 SP 改為編譯時設定、CSC 遠端簽章已實作；PR #9 加入 did:key `#0` 出示修正、依 DTD 的線上簽核點、設定分八組與關於頁、自訂信任頁、文件分頁重整，以及 Android release 以 `CleartextHttp` 取得 http 公布的時戳、OCSP、CRL 與 AIA。之後的 P1 到 P3 補強（用戶端驗證、DC API 多重簽章、mdoc 簽署清單、CSC 強化）見 [p1-p3-followup-2026-10-16.md](p1-p3-followup-2026-10-16.md)。現行規則見 AGENTS.md 的 P3 要點。
>
> **後續（2026-10-25）：** 保證層級 B-B 到 B-LTA 擴及 CAdES、XAdES 與 ASiC-E（CAdES 為 archive-time-stamp-v3，XAdES 為 `xadesv141:ArchiveTimeStamp`），PDF 可選認證簽章（DocMDP P=1 到 3），已簽署的 PDF 可「延長保存」（為全部簽章補上長期驗證資料與文件時戳）；簽完顯示實際達到的層級。EU DSS 比對結果加在下方「錢包簽出、DSS 驗證」的表格。公文交換收發與 zkPDF 仍是停用列，zkTLS 已在 P4 實作。

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
| App 流程（公文容器）：含 .si 的公文壓縮檔依簽核檔自動建立容器、只有未列出的檔案要確認、依兩個簽核點分層、取得容器撤銷資訊、移除時戳、匯出容器 ZIP 與說明、連同成員刪除 | `:app:desktopTest --tests '*officialZipIsBundledByItsApproval'` | 通過 |
| 全部協議與互通 | `:test-servers:test` | 228 項：214 通過、14 項需 `DIW_INTEROP=1` 略過（2026-10-16） |
| 全部 App 流程 | `:app:desktopTest` | 29 項：26 通過、2 項需網路略過、截圖測試需 `DIW_SCREENSHOTS`（2026-10-16） |
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

**錢包簽出、DSS 驗證**（`DIW_SIGNED_OUT=<資料夾> ./gradlew :test-servers:test --tests '*DocumentSigningTest' --tests '*LongTermSigningTest' --rerun`，再 `./gradlew -p tools/dss-check run --args=<資料夾>`，長期驗證的樣本在 `<資料夾>/lt`，另外執行一次；測試 PKI 沒有 CRL 或 OCSP，政策只把「缺撤銷資料」由 FAIL 改為 WARN，其餘為 DSS 預設政策）：

| 檔案 | DSS 判定的格式 | 結果 |
|---|---|---|
| PAdES（RSA，含時戳） | PAdES-BASELINE-T | TOTAL_PASSED，簽章與資料完整，時戳完整 |
| 同一份 PDF 再加 EC 簽章 | PAdES-BASELINE-T 與 PAdES-BASELINE-B | 兩個簽章都 TOTAL_PASSED |
| xref stream 的 PDF | PAdES-BASELINE-B | TOTAL_PASSED |
| CAdES 分離式 .p7s（含時戳）、封裝式 .p7m | CAdES-BASELINE-T、CAdES-BASELINE-B | TOTAL_PASSED |
| ASiC-E 容器 | CAdES-BASELINE-T | TOTAL_PASSED |
| XAdES enveloped（RSA 含時戳、EC） | XAdES-BASELINE-T、XAdES-BASELINE-B | TOTAL_PASSED |
| CAdES 分離式 B-LTA（2026-10-25） | CAdES-BASELINE-LTA | TOTAL_PASSED，簽章時戳與保存時戳完整 |
| ASiC-E B-LTA（2026-10-25） | CAdES-BASELINE-LTA | TOTAL_PASSED，簽章時戳與保存時戳完整 |
| XAdES enveloped B-LTA（2026-10-25） | XAdES-BASELINE-LTA | TOTAL_PASSED，簽章時戳與保存時戳完整 |
| PDF 認證簽章 P=2（2026-10-25） | PAdES-BASELINE-T | TOTAL_PASSED |
| PDF 認證簽章 P=1 加 B-LTA（2026-10-25） | PAdES-BASELINE-LTA | TOTAL_PASSED，DSS 與文件時戳不違反 P=1 |
| B-B 簽章延長保存兩次（2026-10-25） | PAdES-BASELINE-LTA | TOTAL_PASSED，兩個文件時戳完整 |
| 電子公文「函」.di | 無法讀取 | DSS 拒絕含 DOCTYPE 的 XML（安全設定），公文格式本身需要 DTD 宣告；改由 JDK 與錢包驗證 |

比對中發現並已修正：錢包的 XAdES 原本缺少 `DataObjectFormat`，DSS 判定為 XAdES-T / XAdES-BES 而不是 baseline（EN 319 132-1 baseline B 要求 k）。補上後為 XAdES-BASELINE-B / T。

## 安全與個資

- 測試樣本只有本機測試 PKI 產生的檔案與 DSS、ofdrw 的公開範例；使用者提供的真實文件只在本機檢查，沒有提交進 repo。
- PIN 不保存；自然人憑證簽章完成後以卡片憑證的公鑰檢查簽章值，不符就不寫入檔案。
- 衍生憑證的查驗端重新驗證時戳與自然人憑證簽章；「文件簽章檢查」是發行錢包的陳述，畫面標示為未由查驗端重算。

## 已知限制

- 製作 PDF 時中文使用 PDF 閱讀器內建的 CJK 字型（MSung-Light），沒有嵌入字型；閱讀器沒有該字型時會以其他字型替代。（2026-10-15 已移除 App 內製作 PDF，這項只影響測試產生的 PDF。）
- 來源網站以表單 POST 觸發的下載，Android WebView 的下載事件只提供網址，錢包以 GET 重抓可能失敗；這時請在網站內改用「另存」或從系統分享到本 App。
- 桌面版沒有內嵌瀏覽器，來源網站以外部瀏覽器開啟，下載後再匯入。
- 公文交換收發與 zkPDF 證明顯示為停用列並寫明原因（zkTLS 已在 P4 實作）。行動自然人憑證簽章需要編譯時設定 SP 帳號（或在開發者設定手動輸入），CSC 遠端簽章已實作（內建 EUDI 測試服務）。
- 簽署憑證鏈的中繼憑證或根憑證不在內建清單時，判定為「部分」，使用者可在設定匯入根憑證。國富安 GFA（含 e簽寶平台用的 OPERATION CA04）、BJCA Global Root CA3、e簽寶時戳機構與 e簽寶公布的其他合作 CA 已內建（2026-10-16），這類文件現在連到內建根憑證，判定為 T2。
- 卡片影像只在證件沒有影像時產生；發行端之後才補上標誌的證件不會自動更新影像。

## 需要實機驗證

| 項目 | 步驟 | 預期 |
|---|---|---|
| 自然人憑證卡 NFC 簽署 PAdES | 文件分頁匯入 PDF，選「簽署」，簽署方式選自然人憑證卡、輸入 PIN，依提示感應兩次 | 簽署完成後文件畫面新增簽章，簽署者為卡片姓名，憑證鏈到 MOICA G3（T2）；匯出的 PDF 以 DSS 或 Adobe 驗證為有效 |
| USB 讀卡機（OTG）與電腦 PC/SC | 同上，在讀卡機清單選 USB 或 PC/SC 讀卡機 | 卡片放在讀卡機上一次完成 |
| 真實文件衍生憑證 | 以真實文件（例如在學證明、入出國日期證明書）產生衍生憑證，勾選自然人憑證證據 | 另一台手機在「查驗」分頁產生挑戰，本機出示後顯示通過，證據列出時戳與自然人憑證簽章 |
| Bonds 身分證卡 | MyData 下載國民身分證資料（ZIP 先解出），開啟 PDF 選「製作 Bonds 身分證卡」，輸入身分證統一編號、確認欄位，以自然人憑證卡簽署；Bonds 查驗方產生 `k=s` 挑戰後出示，只勾選「簽發時年滿 18 歲」 | 欄位與 MyData 內容相同；Bonds 顯示自然人憑證驗證通過，只看到姓名與年齡欄位 |
| Bonds 自發卡 | Bonds 查驗方產生 `k=s` 挑戰，本 App 選有自然人憑證證據的衍生憑證出示 | Bonds 顯示自然人憑證驗證通過 |
| Bonds 自發卡線上出示 | 以 Bonds 查驗方的 OpenID4VP QR（vc+moica，身分證卡）掃描出示 | 同意畫面列出身分證卡與要求的欄位，查驗方收到並驗證通過 |
| MyData App 內下載 | 在 App 內開 MyData，登入後下載國民身分證資料或其他項目 | 不會跳回 MyData 首頁；ZIP 自動解出後刪除，檔名為項目名稱，來源寫「MyData・項目名稱」，取得方式為 App 內下載；身分證資料直接進入身分證卡畫面 |
| MyData 自動填入 | 設定「MyData 自動填入」存身分證統一編號與出生日期，在 App 內開 MyData | 驗證頁面自動填入兩個欄位並提示；下載的加密 PDF 不需再輸入密碼即可預覽 |
| OpenCerts | 匯入真實 OpenCerts 證書（.opencert） | 內容完整性通過；發行狀態與發行者身分顯示查驗結果與以太坊網路、DNS 網域；欄位以中文標籤顯示；「以發證機構樣式顯示」載入發證機構的樣式 |
| 身分證卡技術細節 | 開啟身分證卡，點「顯示技術細節」 | 列出查驗結果、自然人憑證內容、簽章與每個 disclosure |
| 加密 PDF 預覽 | 開啟 MyData 的 PDF，在預覽輸入身分證統一編號 | 顯示頁面與文字層；衍生憑證畫面列出 PDF 內的欄位 |
| 卡片影像 | 有證件後在網頁觸發 Digital Credentials API 請求 | 系統選擇器顯示各證件的卡片影像（衍生憑證為文件第一頁） |
| 來源網站取件 | 文件分頁「取得文件」開 MyData 或移民署，登入並下載 | 下載的檔案出現在文件分頁並記錄來源；行動自然人憑證登入時跳到官方 App 後可返回 |
| 分享匯入 | 從其他 App 分享 PDF 或 .p7s 到本 App | 檔案出現在文件分頁並顯示檢查結果 |
| 時戳服務 | 設定「文件與時戳」選不同 TSA，替文件加時戳 | 時戳通過，簽發者顯示該服務 |
| 保證層級（2026-10-25） | 以自然人憑證卡或 CSC 遠端簽章，分別簽 PDF（B-LTA）、一般檔案（CAdES B-LTA）、XML（XAdES B-LTA），連線到真實的 TSA、OCSP | 簽完訊息顯示達到 B-LTA；文件畫面的等級與保存時戳檢查通過；匯出後以 DSS 或 Adobe 驗證為 LTA |
| 認證簽章（2026-10-25） | 對沒有簽章的 PDF 選「認證簽章」P=1、P=2 各簽一次，再嘗試加簽 | P=1 之後加簽被判為違反；P=2 之後加簽通過；Adobe 顯示為認證文件 |
| 延長保存（2026-10-25） | 對外部簽署、只有 B-B 或 B-T 的 PDF 點「延長保存」 | 產生「原檔名-ltv.pdf」，等級變為 B-LTA；原檔保留 |
| 公文壓縮檔與容器 | 匯入機關公文系統匯出的壓縮檔（含 .di、.si、附件與頁面影像） | 依簽核檔建立容器，檔案列在各簽核點下，健檢顯示檔案齊全與簽核點簽章；「取得容器內簽章的撤銷資訊」後顯示 OCSP 或 CRL 份數 |
| 匯出 | 公文詳情「匯出公文容器」、有時戳的文件「匯出文件與證據」 | 系統儲存對話框出現中文檔名的 ZIP；解開後檔名正確，可用檔案管理局電子封裝檔工具箱或其他工具檢查原檔 |

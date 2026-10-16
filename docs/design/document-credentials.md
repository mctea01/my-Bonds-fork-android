# 文件憑證方案比較：zkPDF、zkTLS、Bonds 與 OpenCerts

> **設計基準與階段規劃，並非已完成功能清單。** 最新實作進度、PR #11 與 P1–P3 驗收範圍見 [現行功能矩陣（2026-10-16）](../status-2026-10-16.md)。個人錢包以公開規格支援行動自然人憑證、CSC 和公文檔案；正式機關收發文／服務商帳號屬外部授權，不是程式缺陷。

撰寫日期：2026-10-11
## 結論與待決事項

推薦「一張文件衍生憑證、三層證據」：每份文件都產生同一種憑證，再依文件條件疊加證據。你的優先順序（zkPDF，其次 zkTLS，最後自然人憑證加自簽 did:key）當成證明力的排序與畫面上的等級，不當成三選一。

- 憑證本體：IETF SD-JWT VC，由錢包層級金鑰簽發，欄位可選擇性揭露，`vct` 依文件種類；學歷欄位沿用 OpenCerts 的 transcript／certificate-of-award 結構。為與 Bonds 互通，另可匯出 vc+moica。
- 第一層（一定有）：自然人憑證對憑證雜湊簽章（Bonds 做法），加上原檔 SHA-256 與 RFC 3161 時戳。證明「誰主張、何時持有」。
- 第二層（有官方查驗頁時）：zkTLS，證明官方查驗頁回了「有效」與選定欄位。
- 第三層（PDF 內嵌機關簽章且已有該版型電路時）：zkPDF。
- 標準隔離：SD-JWT VC 驗證走既有標準路徑，證據驗證放在獨立模組；依現有信任分層，zkPDF（GPKI 簽章）為 T2、zkTLS（TLS 只確認網域）與自然人憑證聲明為 T3，不會出現 T1。

需要你決定的事（已於第二輪回覆，見下一節）：

1. 階段調整：新 P3 文件與簽章、新 P4 ZKP（含文件）、新 P5 驗證者透明。推薦：同意。
2. zkTLS 公證模式：先做「查驗方自己當 notary」的即時模式，或先架設本專案的 notary。推薦：即時模式，notary 先只在測試環境。
3. 衍生憑證格式：SD-JWT VC 並可匯出 vc+moica，或只用 vc+moica。推薦：前者。
4. 行動自然人憑證 SP 帳號：是否要向內政部申請。不申請則 SP 簽章維持停用列，實體卡不受影響。

另需樣本：教育部學位證書、臺北市畢業證書、移民署證明書、戶籍與地政謄本各一份（需要原始檔案，遮蔽會破壞簽章；不便提供時，可改用我提供的小工具在你的電腦上只讀出簽章資訊），用來確定各自的簽章格式與查驗欄位。

## 第二輪：樣本分析與決定

臺北市畢業證書的頁面是一張點陣圖，沒有文字層，zkPDF 只能證明「學校簽過這份檔案」，不能證明上面寫什麼。zkPDF 的第一個對象改為文字型的簽章 PDF，等其他樣本確認；zkTLS 的第一個對象改為移民署入出國查詢。第三輪樣本後已調整：zkPDF 先做中國大陸大學在學證明，再做大陸移民局證明，zkTLS 先做學信網與移民署證明書查驗頁。

| 項目 | 你的決定 |
| --- | --- |
| 衍生憑證格式 | SD-JWT VC，可匯出 vc+moica |
| zkTLS 實作 | TLSNotary 優先；條件允許時採 GovBind 做法（GovBind 建在 Proxy 模式 TLSNotary 上，eprint 頁未列公開程式碼，需自行實作） |
| zkTLS 離線 | 要離線支援，盡量不依賴伺服器；你有一台低配置主機可用 |
| MyData | ZIP 需解壓，不做 zkTLS，只有自然人憑證層 |
| 行動自然人憑證 | 個人無法申請 SP；嘗試 UAT 與 mobilemoica: |
| OpenCerts | 只匯入保存 |
| PKCS#7 | 新增 .p7s／.p7m 支援 |
| 戶籍 asdt | 嘗試解析 |

臺北市畢業證書樣本（2026-10-11 解析）：

- PDF 1.7、一頁、未加密；簽章 adbe.pkcs7.detached、RSA SHA-256，ByteRange 涵蓋全檔，pdfsig 判定有效。
- 簽署者是學校的組織及團體憑證（XCA 簽發，效期 2019-09-23 至 2025-09-23，現已過期）。CMS 內有 RFC 3161 簽章時戳與撤銷資訊封存，可證明簽署時憑證有效；原文驗證可達 T2。
- 頁面是一張 1241×1755、150 dpi 的圖片，沒有文字層。姓名、字號等欄位只能靠 OCR 或使用者輸入，屬持有人聲明。
- QR 是 `https://id.taipei/tpcd/taipeipass-app/scan?type=verify_fetch_callback&id=…&myDocQrcode=…&checkCode=…`，瀏覽器開啟會轉到台北通 App 下載頁，查驗只在 App 內。要 zkTLS 得重現 App 的 API 與台北通登入，暫不建議。

移民署入出國查詢（ncp.immigration.gov.tw/niaweb）：

- 需先用自然人憑證申請帳號，再以憑證登入。登入表單送出身分證號與 HiPKI 元件產生的 PKCS#7 簽章；簽的內容是固定字串「TBS」、nonce 為空。錢包可用 P3 的卡片簽章取代 HiPKI 元件。
- 這個簽章不綁當次連線，被截取就能重放登入，錢包不可保存或匯出它，也不可放進 zkTLS 公開的部分。
- 查詢區間由使用者自訂，結果頁 queryShow 是 HTML。頁面聲明「本查詢紀錄畫面未經許可不得擅自列印作為其他證明用途」，zkTLS 證明只是技術證據，不等於入出國日期證明書。

zkTLS 的離線選項（離線必然要先有人簽一份紀錄，查驗方信任的就是那個簽章者）：

| 模式 | 伺服器 | 離線 | 查驗方信任什麼 | 評估 |
| --- | --- | --- | --- | --- |
| 即時（查驗方當 notary） | 不需要 | 不行 | 不需信任第三方 | 線上首選 |
| 裝置證明的 TLS 紀錄 | 不需要 | 可以 | Android 硬體金鑰證明（含 App 套件與簽章憑證、verified boot）加上本 App 未被修改 | 離線首選；D1 已實測 root 機可偽造金鑰證明，只能是 T3，且這不是 zkTLS |
| 你自架的 notary（低配置主機） | 你的主機 | 可以 | 這台 notary；但它由持有人控制，對第三方等同自我聲明 | 適合自己保存與測試環境 |
| 獨立 notary | 第三方 | 可以 | 該營運者 | 等有可信營運者再做 |

裝置證明模式的設計【推論，提案】：App 在本機完成 TLS 連線，把回應萃取的欄位做成 SD-JWT VC，由一把附金鑰證明鏈的 Keystore 硬體金鑰簽章。選擇性揭露靠 SD-JWT 本身，不需要 ZK；線上時仍可加做即時 zkTLS 強化。

zkPDF 與加密 PDF【推論】：

- 可以處理。PDF 加密只加密字串與串流，簽章的 ByteRange 簽的是加密後的位元組，所以驗簽部分不變。
- 要證明內容，電路必須先解密含主張的那個串流（AES-128／256 CBC，舊檔為 RC4）再解壓。檔案金鑰作為私密輸入，並在電路內用 /Perms（AES-256 檔的一個區塊）確認金鑰屬於這份檔案，避開昂貴的密碼推導。
- 以憑證加密的 PDF（公鑰安全處理器）先在電路外用收件人私鑰取出檔案金鑰，其餘相同。
- 成本比未加密高一個等級（每 16 位元組一次 AES）。MyData 的加密 PDF 沒有簽章，本來就不適用 zkPDF。

行動自然人憑證：簽章的第一步是以 SP 身分取得 sp\_ticket，`mobilemoica://…/a2a/verifySign` 也要帶這個 ticket；UAT 同樣需要內政部發的測試 SP 帳號。沒有 SP 帳號就無法簽章；我不會使用從其他 App 取出的 SP 金鑰，那等於冒用別人的 SP 身分。可行的部分是在內嵌頁面登入政府網站時把 `mobilemoica:` 導向官方 App（由網站當 SP）。如果你手上的規格書附有公開的 UAT 測試帳號，可以再評估。

戶籍 asdt：已有樣本，結果見第三輪。

大陸文件：

| 文件 | 查驗方式 | 初步判斷 |
| --- | --- | --- |
| 學信網學籍在線驗證報告 | 以 16 碼在線驗證碼查詢，不需登入，也沒有圖形驗證碼（2026-10-11 實測） | 很適合 zkTLS；www.chsi.com.cn 支援 TLS 1.2 AES128-GCM（2026-10-11 實測） |
| 國家移民管理局出入境記錄、通行證與居住證關聯證明 | PDF 內嵌國家移民管理局簽章（RSA SHA-256），沒有 QR 或查驗頁網址 | 文字型簽章 PDF，是 zkPDF 的第一個對象（見第三輪） |
| 中國大陸大學在學證明 | PDF 內嵌學校簽章與時戳；QR 查驗 API 只有 HTTP | zkPDF 的第一個對象（見第三輪） |

樣本已齊，中國大陸大學在學證明見第三輪。

## 第三輪：新樣本與查驗頁

大陸移民局的兩份證明是第一批可做 zkPDF 文字證明的樣本。台灣移民署證明書沒有數位簽章，但查驗頁不需自然人憑證，zkTLS 改以查驗頁為對象。學信網查驗不需登入也沒有圖形驗證碼，是最容易的 zkTLS 對象。asdt 是加密給戶政司的權杖，本機無法驗證。（2026-10-11 解析，只記錄結構，不含個人資料。）

| 文件 | 檔案結構 | 原文驗證 | zkPDF | zkTLS |
| --- | --- | --- | --- | --- |
| 台灣移民署入出國日期證明書 | PDF 1.4（JasperReports、iText 2.1.7），一頁，未加密，有文字層；QR 只是查驗頁網址 | 沒有數位簽章 | 不適用 | 查驗頁 entryexitQueryResult.action：身分證號或護照號、證明書序號、圖形驗證碼，不需登入；只提供 TLS 1.2（ECDHE-RSA-AES128-GCM）；自發證日起 3 個月內可查驗 |
| 大陸通行證與居住證關聯證明 | PDF 1.4（iText 5、ESS-PDF），一頁，RC4 128 位元加密但使用者密碼為空，有文字層 | adbe.pkcs7.detached、RSA SHA-256；簽署者為國家移民管理局 Electronic Document Signer（效期至 2027-01-03），鏈到 BJCA DocSign CA3 與 BJCA Global Root CA3；只有 signingTime，沒有 RFC 3161 時戳；自查詢日起 30 天有效 | 適合 | 沒有查驗頁；s.nia.gov.cn 從雲端連線被重置 |
| 大陸出入境記錄查詢結果 | 同上，兩頁 | 同上 | 適合 | 同上 |
| 中國大陸大學的學籍（在學）證明 | PDF 1.7（Word 2016 轉出，e簽寶簽章），一頁，未加密，有文字層；有證明編號、驗證密鑰與查驗 QR | adbe.pkcs7.detached、RSA SHA-256；簽署者為該大學的機構憑證（國富安 GFA 信任網路 OPERATION CA04 簽發，效期 2026-03-07 至 2027-03-07），CMS 只附簽署者憑證；有 e簽寶 RFC 3161 時戳；signingTime 寫成 2010 年，不可採信 | 最適合：未加密、文字型、有時戳 | QR 查驗 API（/api/client/security/check/by/qrcode?n=編號\_密鑰）不需圖形驗證碼，回 JSON（結果、文件名稱、列印日期、姓名、學號、頁面圖）；但只有 HTTP，https 從雲端連線被重置，沒有 TLS 就不能做 zkTLS |
| 學信網學籍在線驗證報告 | 只用在線驗證碼 | 不適用 | 不適用 | bg.do?vcode=…&srcid=bgcx 回傳 HTML，含全部欄位與照片；有效期由權屬人設定 1 至 6 個月，可延長 |
| 電子戶籍謄本 asdt | base64 文字 544 位元組，解碼後是 406 位元組的 PKCS#7 EnvelopedData | 收件者為 www.ris.gov.tw 的憑證（RSA-1024），內容以 3DES-CBC 加密，只有 48 位元組；沒有簽章，只有戶政司能解密 | 不適用 | 上傳到戶政司查驗頁後可做 zkTLS，需要查驗頁流程再確認 |

- zkPDF：大陸兩份證明的加密只限制複製與修改。檔案金鑰由空的使用者密碼經 MD5 推導，任何人都算得出來，不需要私密輸入。電路在 SP1 內解密並解壓頁面串流，再比對欄位，主要成本是 RSA-2048 驗簽與串流解密。
- 信任錨：BJCA Global Root CA3 不在內建公開根憑證，它不在 Mozilla 與 Microsoft 的計畫內，BJCA 下載頁也沒有列出。文件註明可從 s.nia.gov.cn 下載頒發者憑證。推薦 P3 先讓使用者匯入（T3）；若要內建，需把工具的「官網釘選」規則從 SM2 根憑證擴大到這張 RSA 根憑證。
- 台灣移民署：你提到實體卡依賴 HiCOS，無法轉成 PKCS#11。查驗頁只需證號、序號與圖形驗證碼，不需要自然人憑證，所以 zkTLS 的對象改為證明書查驗頁，需要憑證登入的 queryShow 退為備選。圖形驗證碼在錢包內嵌頁面由使用者輸入，取得 session cookie 後再開 notarized 連線，身分證號與 cookie 在公開部分遮蔽。結果頁的格式還沒確認，我沒有替你送出身分證號查詢。
- 學信網：適合當 TLSNotary 的第一個實作測試。回應含照片，公開部分只揭露需要的欄位。
- asdt：錢包只保存原檔、雜湊與時戳；要證明內容，必須先在戶政司查驗頁查驗，再對那次連線做 zkTLS。
- 中國大陸大學：改為 zkPDF 的第一個對象，因為它未加密、有文字層，又有時戳，比大陸移民局證明少一步 RC4 解密。國富安 GFA 的根憑證不在內建清單，CMS 也沒附中繼憑證，信任錨同樣先由使用者匯入（T3）。（2026-10-16 更新：GFA 根憑證與 OPERATION CA04 已由 e簽寶公布的合作 CA 憑證包內建，這份證明判定為 T2。）QR 查驗 API 只有 HTTP，只能當輔助比對，不能當證據。

## Bonds 實際做法

Bonds 並沒有「從文件產生機關背書的憑證」：它的自發卡是持卡人把 MyData 下載的內容自己填成憑證，再用行動自然人憑證對憑證雜湊簽章，證明力是「這位自然人憑證持有人主張這些值」。以下依既有研究（research/bonds.md 第 3、4、6、7 節）整理。

| 環節 | Bonds 做法 | 實際證明了什麼 | 限制 |
| --- | --- | --- | --- |
| 取得文件 | WebView 登入 mydata.nat.gov.tw 攔截下載，支援 8 種文件；學歷不屬 MyData，未支援 | 檔案來自使用者自己的 MyData 工作階段 | 非官方介接，改版或條款可能中斷；Bonds 2026-08-09 實測 MyData 下載檔本身沒有簽章 |
| 產生憑證 | vc+moica：JSON 信封，payload 為憑證正規化位元組，TBS 為 `bonds-tw-credential-v1:<SHA-256 hex>`，以行動自然人憑證 SIGN（RSASSA-PKCS1-v1\_5 SHA-256）；另有每卡 did:key 簽的 issuerJWS 與 SD 揭露 | 簽章者是持有該張自然人憑證的人，且憑證 CN 等於憑證內姓名 | 不是內政部或原機關背書；欄位值由持卡人自填，可偽造內容 |
| 查驗 | 內建 MOICA G3 與 GRCA G3，驗憑證鏈、RSA 簽章、CN 與姓名一致、揭露有被承諾 | 身分綁定與完整性 | vc+moica 是 Bonds 自家擴充格式，只有 Bonds 與 verifier-lite 認得 |
| 行動自然人憑證 | 需要 SP 帳號（sp\_service\_id 與 AES 金鑰）與後端 broker；金鑰不可放進 App | 由內政部 FidO 伺服器代為簽章 | Bonds 的 broker 尚未啟用（secrets 為空）；每次簽章都把明文身分證號交給內政部 |
| 實體卡 | 只在 DEBUG：iPhone 產生請求，Mac 以 PC/SC 讀卡機與 open-gpki-pkcs11（LGPL-2.1+）簽章 | 同上，但不經內政部伺服器 | 原型，需要電腦與讀卡機 |
| 查驗語意 | vct 草案標 `assurance: holder-derived`，附 `source.sha256` 與解析器版本 | 查驗方知道這是持有人衍生 | 需查驗方自訂政策承認 |
| ZK | zkID 的 RSA 憑證鏈與使用者簽章電路，約 1 GB 資產、峰值約 2 GiB | 持有有效自然人憑證，不揭露身分 | FidO 簽固定 app\_id，簽章材料可重放（Bonds 自列七條限制） |

對本專案的意義：Bonds 方法適用所有文件、實作成本最低，但證明的是「誰主張」而不是「內容為真」。它最適合當最後一層兜底，並作為其他兩層的身分綁定元件（把憑證綁到自然人憑證持有人）。

## zkPDF

zkPDF 證明「這份由某把金鑰簽章的 PDF 在第 n 頁含有某段文字」而不交出整份文件，是三種方法中唯一不需要信任第三方的一種。但 PSE 的參考實作已於 2026-08-19 封存，而且靠 SP1 證明網路在伺服器端產生證明，手機本機做不到，本專案必須自建「依文件版型定製」的電路。

| 項目 | 內容 |
| --- | --- |
| 原理 | 先驗 PDF 內嵌的 PKCS#7 簽章（ByteRange 的 SHA-256），再解析該頁內容串流（含 DEFLATE），證明指定頁碼、位移的字串存在；公開輸出是簽章者公鑰與要證明的字串 |
| 實作 | [privacy-ethereum/zkpdf](https://github.com/privacy-ethereum/zkpdf)：Rust、SP1 zkVM、可轉 Groth16、WASM 解析；MIT；只列 RSA-SHA256（部落格測試另有 RSA-SHA1）；2026-08-19 封存 |
| 效能（官方部落格） | 268 KiB PDF：4405 萬 cycles、Groth16 52 秒；104 KiB 印度 DigiLocker PAN 卡：2994 萬 cycles、31 秒；皆在 SP1 證明網路上跑 |
| 手機可行性 | 部落格自述「在瀏覽器與手機上對多 MB PDF 做用戶端證明目前不可行」；交給證明網路則網路看得到整份 PDF，與隱私目的衝突 |
| 可行的改法 | GovBind（eprint 2026/2206）的做法：只承諾私密區段、公開其餘位元組，只在電路內解壓含主張的那一個串流，以「文件版型」定製電路。簽章底層可沿用 P4 已規劃的 zkID（Bonds 用的 RSA 電路）。【推論】 |
| 信任錫 | 電路只證明「某公鑰簽的」，查驗方還要知道該公鑰屬於哪個機關：需在電路外附上 GCA／XCA 憑證鏈到 GRCA（會揭露是哪個機關簽的），或在電路內驗鏈到 GRCA（Bonds 的 RSA-4096 憑證鏈證明金鑰 693 MB，成本很高） |
| 適用的台灣文件 | 只適用「PDF 本身內嵌簽章」的文件：臺北市電子畢業證書（學校機關憑證簽章）、推論教育部數位學位證書（驗證 API 回傳 AATL 欄位）。戶籍與地政謄本的效力在 asdt／.p00 密文檔，明文 PDF 不具效力；MyData 下載檔無簽章，都不適用 |

結論：zkPDF 的證明力最高，但不是拿來就能用的元件。每種文件要先取樣確認簽章格式與版型，再為它寫一個電路；在沒有電路前，同一份文件仍可用一般的 PAdES 驗證求得「原文可驗」的證據（交出整份文件）。

## zkTLS（有查驗連結或查驗碼時）

zkTLS 證明「某個 HTTPS 主機在一次真實的連線中回了這些內容」，可只揭露部分欄位。它最適合有官方查驗網頁的文件（教育部學位、戶籍、地政），也能為沒有簽章的 MyData 下載補上來源證明；代價是查驗方必須信任公證方（notary／attestor）不與持有人勾結。

| 方案 | 狀態與授權 | 適合本專案的地方 | 風險 |
| --- | --- | --- | --- |
| [TLSNotary](https://github.com/tlsnotary/tlsn) | Rust，Apache-2.0 或 MIT；README 寫明「不應用於正式環境」；[路線圖](https://pse.dev/mastermap/tlsnotary)：1.0 排在 2026 下半年、Proxy 模式收尾中、TLS 1.3 暫停、行動 SDK 進行中 | 授權與本 repo（Apache-2.0）相容，可以 uniffi 打包進 Android；查驗方可以自己當 notary | 只支援 TLS 1.2；MPC 模式頻寬大，大回應慢 |
| [Reclaim](https://eprint.iacr.org/2026/2187) | attestor-core 為 AGPL-3.0，可自架 attestor；論文報告中低階手機 7.28 秒證明 1200 kB 回應 | 大回應（MyData ZIP）效能最好 | AGPL 只能當獨立服務使用；Android 官方流程需另裝 Reclaim App |
| [GovBind](https://eprint.iacr.org/2026/2206)（論文） | Proxy 模式 TLSNotary 加上對內容的 ZK 述詞；土耳其 e-Devlet 文件 24 個 session、72 個證明，產生 54–119 秒、驗證 44–127 ms、證明 11–12 KiB | 正是「有查驗服務的政府 PDF」情境，可當本專案的設計藍本 | 只有論文原型 |

連線相容性：2026-10-11 以 openssl 測試，dcert.moe.gov.tw、www.ris.gov.tw、ep.land.nat.gov.tw、coa.immigration.gov.tw、mydoc.gov.taipei 都接受 TLS 1.2 的 ECDHE-RSA-AES128-GCM-SHA256，TLSNotary 可用。

公證方的三種信任模型（這是要你決定的設計點）：

1. 即時互動：出示當下由查驗方自己當 notary，與持有人一起跑 MPC-TLS 查驗官方網頁。不需信任任何第三方，但只能線上、只在查驗有效期內。
2. 預先公證：由本專案架設的 notary 簽出 attestation，存入證件後可離線出示；查驗方要信任這個 notary，依現有規則屬 T3。
3. 多公證方門檻：多個獨立 notary 各簽一份，降低勾結風險，成本與營運負擔最高。

其他限制：官方查驗頁多有圖形驗證碼，需要在錢包內嵌的頁面由使用者輸入；每個網站都要一個解析設定，改版就失效；戶籍、地政、移民署的查驗都只有 3 個月；zkTLS attestation 在台灣沒有法定效力，只是技術證據。

## OpenCerts（open-certificate 與 certificate-cli）

OpenCerts 是「學校簽發、持有人保存、任何人驗證」的發行端格式，不是持有人自行衍生憑證的方法。建議用它的學歷 schema 當衍生憑證的欄位模型，並讓錢包能匯入與驗證 OpenCerts 文件；不建議用它來封裝自行產生的憑證。

| 項目 | 內容 |
| --- | --- |
| [open-certificate](https://github.com/OpenCerts/open-certificate) | Apache-2.0，Node.js 22 以上，不在 npm。提供 OpenAttestation 格式的 transcript 1.0–2.2、testimonial 1.0、certificate-of-award 1.0，以及 W3C VC 2.0 格式的 transcript 3.0、testimonial 2.0、certificate-of-award 2.0；W3C 版本以 did:web 與 ecdsa-sd-2023 簽章，由 [TrustVC](https://github.com/TrustVC/trustvc) 實作，未宣告的欄位會被拒絕，自由內容放 `additionalData` |
| [certificate-cli](https://github.com/OpenCerts/certificate-cli) | Apache-2.0，2021-02-03 已封存。指令 batch（整批簽發、輸出 Merkle root）、verify、verify-all、filter（隱藏欄位仍可驗證）。官方指向 open-attestation-cli、oa-verify、OpenCerts/verify 取代 |
| OpenAttestation v2 機制【依記憶，未開頁核對】 | 每個欄位加鹽後雜湊（keccak256）組成 targetHash，整批文件再組 Merkle root；發行以乙太坊 documentStore 合約或 DID 簽章；發行者身分靠 DNS-TXT 記錄；隱藏欄位是把欄位換成它的雜湊 |
| 對本專案的適合度 | 身分靠發行者的網域（DNS-TXT 或 did:web），個人錢包自己簽的 OpenCerts 沒有信任來源；隱藏欄位的功能與 SD-JWT VC 重疊，而 SD-JWT VC 已是 P1 的標準路徑 |

建議用法：

- 匯入與驗證：支援 `.opencert`（OA v2）與 W3C VC 2.0 版本，放在標準 W3C 路徑旁的獨立模組；DNS-TXT 或 did:web 驗證成功為 T3。ecdsa-sd-2023 選擇性揭露是新的 Data Integrity cryptosuite，需要另行實作。
- 欄位模型：文件衍生的學歷憑證（畢業證書、學位證書）沿用 transcript／certificate-of-award 的欄位名稱與結構，放在 SD-JWT VC 內。
- 主動簽發：組織使用者有自己的網域時，可以用本錢包簽發 did:web 的 W3C VC 2.0 證書（見「主動簽署」）。

## 方案比較

你的優先順序（zkPDF，其次有查驗方法時的 zkTLS，最後自然人憑證加自簽 did:key）就證明力而言是對的；但三者不是互斥選項，而是同一張衍生憑證可以疊加的證據。下表「原文簽章驗證」是不加零知識的基準。

| 方法 | 證明什麼 | 查驗方需信任 | 揭露給查驗方 | 適用文件 | 手機本機 | 離線出示 | 實作成本 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| zkPDF | 機關簽章的 PDF 含有這些內容 | 只有簽章金鑰（GPKI） | 只有主張的欄位與簽章機關 | 內嵌簽章的 PDF：臺北市畢業證書、推論教育部學位證書 | 需依版型定製電路，尚未驗證 | 可以 | 最高：每種版型一個電路 |
| zkTLS（即時） | 官方查驗頁剛剛回了「有效」與這些欄位 | 無第三方（查驗方自己是 notary） | 只有選定欄位 | 有查驗頁：教育部學位、戶籍、地政、移民署（待確認） | TLSNotary 行動 SDK 進行中 | 不行 | 高：每個網站一個解析設定 |
| zkTLS（預先公證） | 同上，加上公證時間 | 本專案的 notary（T3） | 只有選定欄位 | 同上，以及無簽章的 MyData 下載 | 同上 | 可以 | 高，另需營運 notary |
| 原文簽章驗證（PAdES 等） | 機關簽章的整份文件 | 只有簽章金鑰 | 整份文件 | 所有內嵌簽章的文件 | 可以 | 可以 | 中：原 P5 已規劃 |
| 自然人憑證加自簽 did:key（Bonds） | 身分為某人的持卡人主張這些值 | 內政部 MOICA 與持卡人誠信 | 選定欄位與簽章者姓名 | 所有文件 | 可以（卡片 NFC 或行動自然人憑證） | 可以 | 低：P2 已有 vc+moica 驗證 |
| OpenCerts | 發行網域簽發了這份證書 | 發行者網域 | 未隱藏的欄位 | 發行端自己採用時 | 可以 | 可以 | 中 |

結論：用「一張衍生憑證、多層證據」取代「三選一」。每份文件一定有 Bonds 層（身分綁定），有查驗頁就加 zkTLS，有內嵌簽章且已有對應電路就加 zkPDF；畫面與查驗結果標出實際有哪一層。

## 主動簽署

主動簽署可以用同一個「簽章金鑰介面」接五種金鑰來源，輸出 PDF、通用簽章檔與可驗證憑證；唯一做不到的是「發送」電子公文，因為個人沒有公開的 G2C 交換管道。

| 金鑰來源 | 演算法 | 法律與信任 | 可行性 |
| --- | --- | --- | --- |
| 自然人憑證卡（NFC、USB 讀卡機、桌面 PC/SC） | RSA-2048，PKCS#1 v1.5 SHA-256（卡上「cert1」） | 憑證鏈 MOICA 到 GRCA，依現有規則為 T2 | D1 已用 NFC 讀出憑證；簽章需實作 PIN 驗證（見下節） |
| 行動自然人憑證 | 同上，由內政部伺服器簽 | 同上 | 需要 SP 帳號與後端（見下節） |
| 工商憑證卡 | RSA，PKCS#1 v1.5 | MOEACA 到 GRCA，T2 | open-gpki-pkcs11 已支援一代工商憑證；桌面優先 |
| 錢包軟體或硬體金鑰（Keystore、StrongBox、匯入 PKCS#12） | EC P-256 或匯入的 RSA | 自簽或使用者匯入 CA，T3 | P1 已有金鑰管理 |
| 遠端簽章（CSC API v2） | 依信託服務 | 歐盟合格簽章可達 QES | eudi-lib-android-rqes-core（Apache-2.0，只有 Android），原 P5 已規劃 |

可產生的成果：

- 簽章檔：PAdES（B-B、B-T、B-LT）、CAdES detached（.p7s）、XAdES、JAdES，打包為 ASiC-E；時戳以 RFC 3161 TSA（validation/docs/sigval 已實測）。Android 以 BC 產 CMS、PdfBox-Android 做增量儲存；DSS 的 PAdES 模組引用 java.awt，只用在桌面。
- 自製文件與證書：範本產生 PDF/A-3，把同內容的 VC（JSON）以 `/AF` 嵌入，再做 PAdES。中文需嵌入字型子集，注意 APK 大小。
- 發行可驗證憑證：錢包當發行端簽 SD-JWT VC 或 W3C VC。自然人憑證是 RSA，可用 JOSE RS256 加 x5c；mdoc 只允許 EC，只能用錢包 EC 金鑰。組織有網域時可用 did:web 發 W3C VC 2.0（OpenCerts 格式）。
- 電子公文：可產生 .di XML 加 XMLDSig 供保存，但《機關公文電子交換作業辦法》第 13 條讓私人收件人由機關另訂，目前沒有自然人取得交換地址的公開流程；「送出」應顯示為停用列並寫明原因。機關公文需 GCA 機關憑證，個人金鑰簽的只是個人文書。

## 自然人憑證卡與行動自然人憑證

實體卡可以馬上開始，不需要向任何機關申請；行動自然人憑證必須先取得內政部 SP 帳號並架設後端，這一項需要你提出申請。

實體卡：

- 介面：106 年 8 月後發行、卡號 TP07 開頭的是雙介面卡，支援 NFC（[內政部公告](https://moica.nat.gov.tw/news_in_1857a906a7e000004073.html)）；舊卡只能用讀卡機。App 已有 Android 的 NFC 與 USB CCID、桌面 PC/SC 傳輸層（P2 做 mdoc 讀卡用），可以共用。
- 指令流程：D1 實測二代卡以 GPPKI AID `A0000002830000062201696400010101` 選取，不需 PIN 即可讀出 GRCA、MOICA 與使用者簽章、加密憑證。依 [open-gpki-pkcs11](https://github.com/chouhsiang/open-gpki-pkcs11) README，二代卡登入走 GPPKI applet 加 SCP03，一代卡以 3DES 保護 PIN，兩代都支援 SHA256-RSA-PKCS 簽章。
- 授權：open-gpki-pkcs11 為 LGPL-2.1-or-later。建議只參考指令流程以 Kotlin 獨立實作（與 D1 做法相同），不複製程式碼。
- 安全：PIN 錯誤會扣重試次數，送 VERIFY 前先讀剩餘次數，錯一次就停（Bonds 同樣做法）；PIN 不落地、不寫紀錄。
- 用途：PAdES 等文件簽章、衍生憑證的身分綁定（Bonds vc+moica 相容簽法）、發行 RS256 憑證。

行動自然人憑證（TW FidO SP API v2.9，細節見 research/bonds.md 第 3 節）：

- 第三方 App 要以 SP 身分呼叫 `fidoapi.moi.gov.tw`，需要 sp\_service\_id 與 AES 金鑰；金鑰放進 App 就能被取出冒用，所以一定要後端 broker。
- 每次簽章都把明文身分證號送到內政部；只提供 PKCS#1 簽章，是否接受 PAdES 需要的 SignedAttributes（約數百位元組）尚未實測。
- App 切換用 `mobilemoica://` 是 iOS 實測結果，Android 尚未確認；官方 App 需 Android 12 以上。
- 2024-12-02 起可以不先持有 IC 卡，直接在戶政事務所申辦行動自然人憑證（商周報導），所以有些使用者只有行動版。
- 另一個用途不需 SP 帳號：在錢包內嵌頁面登入 MyData、戶政等政府網站時，把 `mobilemoica:` 導向官方 App（Bonds 的 MyData 作法）。這是取得文件與 zkTLS 公證的前提。

建議：先做實體卡 NFC／USB／PC/SC 簽章與行動版登入導向；行動版的 SP 簽章先做成停用列，寫明「需要 SP 帳號與後端」。

## 文件來源

六個來源裡，教育部學位證書最適合當第一個實作對象：官方查驗回應是小而結構化的 JSON，還含「是否為最新版」，zkTLS 做起來最乾淨。臺北市畢業證書經樣本確認頁面是圖片，不適合當 zkPDF 對象（見「第二輪」）。

| 來源 | 取得方式 | 檔案與簽章 | 官方查驗 | 最適合的證據 |
| --- | --- | --- | --- | --- |
| 教育部大專校院數位學位證書 | 學校寄到信箱或校務系統下載（[清華說明](https://registra.site.nthu.edu.tw/var/file/211/1211/img/175251807.pdf)） | PDF；另存新檔會驗證失敗，推論是整檔雜湊；驗證回應有 AATL 欄位，推論內嵌 AATL 憑證簽章 | [dcert.moe.gov.tw](https://dcert.moe.gov.tw/) 上傳 PDF（上限 2 MB、需驗證碼），回應 success／expired（有新版）／failure 與姓名、學號、學校、學院、系所、版本號 | zkTLS；若取樣確認有內嵌簽章再加 zkPDF。加入數位證明管理中心的學校可直接領 TWDIW 卡，走 P2 既有流程 |
| 臺北市 MyDoc 電子畢業證書（市立國高中職） | [mydoc.gov.taipei](https://mydoc.gov.taipei/MYDOC/) 以台北通金質會員登入，個人證件包下載 | PDF；[實施計畫](https://www.taivs.tp.edu.tw/static/webroot/G157187608106738/application/NN178036298481896.pdf)寫由各校 GCA 簽章，FAQ 寫 XCA | 只能用台北通 App 掃 QR 驗證 | 原文 PAdES 驗證（學校 XCA 憑證、含時戳，T2）；頁面是圖片，zkPDF 只能證明簽章、不能證明文字；查驗只在台北通 App 內 |
| 移民署入出國日期證明書 | 移民署網站以自然人憑證線上申辦，免費；也在 MyData（API.LPvQONMWj6） | 線上版不含入出境記錄附件 | [我的E政府](https://www.gov.tw/News_Content_2_371276)：線上證明書驗證有效 3 個月；查驗頁網址與輸入未公開說明 | zkTLS：以自然人憑證登入 ncp.immigration.gov.tw，自訂區間查詢後證明結果頁（見「第二輪」） |
| 內政部戶政司電子戶籍謄本 | [ris.gov.tw](https://www.ris.gov.tw/) 自然人憑證申辦，當日完成 | asdt 簽章檔（只能在該站驗證）與明文 | [上傳 asdt 或輸入 42 碼檢查號](https://www.gov.tw/News_Content_2_371532)；成功後下載需自然人憑證 | zkTLS（檢查號）；asdt 格式未公開，zkPDF 不適用 |
| 內政部地政司地政電子謄本 | [全國地政電子謄本系統](https://ep.land.nat.gov.tw/EpaperDoc/MainNew)申請 | .p00 密文檔（各縣市說明寫 GCA 簽章）；列印的明文不具文書證明效力 | 輸入檢查資料或上傳 .p00，需驗證碼，申領後 3 個月內 | zkTLS（限 3 個月內）；之後只剩原檔與 Bonds 層 |
| MyData（財產、戶籍、勞健保等 8 項及入出國日期） | 錢包內嵌頁面登入 mydata.nat.gov.tw 下載（Bonds 作法） | 未加密 ZIP 內含以身分證號為密碼的 PDF；Bonds 實測無簽章 | 無 | 只有 Bonds 層（你決定 ZIP 需解壓，不做 zkTLS） |

都需要你提供樣本才能定案的事項：各文件 PDF 的簽章演算法與 SubFilter、教育部證書是否內嵌簽章、移民署查驗頁的網址與欄位。雲端連不到數位證明管理中心（dcmc.csie.ncku.edu.tw），其發卡流程未核對。

## 階段順序調整建議

建議把 P5 移到 P3、P4 之前，但拆成兩段：新 P3 做文件、簽章與衍生憑證，新 P4 把文件的 zkTLS、zkPDF 與原 P4 的 ZKP 合併，原 P3 驗證者透明往後移為 P5。理由是你提的依賴關係：ZK 電路要有文件與衍生憑證才有對象，而驗證者的信任分級在 P2 已有 T1–T4 可先用。

| 新階段 | 內容 | 驗收條件 | 來源 |
| --- | --- | --- | --- |
| P3 文件、簽章與衍生憑證 | PAdES／CAdES／XAdES／OFD+SES 驗證與信任包、保存與時戳；自然人憑證卡 NFC／USB／PC/SC 簽章；主動簽署（PAdES、ASiC-E、自製證書）；文件衍生憑證格式與 Bonds 層（vc+moica 相容）；教育部、MyDoc、MyData、戶政、地政、移民署取件入口；OpenCerts 匯入；查驗分頁能驗衍生憑證 | 以測試樣本通過 ETSI 驗證報告比對；實機用 TP07 卡 NFC 簽出可被 DSS 驗證的 PAdES；一份真實文件產生衍生憑證並被另一台手機查驗 | 原 P5 加新增 |
| P4 ZKP（文件與憑證） | 共用原生 ZK 執行環境與裝置分級；zkTLS（TLSNotary，先做即時模式，第一個對象移民署入出國查詢，離線用裝置證明紀錄）；zkPDF 版型電路（第一個對象待文字型簽章 PDF 樣本）；Longfellow、OpenAC 年齡證明 | 中階機完成一次文件 zkTLS 出示與一次 ZK 憑證出示；zkPDF 若手機做不到則以桌面產生並在畫面標明 | 原 P4 加新增 |
| P5 驗證者透明與主動驗證 | 驗證者聲明、WRPRC、驗證者模式；加上衍生憑證與 ZK 的查驗政策 | 兩台手機互為持有者與驗證者，顯示身分、代表關係與目的 | 原 P3 |
| P6 iOS | 不變 | P1 至 P5 在 iOS 實機通過 | 原 P6 |

留在停用列、等外部條件的項目：行動自然人憑證 SP 簽章（等 SP 帳號）、CSC 遠端簽章（等信託服務帳號）、電子公文收發（等主管機關開放管道）。

風險：新 P3 範圍比原 P5 大，若要控制時程可把 OFD+SES 移到 P4 之後；zkPDF 的手機可行性沒有人驗證過，是新 P4 最大的未知數。你同意後我才會更新「DIW MY WALLET 技術背景與跨平台轉換規劃」。

## 參考來源

既有研究：[bonds.md](../research/bonds.md)、[documents-signatures.md](../research/documents-signatures.md)、[zkp-verifier.md](../research/zkp-verifier.md)、[device-results-D1-2026-10-10.md](../research/device-results-D1-2026-10-10.md)。

- [zkPDF 部落格（PSE，2025-06-13）](https://pse.dev/blog/zkpdf-unlocking-verifiable-data)
- [privacy-ethereum/zkpdf](https://github.com/privacy-ethereum/zkpdf)
- [GovBind：eprint 2026/2206](https://eprint.iacr.org/2026/2206)
- [Reclaim Protocol：eprint 2026/2187](https://eprint.iacr.org/2026/2187)
- [tlsnotary/tlsn](https://github.com/tlsnotary/tlsn)
- [TLSNotary 路線圖（PSE Master Map）](https://pse.dev/mastermap/tlsnotary)
- [reclaimprotocol/attestor-core](https://github.com/reclaimprotocol/attestor-core)
- [OpenCerts/open-certificate](https://github.com/OpenCerts/open-certificate)
- [OpenCerts/certificate-cli](https://github.com/OpenCerts/certificate-cli)
- [TrustVC/trustvc](https://github.com/TrustVC/trustvc)
- [chouhsiang/open-gpki-pkcs11](https://github.com/chouhsiang/open-gpki-pkcs11)
- [教育部電子證書驗證系統](https://dcert.moe.gov.tw/)（前端程式中的 /students/validate/ 回應欄位）
- [教育部大專院校數位證書試辦計畫新聞](https://depart.moe.edu.tw/ED2200/News_Content.aspx?n=90774906111B0527&sms=F0EAFEB716DE7FFA&s=33ED650888B18CC3)
- [清華大學教育部版數位學位證書說明](https://registra.site.nthu.edu.tw/var/file/211/1211/img/175251807.pdf)
- [成功大學數位學位證書使用流程](https://reg-acad.ncku.edu.tw/var/file/41/1041/img/4278/gd_degree_acp.pdf)
- [臺北市電子化畢業證書實施計畫](https://www.taivs.tp.edu.tw/static/webroot/G157187608106738/application/NN178036298481896.pdf)
- [臺北市電子化畢業證書常見問答](https://www3.slhs.tp.edu.tw/board/data/2024625241737.pdf)
- [我的E政府：電子戶籍謄本申辦及驗證](https://www.gov.tw/News_Content_2_371532)
- [我的E政府：入出國日期證明書線上申辦](https://www.gov.tw/News_Content_2_371276)
- [全國地政電子謄本系統](https://ep.land.nat.gov.tw/EpaperDoc/MainNew)
- [內政部：行動自然人憑證 APP 增靠卡感應註冊](https://moica.nat.gov.tw/news_in_1857a906a7e000004073.html)
- [MyData：入出國日期證明書](https://mydata.nat.gov.tw/personal/detail/API.LPvQONMWj6)

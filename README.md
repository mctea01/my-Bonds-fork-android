# DIW MY WALLET

跨平台整合數位皮夾，以 [Multipaz](https://github.com/openwallet-foundation/multipaz)、台灣數位憑證皮夾（TWDIW）、EUDI Wallet、Microsoft Entra Verified ID 與 Bonds 的公開實作為參考，目標涵蓋數位憑證、電子簽章、身分認證、文件保存與電子公文。

目前先交付 Android，UI 以 Compose Multiplatform 撰寫，同一份程式也建置 Windows 與 Linux 桌面版。

## 功能

### 標準協議（預設全部啟用）

| 類別 | 支援內容 |
|---|---|
| 發證 | OpenID4VCI 1.0，以及 draft 11/12、draft 13 發證端；pre-authorized code（含 tx_code / user_pin）、authorization code（PKCE、PAR）、DPoP、wallet attestation、批次與延遲發證、回應加密 |
| 憑證格式 | ISO mdoc（mso_mdoc）、SD-JWT VC（dc+sd-jwt、vc+sd-jwt）、W3C VC（jwt_vc_json、jwt_vc_json-ld、ldp_vc）、包在 SD-JWT 中的 W3C VC |
| 出示 | OpenID4VP 1.0（DCQL、DC API），以及 draft 13 到 23（Presentation Exchange 2.0、client_id_scheme、did / x509_san_* client）、SIOPv2、OAuth fragment / query / form_post 回應；DC API 同時接受 `openid4vp` 與 `org-iso-mdoc` |
| mdoc 近距離 | ISO/IEC 18013-5：出示（NFC 交握，static 或 negotiated handover；QR Code 交握；資料經 BLE 或 NFC）與查驗（手機 NFC、手機 OTG 接 USB CCID 讀卡機、電腦的 PC/SC 讀卡機） |
| 遠端 mdoc | ISO/IEC 18013-7 Annex B（OpenID4VP 草案的 mdoc handover）與 Annex C（DC API 的 org-iso-mdoc，回應以 HPKE 加密並綁定網頁來源） |
| 信任 | X.509 信任錨（正式、使用者匯入、系統憑證庫、測試環境分開顯示，可匯入任何組織的根憑證；內建運作中的政府憑證總管理中心根憑證與 GCA、XCA、MOEACA、MOICA 中繼憑證；內建中國大陸憑證機構的根憑證，含國家根與持牌 CA 的國密 SM2 根憑證，可單獨關閉；內建發票、移民等常用服務憑證鏈的根憑證，每月由 CI 依來源更新；RSA 與國密 SM2 憑證鏈以 PKIX 驗證）、DID（did:key、did:jwk、did:web、did:ion）、DIF Linked Domains（依 Microsoft 規則，已驗證網域不另行警示）、TWDIW 信任清單與 Arbitrum 錨定、使用者自行信任的 DID |
| 狀態 | IETF Token Status List、W3C Bitstring Status List、Status List 2021（含 Microsoft Verified ID 經 Identity Hub 提供的清單）、Revocation List 2020，顯示規格原文狀態；狀態清單的 jku 金鑰先綁定發行端，綁不上時標示「僅經 HTTPS 確認」；背景自動更新，依用途風險（低、中、高）判斷是否接受 |

### 介面

介面以 EUDI Wallet 與 Bonds 的設計為準：所有證件在同一份清單，各發行端與 Profile 的功能併入共同的流程，不另開專區。

| 分頁 | 內容 |
|---|---|
| 證件 | 所有證件同一份清單，依身分證件、政府皮夾卡片、組織與會員卡、其他證件分組，可搜尋與篩選；以自然人憑證簽署的 Bonds 身分證卡列在最上方；右上「+」從清單選擇或掃描 QR Code 加入 |
| 文件 | 保存任何檔案並檢查簽章（PAdES、CAdES／PKCS#7、XAdES 與 XMLDSig、ASiC、OFD 電子印章、RFC 3161 時戳、國密 SM2、OpenCerts）；加時戳；以自然人憑證卡、PKCS#12 或錢包金鑰簽署；製作 PDF 與電子公文（函）；把文件轉成衍生憑證；從 MyData、MyDoc、教育部、戶政、地政、移民署等來源網站直接取件 |
| 使用 | 出示我的證件（掃描後依內容自動分流：OpenID4VP、數位憑證皮夾、Bonds 挑戰、靜態 QR）、感應出示（NFC 或 QR Code，ISO 18013-5）、臨櫃出示（超商取貨等條碼）、加入證件、貼上連結 |
| 查驗 | 離線挑戰查驗他人證件（政府皮夾卡片與自然人憑證自發卡，與 Bonds 相容；或任何綁定金鑰的證件，含文件衍生憑證與其證據）；感應查驗（以 NFC 讀取行動駕照等 mdoc 證件，手機或 PC/SC 讀卡機）；可選用途風險，有網路時查詢對方證件狀態。查驗方身分、線上查驗（OpenID4VP）與零知識證明查驗先保留入口 |
| 紀錄 | 領取、出示、拒絕、查驗與證件狀態變更的對象、時間、證件與欄位名稱，不保存欄位內容 |

右上齒輪進入設定：金鑰保護、證件狀態自動更新、文件與時戳（時戳服務、保存時自動加時戳）、信任清單（數位憑證皮夾公布的發行端與查驗方，開啟時自動查驗 Arbitrum 錨定）、信任錨點（X.509 根憑證與自行信任的 DID，不限 TWDIW）、紀錄清除、互通設定與測試環境。

發行端與查驗方依信任等級顯示：T1 列於官方信任清單且可完整驗證；T2 身分已確認（TWDIW 已列名但鏈上註冊暫時無法確認，或憑證鏈連到內建的政府憑證 GPKI）；T3 可驗證但非官方（系統憑證庫與內建公開憑證機構、Linked Domains、自行匯入的根憑證與自行信任的 DID、未列名的 DID、測試環境）；T4 驗證失敗。設定 > 信任錨點有各等級的說明，長列表可折疊。

每張證件顯示狀態判定（有效、僅經 HTTPS 確認、無法確認、已撤銷等），依證件分類的風險決定顯示為通過、需留意或不應接受；出示前依要求欄位的敏感度與查驗方信任等級計算請求風險，證件狀態被判定為不接受時不能出示（撤銷、暫停），無法確認時可重新查詢。

證件內容頁可直接出示這張證件：mdoc 證件以感應或 QR Code 出示，其他證件在掃描查驗方的 QR Code 後排在最前面。

「從清單選擇」列出數位憑證皮夾可申請的卡片，也可輸入任一 OpenID4VCI 發行端網址。

### 文件、簽章與衍生憑證

- **保存與檢查**：從檔案、分享、來源網站或 ZIP 解出的檔案都存進文件分頁，每次開啟重新檢查。每個簽章分別顯示完整性、簽署者憑證鏈的信任等級（政府憑證 GPKI 與自然人憑證 MOICA 為 T2）、時戳與簽署後是否有其他變更。
- **時戳**：可選 DigiCert、Sectigo、GlobalSign 等 RFC 3161 時戳服務，替任何文件加上時戳，也可設定保存時自動加。
- **簽署**：自然人憑證卡（Android 以 NFC 感應兩次：先讀憑證再簽章；USB 讀卡機與電腦的 PC/SC 讀卡機）、PKCS#12 憑證檔或錢包金鑰（自簽憑證）。PDF 以 PAdES 增量簽署並保留原有簽章，XML 以 XAdES，其他檔案以 CAdES 或 ASiC-E 容器。PIN 不保存。
- **製作文件**：輸入內容產生 PDF，或依文書處理手冊格式產生電子公文「函」（.di），再加簽章。
- **衍生憑證**：任何文件都可轉成一張 SD-JWT VC（可選擇揭露姓名、文件名稱、簽署者、簽署時間、來源），附上文件簽章檢查、時戳與自然人憑證簽章三種證據；有自然人憑證證據時也能以 Bonds 的自發卡格式（vc+moica）出示。另一台手機在「查驗」分頁即可離線驗證。
- **Bonds 身分證卡**：MyData 下載的「國民身分證資料」PDF（以身分證統一編號加密）在文件畫面輸入編號開啟，讀出統號、姓名、出生日期與戶籍地址，確認後以自然人憑證卡簽署成 Bonds 相容的 NationalIDCredential（vc+moica），另加「簽發時年滿 18 歲」欄位。卡片姓名須與自然人憑證相同；出示時可只揭露年齡欄位（姓名一定揭露）。Bonds 原本以行動自然人憑證簽署，本錢包改用實體卡，行動自然人憑證為停用列（需要 SP 帳號）。
- **來源網站**：MyData、臺北市 MyDoc、教育部大專校院電子證書、數位證明管理中心、內政部戶政與地政、移民署入出國日期證明書。Android 在 App 內開啟，下載的檔案直接保存；需要行動自然人憑證登入時轉到官方 App。戶籍謄本 .asdt 是加密給戶政司的檔案，只能保存原檔。
- **尚未提供**（介面上為停用列並寫明原因）：行動自然人憑證簽章（需要內政部 SP 帳號）、CSC 遠端簽章、公文交換收發。

### 相容處理（常駐啟用，不需開關）

- **數位憑證皮夾（TWDIW）官方流程**：`modadigitalwallet://` 與 wallet.gov.tw 連結、發證（client_id `moda_dw`、did:key jwk_jcs 持有者）、出示（含靜態 QR 自訂欄位）、可申請卡片目錄、7-ELEVEN 等離線條碼（DWVP-05）。卡片與其他證件在同一份清單。
- **TWDIW 信任清單**：每個機關的 DID 文件簽章與 Arbitrum One 鏈上登記；測試環境（UAT、sandbox）只在開啟測試環境後才計入。
- **Bonds 離線出示**：掃描 Bonds 查驗方的 JSON QR，以輪播 QR（BTWVP1）或藍牙（手機作為 GATT 周邊）出示 TWDIW 卡片；也可在「查驗」分頁作為查驗方，掃描對方的輪播 QR 驗證。本錢包另以來源 `a` 擴充同一格式，可離線出示任何綁定金鑰的證件：IETF SD-JWT VC（可選欄位，持有者 DID 為 cnf 金鑰的 did:jwk）、W3C VC 的 SD-JWT 與 JWT 形式；查驗端以 x5c、DID 或發行端中繼資料取得發行端金鑰。Bonds App 只認得政府皮夾卡片（`g`）與自發卡（`s`）。
- **Microsoft Entra Verified ID**：`openid-vc://` 發行（合約、PIN、id_token_hint、身分提供者登入、自填欄位）與出示，發行端以 Linked Domains 判斷信任。
- **EUDI 參考實作**：授權回應的 iss 為授權伺服器下的子路徑時仍接受（issuer.eudiw.dev/oidc）。

各方言的程式碼與標準路徑隔離，只在對方使用該方言時才介入，詳見 [AGENTS.md](AGENTS.md)。

## 下載

CI 在 main 每次更新後發佈「nightly」預先發行版，檔案說明見 [docs/release.md](docs/release.md)。

- Android 10（API 29）以上。
- release APK 經 R8 縮減與最佳化；debug APK 允許區網測試伺服器的 HTTP。

## 建置

需求：JDK 21、Android SDK（compileSdk 36）。

```bash
./gradlew :app:assembleDebug          # Android debug APK
./gradlew :app:assembleRelease        # Android release APK（R8）
./gradlew :app:run                    # 桌面版
./gradlew :test-servers:test          # 協議與互通測試
./gradlew :app:desktopTest            # App 流程測試
python3 -I tools/trust-roots/update_roots.py --report report.md   # 依來源重新產生內建公開根憑證（需要網路與 openssl）
```

CI 的測試是獨立的 job，與 Android、桌面版的建置平行執行；main 的 nightly 預先發行版在測試與建置都成功後才發佈。內建公開根憑證由每月的 workflow 重新產生，有變更時開 PR 並附上報告。

Windows 的 PowerShell 請先執行 `chcp 65001` 並設定 `$env:JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"`，避免中文輸出亂碼。

桌面版的感應查驗使用 PC/SC 非接觸式讀卡機（例如 ACR122U、ACR1252U、Identiv uTrust、HID OMNIKEY）。Windows 與 macOS 內建 PC/SC；Linux 需安裝 `pcscd` 與 `libpcsclite1`（或 `pcsc-lite-libs`）並啟動 pcscd。PC/SC 讀卡機只能讀取，不能模擬卡片，所以電腦不能以 NFC 出示。

## 測試伺服器

`test-servers` 是只用於測試環境的發證端、驗證端與 Wallet Provider，符合 OpenID4VCI / OpenID4VP 1.0 並提供舊版設定，用來測試各 SDK 的互通：

```bash
./gradlew :test-servers:run --args="8080 http://<區網 IP>:8080"
```

瀏覽器開啟 `http://<區網 IP>:8080/verifier` 即可產生出示要求，`/pki/iaca.pem` 等路徑提供測試信任錨。App 需在設定中開啟測試環境並匯入對應的信任錨。

## 專案結構

| 模組 | 內容 |
|---|---|
| `core` | 協議與信任核心（Kotlin Multiplatform，JVM 與 Android） |
| `app` | Compose Multiplatform App（Android、桌面） |
| `test-servers` | 測試伺服器與所有自動化測試 |
| `docs` | 驗收與發佈文件 |
| `tools` | 內建根憑證產生器（`trust-roots`）、以 EU DSS 驗證錢包簽章的工具（`dss-check`） |

## 授權

見 [LICENSE](LICENSE)。

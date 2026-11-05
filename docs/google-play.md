# Google Play 上架

上架 Google Play 的目的是讓開發者帳號維持活動，不會因為不活躍而在 2026 年 12 月被關閉；同時讓 Android 使用者可以從 Play 安裝與更新。GitHub 的 nightly 仍是主要的測試發佈管道。

本文件記錄：上架前檢查的結果、Play Console 一次性設定、自動提交 workflow、商店資訊文字，以及 Play Console「應用程式內容」各表單建議的答案。答案依撰寫時（2026-11-05，P4 整合分支）的程式碼判斷；功能改變（特別是新增網路傳輸、分析或廣告 SDK、權限）時要同步更新本文件與 Play Console。

隱私權政策、用戶協議與 TWDIW、Microsoft Verified ID 等專門聲明由法律聲明的工作負責；本文件只列出 Play 對它們的要求。i18n 規劃見 [design/i18n.md](design/i18n.md)。

## 1. 帳號為什麼會被關閉、要做什麼

依 Play Console 說明（[answer 11605267](https://support.google.com/googleplay/android-developer/answer/11605267)），建立超過一年的帳號在下列情況會被視為不活躍：

- 沒有應用程式：從未提交應用程式送審。
- 有應用程式：所有應用程式累計安裝少於 1,000 次、未驗證聯絡電話與電子郵件，而且 180 天內沒有使用 Play Console。

Google 建議兩件事都要做：

1. Play Console 的「帳戶詳細資料 > 聯絡資訊」完成電子郵件與電話驗證並儲存。
2. 建立應用程式並上傳新的 App Bundle（送審）。

說明頁沒有寫明內部測試是否算「送審」。為了確定算數，建議第一次就把版本送到**封閉測試**（closed testing，API 名稱 `alpha`）並送審，不必上正式版。

2023 年 11 月 13 日以後建立的個人帳號，要上**正式版**之前需要先有 12 位測試人員連續加入封閉測試 14 天（[answer 14151465](https://support.google.com/googleplay/android-developer/answer/14151465)）。這個帳號已經存在很久，應不受影響，但以 Play Console 首頁顯示的為準；這只影響正式版，不影響保住帳號。

## 2. 上架前檢查結果

以 CI 第 464 次執行（P4 整合分支 `dd41cd3`）的 `DIW-MY-WALLET-0.4.21-pr12-debug.aab` 與 APK 檢查：

| 項目 | Play 的要求 | 結果 |
|---|---|---|
| 目標 API | 2026-08-31 起新應用程式與更新需 API 36 | `targetSdk = 36`，`minSdk = 29` |
| 64 位元 | 有原生程式庫時需提供 64 位元版本 | arm64-v8a 與 x86_64 齊全 |
| 16 KB 分頁 | 目標 Android 15 以上需支援 16 KB 分頁 | 64 位元的 `.so` 全部以 16 KB 對齊（`libdiw_zk`、Multipaz 的 `libzkp`、JNA、CameraX、AndroidX） |
| 格式 | 新應用程式需 AAB | CI 已建置 `:app:bundleRelease`（R8 縮減與最佳化），nightly 附 `DIW-MY-WALLET-<版本>.aab` |
| 大小 | 單一裝置下載壓縮後不超過 200 MB | debug AAB 61 MB（含兩個 ABI 的零知識程式庫），依 ABI 分割後遠低於上限 |
| 套件名稱 | 上傳後不能更改 | `diw.wallet.app`；Play 商店上目前沒有同名的公開應用程式 |
| 權限 | 受限權限需另外申報 | 沒有受限權限（見下表） |

合併後的 manifest 權限：

| 權限 | 用途 | Play 申報 |
|---|---|---|
| `INTERNET`、`ACCESS_NETWORK_STATE` | 領卡、出示、時戳、撤銷資訊 | 不需要 |
| `CAMERA` | 掃描 QR Code | 不需要（只在裝置上處理） |
| `NFC` | 自然人憑證卡、mdoc 感應出示與查驗（HCE） | 不需要 |
| `BLUETOOTH_SCAN`（`neverForLocation`）、`BLUETOOTH_CONNECT`、`BLUETOOTH_ADVERTISE`；舊版的 `BLUETOOTH`、`BLUETOOTH_ADMIN`、`ACCESS_FINE_LOCATION`（只到 API 30） | ISO 18013-5 與 Bonds 近距離傳輸 | 不需要；不取得位置 |
| `USE_BIOMETRIC`、`USE_FINGERPRINT` | 解鎖金鑰 | 不需要 |
| `VIBRATE`、`DUMP`（AndroidX ProfileInstaller） | 震動回饋、啟動最佳化 | 不需要 |

沒有 `REQUEST_INSTALL_PACKAGES`、`QUERY_ALL_PACKAGES`、`MANAGE_EXTERNAL_STORAGE`、`READ_MEDIA_*`、背景位置、前景服務或廣告 ID，也沒有分析、當機回報或廣告 SDK。

需要留意的地方：

- **32 位元裝置**：armeabi-v7a 與 x86 只有 AndroidX、CameraX 與 JNA 的程式庫，沒有零知識程式庫。Play 會照樣提供給 32 位元裝置；零知識功能在這些裝置上無法使用，要確認 App 能正常降級（P4 的 D3：低運算不阻擋）。若不想支援，可在 `android.defaultConfig` 加 `ndk { abiFilters += setOf("arm64-v8a", "x86_64") }`。
- **執行時下載的資產**：zkPDF 電路與 OpenAC 的資料檔從 GitHub Release 下載並核對雜湊。Play 禁止從 Play 以外下載可執行程式碼（dex、jar、.so）；電路與 CRS 是資料，不是可執行程式碼，應不違反，但商店說明與審查備註要寫清楚是「核對雜湊的密碼學參數」。不可改成下載 `.so`。
- **加密傳輸**：Bonds 相容的 BLE 與區網連線依 Bonds 協定沒有工作階段加密（真實性靠簽章出示與查驗方挑戰，見 `BondsTransport.kt`），OCSP、CRL 與 RFC 3161 時戳依 PKI 慣例使用 HTTP。因此資料安全表單的「傳輸時加密」要回答「否」（第 6.6 節）。

## 3. Play Console 一次性設定

依序：

1. **聯絡資訊驗證**（第 1 節）。
2. **建立應用程式**：名稱 `DIW MY WALLET`、預設語言「中文（台灣）– zh-TW」、類型「應用程式」、免費。
3. **Play 應用程式簽署**：建立第一個版本時選擇。這個決定日後只能用金鑰輪替改變，見第 3.1 節。
4. **第一個 App Bundle 手動上傳**：API 只能上傳到已經有套件名稱的應用程式，所以第一次要在 Play Console 上傳。從 nightly 下載 `DIW-MY-WALLET-<版本>.aab`（不是 `-debug.aab`），到「測試 > 封閉測試」建立測試群組（可以只有自己的帳號）、建立版本、上傳，「版本資訊」貼 `distribution/whatsnew/` 的內容。
5. **應用程式內容**與**商店資訊**：照第 5、6 節填寫。全部完成後「發布總覽」才能送審。
6. 送審通過後，之後的版本可以用自動提交 workflow（第 4 節）。

### 3.1 簽署金鑰的選擇

Play 一律以「應用程式簽署金鑰」重新簽署給使用者的 APK；CI 用來簽 AAB 的金鑰只是「上傳金鑰」。

| 選項 | 結果 |
|---|---|
| A. 匯出現有的 release 金鑰作為應用程式簽署金鑰（Play Console 的「使用其他應用程式的金鑰」或「匯出並上傳 Java KeyStore 的金鑰」，用 Google 提供的 PEPK 工具加密上傳），上傳金鑰也用同一把 | GitHub nightly 的 APK 與 Play 安裝的 App 簽章相同，可以互相覆蓋更新；CI 不必改。缺點是這把金鑰同時存在 GitHub secrets 與 Google，外洩時只能靠金鑰輪替（Android 13 以上才完全有效） |
| B. 由 Google 產生應用程式簽署金鑰，現有 release 金鑰當上傳金鑰 | 最安全，上傳金鑰外洩可以重設。但 Play 版與 GitHub 版簽章不同，使用者切換來源要先解除安裝（錢包資料會一起刪除）；依 APK 簽章的設定（例如 TWDIW 應用身分、Digital Asset Links）要登記兩個指紋 |

已決定採用 A（2026-11-05）：這個專案以 GitHub 發佈為主，使用者會在兩個來源之間切換，而錢包資料不能因為換來源而遺失。CI 不用新增 secret。建立第一個版本時，在「Play 應用程式簽署」選擇上傳自己的金鑰，依畫面下載 PEPK 工具，以 `diw-release.jks` 與別名 `diw` 產生加密後的金鑰檔上傳；上傳金鑰也使用同一把。

## 4. 自動提交 workflow

檔案：`.github/workflows/google-play.yml`（新檔），另外 `github-actions-ci.yml` 的 release 建置要把 R8 mapping 一起發佈到 nightly（`DIW-MY-WALLET-<版本>-mapping.txt`）。兩個檔案的完整內容放在專案共用資料夾 `diw-wallet/play/`，由使用者手動放進 `.github/workflows/`。

做法：從 GitHub Release（預設 `nightly`）下載 release AAB 與 mapping，以 [r0adkll/upload-google-play](https://github.com/r0adkll/upload-google-play) v1.1.5（固定 commit SHA）上傳，版本資訊取自 `distribution/whatsnew/whatsnew-<語言>`。不重新建置，所以上傳的檔案與 nightly 完全相同。

觸發方式：

- **手動**（Actions > Google Play > Run workflow）：選擇 track（`internal`、`alpha` 封閉測試、`beta` 開放測試、`production`）、狀態（`draft`、`completed`、`inProgress` 加分階段比例）與來源 release。
- **自動**（可選）：設定 repository variable `PLAY_AUTO_TRACK`（例如 `internal`）後，每次 push 到 main 的 CI 成功，就把該次 nightly 上傳到這個 track；`PLAY_AUTO_STATUS` 預設 `draft`，可改 `completed`。如果 nightly 已被更新的 push 取代，該次不上傳。沒有設定 `PLAY_AUTO_TRACK` 時不會自動上傳。

上傳在 `google-play` environment 執行，可以在 repo 的 Settings > Environments 設定「Required reviewers」，讓每次上傳都要手動核准。

### 4.1 Service account

1. Google Cloud Console 建立（或選擇）專案，啟用「Google Play Android Developer API」。
2. 「IAM 與管理 > 服務帳戶」建立服務帳戶，不指派任何 Cloud 角色；在「金鑰」新增 JSON 金鑰並下載。
3. Play Console「使用者和權限」邀請服務帳戶的電子郵件，應用程式權限給「DIW MY WALLET」：「發布到測試群組」，要從 workflow 上正式版時再加「發布到正式版、排除裝置及使用 Play 應用程式簽署」。
4. GitHub repo 的 Settings > Secrets and variables > Actions（或 `google-play` environment 的 secrets）新增 `PLAY_SERVICE_ACCOUNT_JSON`，內容是整個 JSON 檔。

| 設定 | 種類 | 內容 |
|---|---|---|
| `PLAY_SERVICE_ACCOUNT_JSON` | secret | 服務帳戶 JSON 金鑰全文 |
| `PLAY_AUTO_TRACK` | variable，可選 | 自動上傳的 track；不設定就只能手動 |
| `PLAY_AUTO_STATUS` | variable，可選 | 自動上傳的狀態，`draft`（預設）或 `completed` |

### 4.2 限制

- 從未發布過的應用程式只接受 `draft`：第一次通過審查之前，workflow 只能建立草稿，再到 Play Console 按「送審」。
- 上正式版之前，必須先有版本經過測試 track。
- 同一個 versionCode 只能上傳一次。versionCode 由 `version.properties` 與 commit 數算出（[release.md](release.md#版本號)），只要從 main 依序建置就一定變大；重跑同一個 nightly 會被 Play 拒絕，這是正常的。
- 零知識原生程式庫沒有附除錯符號，Play Console 會顯示「未上傳原生偵錯符號」的警告，不影響上架。

## 5. 商店資訊

### 5.1 基本資料

| 欄位 | 內容 |
|---|---|
| 應用程式名稱（zh-TW，30 字內） | `DIW MY WALLET：憑證、簽章與文件` |
| 應用程式名稱（en-US） | `DIW MY WALLET: ID & Documents` |
| 類別 | 工具（Tools） |
| 標記 | 選與「工具」「生產力」相關、描述憑證與文件的標記；不要選「政府」相關 |
| 聯絡電子郵件 | 開發者帳號的公開聯絡信箱（必填，會公開顯示） |
| 網站 | `https://github.com/mctea01/my-Bonds-fork-android` |
| 隱私權政策 | 法律聲明完成後的公開網址（第 6.1 節） |

名稱不要使用「數位憑證皮夾」：這是數位發展部官方 App 的名稱，Play 會以冒用政策（Impersonation）審查。

### 5.2 簡短說明（80 字內）

zh-TW：

```
持有與出示數位憑證、保存並驗證簽章文件、以自然人憑證簽署，資料只存在你的裝置。
```

en-US：

```
Hold and present digital credentials, verify signed documents and sign them.
```

### 5.3 完整說明（4,000 字內）

zh-TW：

```
DIW MY WALLET 是開放原始碼的整合數位皮夾：在同一個 App 內領取與出示數位憑證、查驗他人的證件、保存並檢查簽章文件、以自然人憑證或遠端簽章服務簽署文件，並把文件轉成可出示的衍生憑證。

【數位憑證】
・領取：OpenID4VCI 1.0 與舊版草案，支援 ISO mdoc、SD-JWT VC 與 W3C VC
・出示：OpenID4VP 1.0、ISO/IEC 18013-5 近距離出示（NFC、藍牙、QR Code）與 Digital Credentials API
・相容台灣數位憑證皮夾（TWDIW）、Microsoft Entra Verified ID、EUDI Wallet 參考實作、Multipaz 與 Bonds 的發證端與查驗端
・出示前清楚顯示查驗方身分、信任等級、用途與要交出的欄位，由你決定是否同意
・憑證狀態依規格原文顯示（Token Status List、Bitstring Status List 等）

【文件與簽章】
・保存並驗證 PAdES、CAdES、XAdES、ASiC、OFD、電子公文簽核檔與 RFC 3161 時戳
・自動加時戳並保存撤銷資訊，同類文件可並存並依年度整理
・以自然人憑證卡（NFC）、PKCS#12 或 CSC 遠端簽章服務簽署，可選 B-B 至 B-LTA 保證層級
・從文件產生可出示的衍生憑證

【零知識證明】
・年齡證明：只證明「已滿某個年齡」，不交出生日
・網站查驗證明（zkTLS）與 mdoc 零知識出示
・證明在你的裝置上產生；需要的電路參數從專案的 GitHub Release 下載並核對雜湊

【查驗】
・App 也可以當查驗方，以 NFC、QR Code 或藍牙查驗證件與年齡證明

【隱私】
・證件、文件與金鑰只加密保存在你的裝置
・只有在你同意出示、領卡或簽署時，才把必要的資料傳給你選擇的發證端、查驗方或簽章服務
・沒有廣告，沒有分析或追蹤 SDK，不需要註冊帳號
・紀錄只記欄位名稱，不記內容

【重要說明】
・本 App 為個人開發的開源專案（Apache-2.0），不是數位發展部、內政部、Microsoft、歐盟或任何政府機關發行的 App，也未獲得其背書或授權。各機關的名稱與商標屬於其所有人，僅用於說明相容性。
・與官方服務的相容性依各服務公開的行為實作，服務端變更時可能暫時無法使用。
・App 仍在開發中；正式與測試環境在同一個 App 內，測試環境的結果一律標示為不具效力。
・目前介面為繁體中文。

原始碼與問題回報：https://github.com/mctea01/my-Bonds-fork-android
```

en-US：

```
DIW MY WALLET is an open-source wallet that brings digital credentials, signed documents and electronic signatures together in one app.

Digital credentials
- Receive credentials with OpenID4VCI 1.0 and earlier drafts: ISO mdoc, SD-JWT VC and W3C VC
- Present with OpenID4VP 1.0, ISO/IEC 18013-5 proximity (NFC, Bluetooth, QR code) and the Digital Credentials API
- Works with issuers and verifiers of the Taiwan Digital Wallet (TWDIW), Microsoft Entra Verified ID, the EUDI Wallet reference implementation, Multipaz and Bonds
- Before you share anything, see who is asking, how far they are trusted, why, and which fields they get

Documents and signatures
- Keep and verify PAdES, CAdES, XAdES, ASiC, OFD and RFC 3161 time stamps
- Sign with a Taiwan citizen digital certificate card (NFC), PKCS#12 or a CSC remote signing service, at levels B-B to B-LTA
- Turn documents into credentials you can present

Zero-knowledge proofs
- Prove you are over an age without revealing your birth date
- zkTLS website proofs and mdoc zero-knowledge presentation
- Proofs are made on your device; circuit parameters are downloaded from the project's GitHub releases and checked against their hashes

Privacy
- Credentials, documents and keys are stored encrypted on your device only
- Data leaves the device only when you agree to present, receive or sign, and only to the issuer, verifier or signing service you chose
- No ads, no analytics or tracking SDKs, no account

Important
- This is an independent open-source project (Apache-2.0). It is not published, endorsed or authorized by the Ministry of Digital Affairs, the Ministry of the Interior, Microsoft, the European Union or any government agency. Their names and marks belong to their owners and are used only to describe compatibility.
- The app is under development. The user interface is currently in Traditional Chinese.

Source code and issues: https://github.com/mctea01/my-Bonds-fork-android
```

功能說明要與當時的版本相符：尚未提供的功能（例如 zkPDF）不要寫成已提供；Play 會以「誤導性聲明」處理不實描述。

### 5.4 圖像

| 素材 | 規格 | 現況 |
|---|---|---|
| 應用程式圖示 | 512 × 512 PNG，32 位元含 alpha，1 MB 內 | 啟動圖示是向量（`res/drawable/ic_launcher_*.xml`），需另外輸出 PNG |
| 主題圖片 | 1,024 × 500 JPG 或 24 位元 PNG，不含 alpha | 需要製作 |
| 手機螢幕截圖 | 2 到 8 張，每邊 320 到 3,840 像素，長邊不超過短邊的 2 倍 | `desktopTest` 繪製的畫面是 824 × 1,784（比例 2.17），要裁成 824 × 1,648 或加邊到 892 × 1,784；建議至少 1,080 像素寬以便推薦版位 |

截圖只能使用測試資料。不要出現 TWDIW 卡面上的政府標誌、真實姓名或證號，避免冒用與個資問題。

## 6. 應用程式內容（App content）

### 6.1 隱私權政策

必填，需要公開、不需登入、不能是 PDF 的網址，內容要與資料安全表單一致，並寫明開發者名稱與聯絡方式。可以放在 GitHub Pages，或 repo 內的 Markdown 頁面網址。由法律聲明的工作提供；它需要涵蓋第 6.6 節列出的資料類型、各傳輸對象（發證端、查驗方、簽章與時戳服務、使用者自行設定的正式服務端），以及 Bonds 相容連線不加密這件事。

### 6.2 廣告

否。

### 6.3 應用程式存取權

選「所有功能都不需要特殊存取權即可使用」：App 沒有帳號與登入。審查備註可以補充：

```
No account is needed. To try receiving a credential, open Use > Add credential and choose the Multipaz test issuer (test environment). Zero-knowledge circuit parameters are data files downloaded from the project's GitHub releases and verified by SHA-256; no executable code is downloaded.
```

### 6.4 內容分級（IARC 問卷）

- 類別：「所有其他應用程式類型」（工具、參考資料等）。
- 暴力、性、髒話、管制物品、賭博、恐怖內容：全部「否」。
- 使用者互動或交換內容（聊天、使用者產生內容）：否。App 之間的出示是結構化的憑證資料，不是使用者之間的通訊。
- 分享使用者的個人資訊給第三方：是（使用者同意後出示證件）。
- 分享使用者目前的實際位置：否。
- 購買數位商品：否。

預期分級為「普遍級」或「3 歲以上」，並標示「會分享資訊」之類的互動元素。

### 6.5 目標對象與內容

- 目標年齡層：只選「18 歲以上」。App 處理身分證件與簽章，不以兒童為對象，選 18 歲以上也避免適用「家庭」政策。
- 是否會吸引兒童：否。

### 6.6 資料安全

Play 的「收集」是指資料由 App 傳出裝置，不論對象是開發者還是第三方（[answer 10787469](https://support.google.com/googleplay/android-developer/answer/10787469)）。出示憑證與文件時，證件欄位會傳給查驗方，所以要申報收集。使用者主動出示、且出示前有同意畫面，屬於「使用者發起的動作」，不算「分享」。

1. **App 是否收集或分享任何必要資料類型**：是。
2. **所有使用者資料在傳輸時都經過加密**：否。Bonds 相容的 BLE 與區網連線沒有工作階段加密，OCSP、CRL 與時戳使用 HTTP（第 2 節）。
3. **提供使用者要求刪除資料的方式**：否。開發者不保存任何使用者資料（沒有帳號，正式服務端由使用者自行架設，中繼只轉送端對端加密的資料），App 內可以刪除全部本機資料；已出示給查驗方的資料由查驗方保存，要向查驗方要求刪除。隱私權政策要寫明這一點。

資料類型（每一項的回答都是：收集＝是、分享＝否、暫時處理＝否、必要或選用＝使用者可選擇、用途＝應用程式功能）：

| 類別 | 資料類型 | 原因 |
|---|---|---|
| 個人資訊 | 姓名 | 證件欄位，出示時傳給查驗方 |
| 個人資訊 | 電子郵件地址 | 部分證件（例如 Microsoft Verified ID）含電子郵件 |
| 個人資訊 | 使用者 ID | 身分證號、證件號碼 |
| 個人資訊 | 地址 | 戶籍地址等證件欄位 |
| 個人資訊 | 其他資訊 | 出生日期、國籍、性別等證件欄位 |
| 相片和影片 | 相片 | mdoc 等證件的照片欄位 |
| 檔案和文件 | 檔案和文件 | 文件衍生憑證與 zkPDF 證據可能附上文件的簽署版本 |

不申報的類別與原因：

- 位置：不取得位置；`BLUETOOTH_SCAN` 宣告 `neverForLocation`，`ACCESS_FINE_LOCATION` 只用於 Android 11 以下的藍牙掃描。
- 財務、健康、訊息、通訊錄、日曆、App 活動、網頁瀏覽記錄、App 資訊與效能、裝置或其他 ID：沒有傳出裝置。
- 相機畫面、生物辨識、自然人憑證卡讀出的資料：只在裝置上處理；簽章傳給使用者選擇的服務時，傳的是簽章值與文件雜湊，不是檔案。
- 時戳、OCSP、CRL：傳的是文件雜湊與憑證序號，不屬於上表的使用者資料類型。

以後若加入當機回報、分析、正式服務端的預設網址，或把文件傳到伺服器產生證明（例如 zkPDF 證明器），要更新這一節。

### 6.7 其他聲明

| 聲明 | 回答 |
|---|---|
| 政府應用程式（是否由政府開發或代表政府發布） | 否 |
| 金融功能 | App 不提供任何金融功能 |
| 健康應用程式 | 否 |
| 新聞應用程式 | 否 |
| 廣告 ID | 不使用 |
| 前景服務、精確鬧鐘、全螢幕通知等權限聲明 | 不適用（沒有這些權限） |

## 7. 政策風險

- **冒用與政府關聯**：名稱、圖示、截圖與說明都不能讓人以為是政府或 Microsoft 的官方 App。完整說明保留第 5.3 節的「重要說明」；圖示不要使用政府標誌。
- **TWDIW 私有協定**：App 對 TWDIW 的支援依官方 App 的實際行為實作，不是官方授權的整合。審查若詢問，回覆它是使用者自己的憑證、由使用者主動領取與出示。專門聲明與確認頁由法律聲明的工作提供。
- **個人與敏感資料**：同意畫面就是 Play 要求的「明確揭露與同意」，出示前必須顯示，不能預設同意。
- **動態載入**：只能下載資料，不可以下載或載入程式碼（第 2 節）。

## 8. 相依的工作

| 項目 | 負責 | 狀態 |
|---|---|---|
| 隱私權政策公開網址、用戶協議 | 法律聲明 | 進行中 |
| 首次啟動頁與 TWDIW、Microsoft Verified ID 專門聲明 | 法律聲明 | 進行中 |
| 介面多語系、英文商店資訊與英文截圖 | i18n（[design/i18n.md](design/i18n.md)） | 法律聲明與 zkPassport 研究完成後 |
| 圖示 PNG、主題圖片、裁切後的截圖 | 上架 | 待製作 |
| `google-play.yml` 與 CI mapping 發佈 | 使用者手動放入 `.github/workflows/` | 待套用 |

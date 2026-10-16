# 實機測試清單（2026-10-10）

雲端容器無法驗證的項目都在這裡。每項列出前置條件、步驟、預期結果與判定標準，可由人手動執行，也可交給 Codex 執行（標「需人工」的步驟必須有人操作手機）。
測試工具為 `validation/android-smoke/apk/` 的 diw-smoke APK（說明見 `validation/android-smoke/README.md`），以及公開的參考 App。

## 0. 共同準備

### 0.1 裝置組合（至少前三台）

| 代號 | 建議裝置 | 目的 |
|---|---|---|
| D1 | Pixel 8 以後（Android 14 以上，有 StrongBox） | 基準裝置，StrongBox、DC API、HCE |
| D2 | Samsung Galaxy S 或 A 系列（Android 13 以上） | 主流廠商 ROM、Knox、不同 NFC 天線位置 |
| D3 | 中低階機（4 GB RAM 以下） | ZK 與簽章效能下限 |
| D4（可選） | 無 GMS 的 AOSP 系（GrapheneOS、LineageOS） | 兜底：無 Play 服務、無 Credential Manager |
| D5（可選） | 32 位元 ARM 裝置 | 確認 ZK 降級路徑 |
| D6（可選） | 第二支 Android 手機 | 近場出示的讀取端 |

### 0.2 工具與檔案

- 電腦：adb（Android platform-tools）、本專案的 `validation/android-smoke/`。
- diw-smoke APK：先用 `diw-smoke-0.1.1-debug.apk`，全部通過後再以 `diw-smoke-0.1.1-release.apk` 重跑一次自動項目，確認 R8 縮減沒有破壞功能。
- Multipaz TestApp 0.101.0（與本專案使用的 SDK 同版）：`https://apps.multipaz.org/testapp/multipaz-testapp-blue-0.101.0.apk` 與 `...-red-0.101.0.apk`。
- 官方「數位憑證皮夾」（Google Play，套件 `tw.gov.moda.diw`），只用於對照。
- 手機設定：開發人員選項與 USB 偵錯、螢幕鎖（PIN 或圖形）、至少一枚指紋或臉部（Class 3）、NFC 開啟、藍牙開啟。

### 0.3 結果回報方式

- 每台裝置一個資料夾 `device-results/<型號>-<時間>/`，`run-auto` 腳本會自動建立並放入 logcat 與匯出記錄。
- 手動項目用 App 的「Export」匯出，或截圖，一併放進該資料夾。
- 把整個資料夾壓縮後上傳到本專案對話串，並在下方「結果總表」填寫判定。

### 0.4 交給 Codex 時的指示範本

> 在連接的 Android 手機上執行 `validation/android-smoke/scripts/run-auto.sh`（Windows 用 `run-auto.ps1`），完成後把 `device-results/` 下新產生的資料夾內容整理成本清單第 9 節的結果表。遇到需人工的步驟（M1、M2、P1、P2、T2）時停下來，請使用者操作手機後再繼續讀取 logcat（`adb logcat -d -s DIWSMOKE:I`）。不要修改 APK 或測試程式。

## 1. 自動項目（A1 至 A4、C1 至 C6）

### T01 一鍵自動執行

- 前置：0.1 至 0.2 完成，手機以 USB 連接且 `adb devices` 看得到。
- 步驟：
  1. Linux/macOS：`cd validation/android-smoke && ./scripts/run-auto.sh`。
  2. Windows PowerShell：`cd validation\android-smoke; powershell -ExecutionPolicy Bypass -File scripts\run-auto.ps1`（腳本已切換 UTF-8）。
  3. 等待腳本印出 SUMMARY（ZK 與網路檢查需數分鐘）。
- 預期：SUMMARY 列出 A1 至 A4 與 C1 至 C6，每項有判定與耗時。
- 判定：腳本找得到 `AUTORUN DONE` 且有 SUMMARY 即本步驟通過；各項判定見 T02 至 T07。

### T02 裝置能力盤點（A1）

- 預期：記錄 `feature android.hardware.strongbox_keystore`、`hardware_keystore version`、`nfc`、`nfc.hce`、`bluetooth_le`、`identity_credential`、`software.credentials`、`usb.host`，生物辨識 `STRONG=0` 表示可用，`gms` 版本。
- 判定：屬資訊項目（INFO），無通過或失敗；用來解釋其他項目的結果。D4 應顯示 `gms=absent`。

### T03 硬體金鑰與金鑰證明（A2）

- 前置：已設定螢幕鎖。
- 預期：
  - `[TEE] createKey` 成功，`keyMintSecurityLevel=TrustedEnvironment`，`challenge` 與送出的相同，`verifiedBootState=Verified`，`deviceLocked=true`。
  - 支援 StrongBox 的裝置另有 `[StrongBox]` 段，`keyMintSecurityLevel=StrongBox`，`strongBoxBacked=true`。
  - 憑證鏈每一層簽章驗證 OK，沒有任何序號出現在 Google 撤銷清單（`revoked=false`）。
  - `sign` 與 `verify=true`，並記錄簽章耗時。
- 判定：
  - 通過：TEE 段全部符合；有 StrongBox 時 StrongBox 段也全部符合。
  - 部分：`keyMintSecurityLevel=Software`（裝置只有軟體 keystore），正式 App 需走兜底並標示降級。
  - 失敗：challenge 不符、鏈驗證失敗、出現撤銷序號或簽章驗證失敗。
- 補充：把 `root SPKI sha256` 與 Google 公布的硬體證明根憑證比對（https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate）；不一致代表非 Google 認證裝置或自訂 ROM，D4 可能出現此情況，記為資訊。

### T04 TWDIW 連線與 Cloudflare（A3）

- 前置：分別在三種網路各跑一次：家用或辦公室 Wi-Fi、行動網路（中華電信、台灣大哥大、遠傳擇所有可取得者）、手機熱點以外的公共 Wi-Fi（可選）。只需在 App 內點 A3 重跑即可。
- 預期：每個端點兩行（okhttp、urlconn），分類為 `OK`。POST token 應回 HTTP 400 與 `resp_code`（11001 類）而不是 1010。
- 判定：
  - 通過：10 行全為 `OK`。
  - 失敗：任一行出現 `BLOCKED_1010`（UA 或 TLS 指紋被擋）或 `BLOCKED_WAF`；記錄是哪個用戶端、哪個網路。
  - `www.wallet.gov.tw` 在台灣網路應為 `OK`；若為 `BLOCKED_WAF` 代表連一般瀏覽也會被擋，記錄 cf-ray。
- 用途：決定正式 App 是否需要自訂 User-Agent 或特定 TLS 設定（規劃風險「Cloudflare 阻擋」）。

### T05 簽章函式庫在 ART（A4）

- 預期：6 個類別全部 `load ... OK`、`CAdESService instance OK`、`SESeal v4 parsed esID=...`。
- 判定：全部 OK 為通過；任何 `NoClassDefFoundError`、`VerifyError` 為失敗，請附完整記錄。這決定 Android 端是否可直接用 DSS 的 CAdES 簽章模組與 ofdrw 的印章解析。

### T06 錢包核心流程（C1 至 C3）

- 預期：C1 mdoc、C2 SD-JWT VC、C3 OpenID4VP + DCQL 皆 `PASS`（C2、C3 帶 gap 註記屬正常，表示已知的 Multipaz 安全缺口仍存在）。
- 判定：任何 `FAIL` 或 `EXCEPTION` 為失敗。

### T07 ZK、SM2、時戳與效能（C4 至 C6）

- 預期：
  - C4：兩組屬性的 `prove` 與 `proof VERIFIED`；完整 mDL 因 `MDOC_PROVER_TAGGED_MSO_TOO_BIG` 失敗屬預期。記錄 prove 毫秒、verify 毫秒、`heapUsed`。
  - C5：`ok=true tamperRejected=true`。
  - C6：DigiCert、Sectigo 兩行 `imprintOk=true`。
- 判定：
  - C4 通過條件：arm64 裝置證明成功且單次 prove 在 10 秒內；超過 10 秒記為效能不足。32 位元裝置（D5）載入 `libzkp.so` 失敗屬預期，正式 App 需隱藏或降級 ZK。
  - C5、C6 任何失敗為失敗；C6 失敗先確認網路可連 http://timestamp.digicert.com。
- 效能紀錄：把每台裝置的 C1、C4、C5、A2 sign 耗時填入第 9 節效能表，與容器桌面基準比較（C4 prove 約 1.5 秒、verify 約 0.7 秒）。

### T08 release 版回歸

- 步驟：`./scripts/run-auto.sh apk/diw-smoke-0.1.1-release.apk`。
- 判定：結果與 debug 版相同為通過；任何 debug 通過而 release 失敗的項目，記錄錯誤（通常是 R8 移除反射用到的類別）。

## 2. 需人工的 diw-smoke 項目

### T09 生物辨識綁定金鑰（M1，需人工）

- 前置：已註冊至少一枚 Class 3 生物特徵（T02 顯示 `STRONG=0`）。
- 步驟：
  1. 開啟 App，點「M1 Biometric-bound key sign」。
  2. 出現生物辨識提示時用已註冊的指紋或臉部通過。
  3. 再點一次 M1，這次在提示出現時按「Cancel」。
- 預期：第一次記錄 `OK unauthenticated sign rejected` 與 `authenticated sign verify=true authType=2`；第二次為 `biometric error 13`（使用者取消）並判定失敗。
- 判定：第一次 `PASS` 且第二次因取消而失敗，即通過（證明金鑰確實受生物辨識保護）。若第一次就出現 `FAIL signed without user authentication`，代表裝置未正確執行驗證綁定，為嚴重失敗。

### T10 NFC 自然人憑證卡探測（M2，需人工）

- 前置：內政部自然人憑證卡（若有不同世代，每張各測一次）、NFC 已開啟。**本測試不送 PIN，不會鎖卡。**
- 步驟：
  1. 點「M2 NFC IsoDep card probe」，30 秒內把卡片貼在手機背面 NFC 位置並保持不動。
  2. 換一個位置或角度再試一次；仍無反應則記錄「未偵測」。
  3. 同樣步驟測一張已知支援 NFC 的卡（悠遊卡或信用卡）作為對照。
- 預期：
  - 若卡片有非接觸介面：記錄 `techs=IsoDep,...`、`historicalBytes`，以及每個 SELECT 的 `SW`（9000 表示成功，6A82 表示檔案不存在）。
  - 若卡片只有接觸介面：等待逾時 `FAIL (no tag)`，而對照卡可偵測。
- 判定：
  - 對照卡偵測得到、自然人憑證卡偵測不到：判定「此卡無 NFC 介面」，正式 App 走 USB OTG + CCID 讀卡機路線。
  - 自然人憑證卡出現 IsoDep：判定「有非接觸介面」，請上傳完整記錄，後續依 SW 結果設計 APDU 流程。
  - 對照卡也偵測不到：手機 NFC 有問題，換裝置重測。

### T11 USB 讀卡機可用性（可選，需人工）

- 前置：支援 USB OTG 的手機、USB CCID 讀卡機、OTG 轉接頭。
- 步驟：插上讀卡機，執行 `adb shell dumpsys usb` 與 `adb shell lsusb`（若有），記錄讀卡機 VID/PID 與介面類別。
- 預期：裝置列出介面類別 0x0B（Smart Card）。
- 判定：列得出 0x0B 即硬體路線可行；APDU 層需等正式 App 實作 CCID 後再測。

## 3. 近場與系統整合（以 Multipaz TestApp 為基準）

這些功能在 diw-smoke 尚未實作，先用與本專案同版 SDK 的 Multipaz TestApp 驗證裝置與 SDK 是否可行，正式 App 完成後以相同步驟重測。

### T12 ISO 18013-5 近場出示：QR + BLE（P1，需人工、需兩支手機）

- 前置：D1 安裝 TestApp blue（持有端），D6 安裝 TestApp red（讀取端）；兩機藍牙與定位權限開啟。
- 步驟：
  1. 持有端在 TestApp 的文件列表加入測試 mDL（TestApp 內建「Provision test documents」或同等選項）。
  2. 持有端進入出示畫面顯示 QR code。
  3. 讀取端選擇讀取 mDL（例如年齡驗證請求），掃描 QR。
  4. 持有端確認同意畫面並以生物辨識或 PIN 同意。
  5. 在 TestApp 設定中分別切換 BLE「central client」與「peripheral server」模式各測一次。
- 預期：讀取端顯示文件資料與驗證結果（簽章有效）；從掃描到顯示的時間記錄下來。
- 判定：兩種 BLE 模式皆成功、整體時間 10 秒內為通過；只有一種模式成功記為部分並註明。

### T13 ISO 18013-5 近場出示：NFC 交握（P1，需人工、需兩支手機）

- 前置：同 T12，兩機 NFC 開啟，持有端不需先開出示畫面。
- 步驟：讀取端開始讀取，兩支手機背對背輕觸；持有端出現同意畫面後同意。
- 預期：NFC 交握後轉 BLE 或 NFC 資料傳輸，讀取端顯示結果。
- 判定：成功即通過；記錄是否需要先解鎖持有端、是否需要先開啟 App（HCE 前景或背景）。

### T14 Credential Manager 與 DC API（P2，需人工）

- 前置：D1（Android 14 以上、有 GMS）、Chrome 穩定版、TestApp blue 已有測試文件；D4 也跑一次作為無 GMS 對照。
- 步驟：
  1. 在手機 Chrome 開啟 https://digital-credentials.dev/ ，選擇要求 mDL 或 PID 的範例請求並送出。
  2. 系統跳出憑證選擇畫面時，確認列出 TestApp 的文件，選擇並同意。
  3. 另以 https://verifier.eudiw.dev/ 選擇 DC API 流程再測一次。
- 預期：出現 Android 系統的憑證選擇器（非 App 內畫面），網頁取得結果；選擇器顯示請求網站的 origin。
- 判定：D1 兩個網站皆成功為通過；D4 無選擇器屬預期，記錄為「無 GMS 時需走 App 內掃碼兜底」。

### T15 HCE 背景出示行為（可選，需人工）

- 步驟：在 T13 中分別測持有端 App 在前景、背景、手機鎖定三種狀態。
- 判定：記錄每種狀態是否可完成；鎖定狀態可完成但需先解鎖驗證屬正常。

## 4. TWDIW 對照

### T16 官方皮夾基準（需人工）

- 前置：官方「數位憑證皮夾」App、自然人憑證或其他可領取的卡。
- 步驟：用官方 App 領一張卡，記錄 offer QR 內容（截圖或用其他 App 掃出文字）、領卡耗時、出示時的畫面流程。
- 判定：資訊項目，作為第三方錢包相容性的對照基準；QR 內容請上傳以便比對 `modadigitalwallet://` 格式。

### T17 TWDIW 沙盒端到端（N1，需使用者帳號）

- 前置：使用者在 https://issuer-sandbox.wallet.gov.tw 與 https://verifier-sandbox.wallet.gov.tw 註冊並啟用帳號，取得 Access-Token。
- 步驟：把兩組 Access-Token 提供到本專案對話串（不要寫進共用檔案），由測試串以 JVM 持有端執行 DWVC-101 發卡與 DWVP-01 出示。
- 判定：發卡、驗章、出示全通過為通過；記錄任何 11007、11016 或其他錯誤碼。

## 5. 兜底與跨平台

### T18 無 GMS 裝置（D4）

- 步驟：在 D4 執行 T01 至 T10。
- 預期：A1 顯示 `gms=absent`；A2 可能沒有 Google 根憑證或沒有 StrongBox；C1 至 C6 應全部通過。
- 判定：C1 至 C6 通過即兜底路線可行；A2 的差異記錄為降級標示依據。

### T19 桌面兜底（Windows、macOS）

- 前置：JDK 21、Gradle 8.14.3；Windows 在 PowerShell 先執行 `chcp 65001` 並設定 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`。
- 步驟：在 `validation/android-smoke` 目錄執行 `gradle :composeApp:run --args="--headless"`。
- 預期：C1 至 C6 全部 PASS，最後印出 `export:` 檔案路徑。
- 判定：全部通過即該作業系統兜底可行；記錄 C4 耗時。Linux x86_64 已在雲端容器通過。

### T20 Linux 手機（可選）

- 前置：postmarketOS 或 Mobian 等 aarch64 Linux 手機、JDK 21。
- 步驟：同 T19。
- 判定：C1 至 C3、C5、C6 通過即核心可行；C4 若因無 linux-aarch64 原生庫失敗，記錄錯誤訊息，ZK 在該平台標示降級。

## 6. 結果總表（每台裝置一份）

| 項目 | D1 | D2 | D3 | D4 | 備註 |
|---|---|---|---|---|---|
| T03 金鑰證明 TEE |  |  |  |  |  |
| T03 StrongBox |  |  |  |  |  |
| T04 TWDIW Wi-Fi |  |  |  |  |  |
| T04 TWDIW 行動網路 |  |  |  |  |  |
| T05 DSS/ofdrw on ART |  |  |  |  |  |
| T06 C1-C3 |  |  |  |  |  |
| T07 C4 ZK |  |  |  |  |  |
| T07 C5 SM2 / C6 TSA |  |  |  |  |  |
| T08 release 回歸 |  |  |  |  |  |
| T09 生物辨識 |  |  |  |  |  |
| T10 自然人憑證 NFC |  |  |  |  |  |
| T12 BLE 出示 |  |  |  |  |  |
| T13 NFC 交握 |  |  |  |  |  |
| T14 DC API |  |  |  |  |  |

## 7. 效能表

| 裝置 | A2 TEE sign ms | A2 StrongBox sign ms | C1 ms | C4 prove ms | C4 verify ms | C4 heapUsed | C5 ms |
|---|---|---|---|---|---|---|---|
| 雲端桌面基準（x86_64 JVM） | - | - | 538 | 約 1500 | 約 740 | - | 160 |
| D1 |  |  |  |  |  |  |  |
| D2 |  |  |  |  |  |  |  |
| D3 |  |  |  |  |  |  |  |

## 8. 本清單未涵蓋、待正式 App 才能測的項目

- 生物辨識新增指紋後金鑰失效（`setInvalidatedByBiometricEnrollment`）：需要保留金鑰跨次執行，diw-smoke 每次會刪除。
- 錢包自己的 HCE 服務、Credential Manager 註冊、OpenID4VCI 領卡畫面與 deep link（`openid-credential-offer://`、`openid4vp://`、`haip-vp://`、`modadigitalwallet://`）。
- 自然人憑證 APDU 簽章流程與 PIN 錯誤次數保護。
- Play Integrity 與錢包提供者 key attestation（EUDI 發行端要求 iso_18045_high）。
- iOS（Compose Multiplatform iOS 目標、Secure Enclave、App Attest）。

## PR #11 新增回歸項目（2026-10-16）

- [ ] 使用可信任的 Wallet Provider 與註冊用戶端在公開 OpenID4VCI 發證端成功取得憑證；檢查 PAR、Token、DPoP nonce 與 Attestation Challenge。
- [ ] DC API `openid4vp-v1-multisigned`：有效與偽造簽章混合、Origin 綁定、多受信任身分選擇、重放與簽章降級拒絕。
- [ ] CSC OAuth：`redirect_uri` 替換、HTTPS／Bearer Token、SAD 與 RSA／ECDSA SHA-256 簽章在不同測試服務端互通。
- [ ] TW FidO：持 SP 測試資格時測試 Push／App-to-App、逾時、取消、checksum、簽署憑證與原文驗證。
- [ ] 個人錢包不必取得正式機關公文交換帳號；僅驗證 SI／DI、公文封裝、CAdES／XAdES、匯入／匯出可互通。

### VICAL／RICAL 實機與更新檢查

- [ ] 匯入僅用於「清單發行者」的受信任根憑證，再由 HTTPS 匯入實際簽章 VICAL／RICAL；確認未信任根與過期清單被拒絕。
- [ ] 驗證 vical `docType`、rical `isTrustAnchor` 限制、簽發者換鑰、清單單調遞增版本與線下緩存的安全行為。
- [ ] Android App Links 本輪不規劃，維持現有 URI Scheme 與 DC API 路由回歸測試。

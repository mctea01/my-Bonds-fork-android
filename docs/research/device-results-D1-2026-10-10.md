# 實機結果：D1 Xiaomi 25010PN30G（2026-10-10）

> **實機歷史紀錄。** 保留當日裝置、測試條件及結果；該次實測不可視為 2026-10-16 PR #11 最新版本已通過。最新功能與尚待實機驗收項目見 [2026-10-16 狀態矩陣](../status-2026-10-16.md)。

原始記錄：`專案共用資料夾 validation/device-results/D1-xiaomi-25010PN30G/`（debug 自動、release 自動、手動 M1/M2 各一份）。

裝置：Xiaomi 25010PN30G（xuanyuan），Android 16（SDK 36），HyperOS 3.0.301.0.WOATWXM，安全性修補 2026-05-01，僅 arm64-v8a。使用者說明此機已 root 並使用 Play Integrity Fix（PIF）。

## 判定總表

| 項目 | debug | release | 判定 |
|---|---|---|---|
| A1 裝置能力 | INFO | INFO | StrongBox、KeyMint 300、app_attest_key、HCE、BLE、credentials、usb.host 皆有；identity_credential 無；GMS 26.37 |
| A2 金鑰證明 TEE | PASS | 鏈不同（見下） | 金鑰功能正常；證明內容在 root 機上不可信 |
| A2 StrongBox | PASS | 測試程式錯誤 | release 失敗為 SQLITE_READONLY_DBMOVED，0.1.1 已修 |
| A3 TWDIW 連線 | PASS 10/10 | PASS 10/10 | 台灣網路（cf-ray TPE）OkHttp 與 HttpURLConnection 皆未被擋，www.wallet.gov.tw 也可開 |
| A4 DSS/ofdrw on ART | 5/6 | 5/6 | 失敗那一項是測試程式寫錯類別名稱；CAdESService 實例化與 GB/T 38540 印章解析在 ART 上成功 |
| C1-C3 | PASS | PASS | Multipaz 核心流程在 ART 正常，5 個已知安全缺口依舊存在 |
| C4 ZK | PASS | PASS | prove 約 0.8 秒、verify 約 0.39 秒，比雲端桌面快；峰值 RSS 約 1.05 GB |
| C5 SM2 | PASS | PASS | BC 1.85 在 ART 正常 |
| C6 TSA | PASS | PASS | DigiCert、Sectigo |
| M1 生物辨識 | - | PASS | 未驗證時簽章被拒，生物辨識後簽章成功（authType=2） |
| M2 NFC | - | FAIL | 測試程式錯誤：取得卡片後立即關閉 reader mode，連線被切斷；0.1.1 已修 |

## 重要發現

### 1. root 機的金鑰證明可被偽裝

同一支手機三次執行（debug 自動、release 自動、release 安裝後的手動執行）得到兩種不同的 TEE 證明鏈，與建置類型無關：

- debug 自動與手動執行：4 張憑證，根為舊版 Google RSA 根（序號 f1c172a699eaf51d），`deviceLocked=true`、`verifiedBootState=Verified`、`osPatchLevel=202610`。建金鑰約 300 ms。
- release 自動執行：5 張憑證，經 RKP（Remote Key Provisioning）的 `Droid CA3`、`Droid CA2`，根為 `Key Attestation CA1`，`deviceLocked=false`、`verifiedBootState=Unverified`、`osPatchLevel=202605`。建金鑰 51 ms。

RKP 那條鏈顯示的才是裝置真實狀態（已解鎖、修補到 2026-05）。另一條鏈【推論】是 root 模組以外洩的 keybox 重新簽發，且這些序號目前不在 Google 撤銷清單（1759 筆）中，鏈的簽章也全部有效。

使用者決定（2026-10-10）：不特別檢查 RKP，多數情況只需確認金鑰有效（證明鏈簽章有效、challenge 相符、不在撤銷清單、金鑰可簽驗）。

對規劃的影響：

- 錢包預設以「金鑰有效」為準，不把 RKP 或裝置鎖定狀態當作拒絕條件。
- 證明內容（鎖定狀態、修補等級）在 root 機上可能被偽裝，只作為資訊或風險提示，不作為安全保證。
- 若特定發行端（如 EUDI 要求 iso_18045_high）自行要求更嚴格的裝置證明，由該發行端判定，錢包照實提交即可。

### 2. Cloudflare 在台灣網路下沒有阻擋

A3 在台灣網路（Cloudflare 台北節點）用真實的 Android TLS 堆疊跑，OkHttp（`okhttp/4.12.0`）與 HttpURLConnection（`Dalvik/2.1.0`）的 10 個請求全部成功，連雲端被擋的 www.wallet.gov.tw 也正常。Bonds 記錄的 1010 在本機未重現；規劃風險可降級為「持續監測」，正式 App 不需偽裝 User-Agent。

### 3. 簽章函式庫在 ART 上可用

- `CAdESService` 可在 ART 上實例化，ofdrw 的 `OFDValidator`、`SESeal`、`PKCS12Tools` 可載入，GB/T 38540 v4 印章（SM2 簽章演算法 1.2.156.10197.1.501）在手機上解析成功。
- debug 與 release（R8）結果一致，排除 xpp3 後 R8 沒有破壞這些路徑。

### 4. ZK 效能

| 指標 | D1 | 雲端桌面基準 |
|---|---|---|
| prove（含出示） | 801 ms、822 ms | 約 1500 ms |
| verify | 398 ms、383 ms | 約 740 ms |
| 證明大小 | 約 360 KB | 約 360 KB |
| 峰值 RSS | 約 1.05 GB | 約 398 MB（JVM 另計） |

峰值記憶體偏高，低階機（D3）需確認是否會被系統終止。

## 0.1.1 重跑（20:32 至 20:35）

- A1 至 A4、C1 至 C6 全部 PASS（A4 6/6，StrongBox 在 release 版也通過），M1 PASS。
- C4：prove 500 至 553 ms、verify 約 265 ms、峰值 RSS 約 0.8 GB。
- A2 這次 TEE 與 StrongBox 都回到 RSA 根的鏈（Verified、已鎖定）。

### M2 自然人憑證卡（NFC）

- **卡片有非接觸介面**：偵測到 `IsoDep, NfcA`，UID 7 位元組（已遮蔽），historicalBytes `0031C16408402230009000`，支援 extended APDU，maxTransceive 65279。
- 回應：SELECT MF（P2=00 與 0C）與 SELECT EF.DIR 皆 `6A86`（P1/P2 不正確）、PKCS#15 AID `6A82`（找不到）、READ BINARY `6E00`（不支援的 CLA，推論需先選定應用）。
- 結論：可以走 NFC 路線，不必只靠 USB 讀卡機；下一步是找出卡片的應用 AID。0.1.2 新增唯讀探測（預設應用 FCI、CPLC、GlobalPlatform ISD AID、其他 SELECT 編碼），仍不送 PIN。

### M2 第二輪（0.1.2，20:41）

- 預設應用與 `SELECT A000000151000000` 都回 9000，FCI 為 GlobalPlatform Issuer Security Domain：標籤 73 內含 GP OID 1.2.840.114283.1 與 1.2.840.114283.2.2.2.1（GlobalPlatform 2.2.1）。
- `GET DATA 9F7F`（CPLC）CLA 80 與 00 都回 9000：IC 製造商代碼 4790（NXP），IC 類型 6B48，OS ID 8231。【推論】這是 NXP 晶片上的 GlobalPlatform Java Card，MOICA 憑證應用是另一個需以 AID 選取的 applet，不是預設應用。
- 舊版 GP AID `A000000003000000` 回 6A82，GET RESPONSE 回 6D00，屬正常。
- 列出卡上 applet（GET STATUS）需要 GP 安全通道金鑰，不可行；需要從自然人憑證中介軟體或開源實作（如 open-gpki-pkcs11，LGPL-2.1+）取得 applet AID 與 APDU 流程。雲端環境無法存取該 GitHub repo。

## 待補

- 已完成 NFC 唯讀讀取憑證（0.1.3）；簽章與 PIN 驗證留待正式實作並加上錯誤次數保護。
- 其他裝置（D2 至 D5）由使用者稍後補測。
- 近場出示（T12、T13）、DC API（T14）尚未執行。

## 0.1.3：自然人憑證唯讀讀取（20:52，PASS）

- 依 open-gpki-pkcs11（LGPL-2.1+，只參考 AID 與指令流程，未複製程式碼）：二代卡憑證應用 AID 為 `A0000002830000062201696400010101`，以 `00 A4 04 0C 10 <AID> 00` 選取；之後 `00 A4 00 04 02 <FID> 00` 選檔、`00 B0` 讀檔，憑證明文存放，讀取不需 PIN 或安全通道。一代卡則以 CLA 80 或 00 選 MF `3F00`。
- 讀取流程：AID 後選 `5030`（PKCS#15 DF）、讀 CDF `4104`，依其中路徑讀出每張憑證，並讀版本 `0900/0905` 與卡號 `0900/0903`。
- 記錄中姓名（CN）、serialNumber 與卡號只保留首字或末 4 碼，其餘遮蔽；另記發行者、效期、金鑰、KeyUsage、SHA-256。
- 只送 SELECT 與 READ BINARY，不送 VERIFY，也不建立 SCP03（簽章與 PIN 需要的金鑰分散流程留待正式實作評估）。
- APK：`validation/android-smoke/apk/diw-smoke-0.1.3-release.apk`，新增原始碼 `GpkiCard.kt`。

### 0.1.3 結果（20:52）

- M2 PASS：二代卡（版本 `CHT V32N`），不送 PIN 讀出 CDF 列出的 4 張憑證，整體約 1.6 秒（含點卡約 3.1 秒）。
- 憑證：GRCA 根（RSA 4096，至 2037）、內政部憑證管理中心 MOICA（RSA 2048，至 2034）、使用者簽章憑證 cert1（keyUsage=digitalSignature）、使用者加密憑證 cert2（keyEncipherment|dataEncipherment），皆為 SHA256withRSA。
- 四張憑證的 CDF 路徑都是 `7FFF/5030/08F2`，以 index 區分位置。
- 結論：NFC 讀自然人憑證可行，錢包可直接在手機上取得憑證鏈（GRCA、MOICA、使用者）作身分與簽章驗證；簽章需 PIN 與 SCP03 金鑰分散，屬下一階段，須加上錯誤次數保護並注意 open-gpki-pkcs11 為 LGPL。
- 原始記錄：`validation/device-results/D1-xiaomi-25010PN30G/manual-0.1.3-nfc-20261010-205236.txt`（姓名、身分證欄位、卡號已遮蔽）。

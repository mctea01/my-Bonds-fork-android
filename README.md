# DIW MY WALLET

跨平台整合數位皮夾，以 [Multipaz](https://github.com/openwallet-foundation/multipaz)、台灣數位憑證皮夾（TWDIW）、EUDI Wallet、Microsoft Entra Verified ID 與 Bonds 的公開實作為參考，目標涵蓋數位憑證、電子簽章、身分認證、文件保存與電子公文。

目前先交付 Android，UI 以 Compose Multiplatform 撰寫，同一份程式也建置 Windows 與 Linux 桌面版。

## 功能

### 標準協議（預設全部啟用）

| 類別 | 支援內容 |
|---|---|
| 發證 | OpenID4VCI 1.0，以及 draft 11/12、draft 13 發證端；pre-authorized code（含 tx_code / user_pin）、authorization code（PKCE、PAR）、DPoP、wallet attestation、批次與延遲發證、回應加密 |
| 憑證格式 | ISO mdoc（mso_mdoc）、SD-JWT VC（dc+sd-jwt、vc+sd-jwt）、W3C VC（jwt_vc_json、jwt_vc_json-ld、ldp_vc）、包在 SD-JWT 中的 W3C VC |
| 出示 | OpenID4VP 1.0（DCQL、DC API），以及 draft 13 到 23（Presentation Exchange 2.0、client_id_scheme、did / x509_san_* client）、SIOPv2、OAuth fragment / query / form_post 回應 |
| 遠端 mdoc | ISO 18013-7 Annex B（OpenID4VP 草案的 mdoc handover）；ISO 18013-5 近距離（QR／NFC 交握、BLE）尚未實作，介面已預留入口 |
| 信任 | X.509 信任錨（正式與測試環境分開顯示）、DID（did:key、did:jwk、did:web）、DIF Linked Domains、TWDIW 信任清單與 Arbitrum 錨定 |
| 狀態 | IETF Token Status List、W3C Bitstring Status List、Status List 2021、Revocation List 2020，顯示規格原文狀態 |

### 介面

介面以 EUDI Wallet 與 Bonds 的設計為準：所有證件在同一份清單，各發行端與 Profile 的功能併入共同的流程，不另開專區。

| 分頁 | 內容 |
|---|---|
| 證件 | 所有證件同一份清單，依身分證件、政府皮夾卡片、組織與會員卡、其他證件分組，可搜尋與篩選；右上「+」從清單選擇或掃描 QR Code 加入 |
| 文件 | 簽章文件與檔案、電子公文（個人公文接收站）、MyData 資料保險箱的保留區域，後續版本啟用 |
| 使用 | 出示我的證件（掃描後依內容自動分流：OpenID4VP、數位憑證皮夾、Bonds 挑戰、靜態 QR）、臨櫃出示（超商取貨等條碼）、加入證件、貼上連結 |
| 查驗 | 以 Bonds 離線挑戰查驗他人證件；查驗方身分、線上查驗（OpenID4VP）、NFC 感應與零知識證明查驗先保留入口，詳細設計後續實作 |
| 紀錄 | 領取、出示、拒絕與查驗的對象、時間、證件與欄位名稱，不保存欄位內容 |

右上齒輪進入設定：金鑰保護、信任清單（數位憑證皮夾公布的發行端與查驗方、Arbitrum 錨定）、紀錄清除、互通設定與測試環境。

「從清單選擇」列出數位憑證皮夾可申請的卡片，也可輸入任一 OpenID4VCI 發行端網址。以 NFC 讀取自然人憑證實體卡、Bonds 的文件與自然人憑證自簽卡（vc+moica，P5）已在介面預留入口。

### 相容處理（常駐啟用，不需開關）

- **數位憑證皮夾（TWDIW）官方流程**：`modadigitalwallet://` 與 wallet.gov.tw 連結、發證（client_id `moda_dw`、did:key jwk_jcs 持有者）、出示（含靜態 QR 自訂欄位）、可申請卡片目錄、7-ELEVEN 等離線條碼（DWVP-05）。卡片與其他證件在同一份清單。
- **TWDIW 信任清單**：每個機關的 DID 文件簽章與 Arbitrum One 鏈上登記；測試環境（UAT、sandbox）只在開啟測試環境後才計入。
- **Bonds 離線出示**：掃描 Bonds 查驗方的 JSON QR，以輪播 QR（BTWVP1）或藍牙（手機作為 GATT 周邊）出示 TWDIW 卡片；也可在「查驗」分頁作為查驗方，掃描對方的輪播 QR 驗證。
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
```

Windows 的 PowerShell 請先執行 `chcp 65001` 並設定 `$env:JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"`，避免中文輸出亂碼。

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

## 授權

見 [LICENSE](LICENSE)。

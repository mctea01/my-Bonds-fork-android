# P2 驗收結果（2026-10-11）

分支 `claude/p2-oid4vc-twdiw-k9xocz`。P2 完成後所有 OpenID4VCI / OpenID4VP 組合皆可使用，TWDIW、Bonds、OpenID4VCI 草案 11/13 與 Microsoft Verified ID 的處理常駐啟用、沒有開關，程式碼與標準路徑隔離。

## 本地自動測試

| 範圍 | 指令 | 結果 |
|---|---|---|
| TWDIW 官方平台（以 MockEngine 模擬 `*.wallet.gov.tw`）：`modadigitalwallet://` 發證、did:key jwk_jcs 持有者、moda_dw、StatusList2021 撤銷與停用、信任清單、出示只揭露要求欄位、自訂欄位、DWVP-05 離線條碼、Cloudflare UA | `:test-servers:test --tests '*TwdiwPlatformTest'` | RESULT_TWDIW |
| Bonds 離線出示：JSON 挑戰、輪播 QR（ECC Q）、BLE 分幀、查驗端驗證、挑戰不符拒絕、自簽卡提示 P5 | 同上（`bondsOfflinePresentationOverQrAndLink`） | 含在上列 |
| Microsoft Entra Verified ID 發行：簽章合約、id_token_hint、PIN 雜湊、自填欄位、Linked Domains（T3）、網域連結失效（T4）、callback | `:test-servers:test --tests '*MsVerifiedIdTest'` | RESULT_MS |
| OpenID4VCI 草案 11/12（credentials_supported、user_pin、metadata 內 token_endpoint）與草案 13（token 回應 c_nonce、被拒後改用 format 請求） | `:test-servers:test --tests '*DraftIssuersTest'` | RESULT_DRAFT |
| P1 既有測試（OpenID4VP 1.0、OpenID4VCI 1.0、Multipaz 互通、QR 編碼、欄位語系、網址政策） | `:test-servers:test` | RESULT_ALL |
| App 共用模型 | `:app:desktopTest` | RESULT_DESKTOP |
| Android release APK | `:app:assembleRelease`（R8） | RESULT_RELEASE |

## 對外互通（需網路，`DIW_INTEROP=1 ./gradlew :test-servers:test --tests '*InteropTest'`）

RESULT_INTEROP

## P2 中發現並已修正

1. OpenID4VP 草案的 DID client（`client_id` 為 `did:key:...`）原本被去掉 `did:` 前綴後再解析，任何 DID 簽章的要求物件都會被拒（kid does not reference the client DID）。TWDIW 與 Bonds 驗證端都用 did:key client，已修正並由 TWDIW 出示測試涵蓋。
2. 草案 11/12 發證端要求 `user_pin`，原本只送 1.0 的 `tx_code`。草案 11 方言改為同時送出。
3. 舊的「jku 取得簽章金鑰」測試已改為驗證錢包拒絕只能透過 jku 取得金鑰的憑證；TWDIW 實際的 iss did:key 由新的平台測試涵蓋。

## 需要實機驗證

| 項目 | 步驟 | 預期 |
|---|---|---|
| TWDIW 正式發證 | 在數位憑證皮夾的發行端網頁產生 QR，用本 App 掃描 | 顯示發行機關名稱與 T1（Arbitrum 已驗證）或 T2；卡面顯示發行端 logo 與顏色 |
| TWDIW 正式出示 | 以政府驗證端（如臨櫃服務）的 QR 出示 | 驗證端顯示成功；同意畫面只列要求欄位 |
| 靜態 QR 自訂欄位 | 掃描需要填寫欄位的靜態 QR | 欄位依 regex 檢查，送出後驗證端收到 |
| 7-ELEVEN 取貨條碼 | 台灣數位憑證頁的「臨櫃與線上出示服務」選 7-ELEVEN | 出示後顯示伺服器產生的條碼與倒數，螢幕保持常亮並調高亮度 |
| Cloudflare 1010 | 若出現 1010 或 403，到設定的 TWDIW 區塊改 User-Agent | 改用其他 UA 後可連線 |
| 信任清單與 Arbitrum | 開啟「數位憑證皮夾信任清單」，按重新整理 | 各組織顯示鏈上狀態；離線時顯示快照時間 |
| Bonds 藍牙 | Bonds iOS 查驗方產生挑戰，本 App 掃描後選「藍牙傳送」 | 第一次要求「附近的裝置」權限；傳送完成後對方顯示驗證結果 |
| Bonds 輪播 QR | 同上改用輪播 QR | 對方掃描完成並驗證 |
| 本 App 作為 Bonds 查驗方 | 「自行查驗他人出示」產生挑戰，以另一台手機的 Bonds 出示 | 顯示出示者 DID、揭露欄位與發行端信任 |
| Microsoft Entra Verified ID | 以 Entra 租戶的發行 QR（`openid-vc://`）領卡，含 PIN 或登入 | 顯示網域與 T3；領卡後到 Verified ID 驗證端出示成功 |
| UAT 平台 | 設定開啟測試環境並把 TWDIW 前端改為 UAT | 頁面標示「測試平台（結果不具效力）」，信任等級為測試環境 |

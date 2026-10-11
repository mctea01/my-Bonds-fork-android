# P2 驗收結果（2026-10-11）

分支 `claude/p2-oid4vc-twdiw-k9xocz`。P2 完成後所有 OpenID4VCI / OpenID4VP 組合皆可使用，TWDIW、Bonds、OpenID4VCI 草案 11/13 與 Microsoft Verified ID 的處理常駐啟用、沒有開關，程式碼與標準路徑隔離。

## 本地自動測試

| 範圍 | 指令 | 結果 |
|---|---|---|
| TWDIW 官方平台（以 MockEngine 模擬 `*.wallet.gov.tw`）：`modadigitalwallet://` 發證、did:key jwk_jcs 持有者、moda_dw、StatusList2021 撤銷與停用、信任清單、出示只揭露要求欄位、自訂欄位、DWVP-05 離線條碼、Cloudflare UA | `:test-servers:test --tests '*TwdiwPlatformTest'` | 5/5 通過 |
| Bonds 離線出示：JSON 挑戰、輪播 QR（ECC Q）、BLE 分幀、查驗端驗證、挑戰不符拒絕、自簽卡提示 P5 | 同上（`bondsOfflinePresentationOverQrAndLink`） | 含在上列 |
| Microsoft Entra Verified ID 發行：簽章合約、id_token_hint、PIN 雜湊、自填欄位、Linked Domains（T3）、網域連結失效（T4）、callback | `:test-servers:test --tests '*MsVerifiedIdTest'` | 2/2 通過 |
| OpenID4VCI 草案 11/12（credentials_supported、user_pin、metadata 內 token_endpoint）與草案 13（token 回應 c_nonce、被拒後改用 format 請求） | `:test-servers:test --tests '*DraftIssuersTest'` | 2/2 通過 |
| P1 既有測試（OpenID4VP 1.0、OpenID4VCI 1.0、Multipaz 互通、QR 編碼、欄位語系、網址政策） | `:test-servers:test` | 全部 55 項通過（ClaimLabels 2、Oid4vciE2e 18、Oid4vpE2e 18、Multipaz 互通 5、QR 2、網址政策 1，加上上列 9 項）；InteropTest 9 項需 `DIW_INTEROP=1`，預設略過 |
| App 共用模型 | `:app:desktopTest` | 8 項：6 通過、2 項需網路而略過 |
| Android release APK | `:app:assembleRelease`（R8） | 建置成功，app-release.apk 約 21 MB，R8 產生 mapping.txt（縮減與最佳化已套用） |

## 對外互通（需網路，`DIW_INTEROP=1 ./gradlew :test-servers:test --tests '*InteropTest'`）

| 對象 | 結果 | 說明 |
|---|---|---|
| 數位憑證皮夾正式信任清單 frontend.wallet.gov.tw + Arbitrum One | 通過 | 以設定的 User-Agent 取得 50 筆組織（發行端 23、驗證端 27）；抽樣 3 筆的 DID 文件自簽有效、鏈上登記交易成功且 getDocById 內容一致，判定 T1。 |
| mashbean TWDIW 方言發證端 issuer.mashbean.net | 通過 | 預授權、token 回應 c_nonce、did:key 持有者、vc+sd-jwt 無 vct；領到學生證並讀出全部欄位，發行端金鑰來自 iss did:key（T3）。 |
| mashbean 驗證端 verifier.mashbean.net | 通過（要求驗證） | TWDIW（`modadigitalwallet://`）與 Bonds（`openid4vp://`，PE 加 DCQL）兩種連結都辨識為 TWDIW、驗證 did:key 簽章；錢包內沒有政府卡片，比對結果為 access_denied。實際出示需正式卡片，列入實機測試。 |
| walt.id、EUDI、Multipaz | 與 P1 相同 | walt.id SD-JWT VC 領卡成功；EUDI 驗證端要求驗證成功、發行端需 key attestation；Multipaz 發行端需其登錄的 client attestation CA。 |

## P2 中發現並已修正

1. **正式信任清單全部誤判為「與鏈上不符」（T4）。** 合約 getDocById 回傳的是一個 struct（開頭多一個 0x20 位移），原本直接當成欄位解析。修正後正式組織判定為 T1，已以對外互通測試確認。
2. **mashbean 發證端拒絕 proof（kid 不是 did:key）。** SD-JWT VC 等本身沒有 DID 的金鑰，原本一律用 did:jwk 命名；改為使用發行端列出的方法。
3. **官方出示要求從一般 `openid4vp://` 連結進入時未套用 TWDIW 方言。** 官方格式的 input descriptor 沒有 format，改以 did:key client 加上 client_metadata.vp_formats（jwt_vp / jwt_vc）辨識。
4. **TWDIW 狀態清單以 key-2 簽章（只公布在 jku），原本驗簽失敗變成「未知」。** 改為讀取位元並標示「未驗證」，不當成可信結果。
5. 同意畫面不再列出比對用的結構欄位（type、credentialSchema、credentialStatus 等）。
6. OpenID4VP 草案的 DID client（`client_id` 為 `did:key:...`）原本被去掉 `did:` 前綴後再解析，任何 DID 簽章的要求物件都會被拒（kid does not reference the client DID）。TWDIW 與 Bonds 驗證端都用 did:key client，已修正並由 TWDIW 出示測試涵蓋。
7. 草案 11/12 發證端要求 `user_pin`，原本只送 1.0 的 `tx_code`。草案 11 方言改為同時送出。
8. 舊的「jku 取得簽章金鑰」測試已改為驗證錢包拒絕只能透過 jku 取得金鑰的憑證；TWDIW 實際的 iss did:key 由新的平台測試涵蓋。

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

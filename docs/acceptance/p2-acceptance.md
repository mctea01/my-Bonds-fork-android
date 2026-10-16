# P2 驗收結果（2026-10-11）

分支 `claude/p2-oid4vc-twdiw-k9xocz`。P2 完成後所有 OpenID4VCI / OpenID4VP 組合皆可使用，TWDIW、Bonds、OpenID4VCI 草案 11/13 與 Microsoft Verified ID 的處理常駐啟用、沒有開關，程式碼與標準路徑隔離。

## 本地自動測試

| 範圍 | 指令 | 結果 |
|---|---|---|
| TWDIW 官方平台（以 MockEngine 模擬 `*.wallet.gov.tw`）：`modadigitalwallet://` 發證、did:key jwk_jcs 持有者、moda_dw、StatusList2021 撤銷與停用、信任清單、出示只揭露要求欄位、自訂欄位、DWVP-05 離線條碼、Cloudflare UA | `:test-servers:test --tests '*TwdiwPlatformTest'` | 5/5 通過 |
| Bonds 離線出示：JSON 挑戰、輪播 QR（ECC Q）、BLE 分幀、查驗端驗證、挑戰不符拒絕、自簽卡提示 P5 | 同上（`bondsOfflinePresentationOverQrAndLink`） | 含在上列 |
| Microsoft Entra Verified ID 發行：簽章合約、id_token_hint、PIN 雜湊、自填欄位、Linked Domains（T3）、網域連結失效（T4）、callback | `:test-servers:test --tests '*MsVerifiedIdTest'` | 2/2 通過 |
| OpenID4VCI 草案 11/12（credentials_supported、user_pin、metadata 內 token_endpoint）與草案 13（token 回應 c_nonce、被拒後改用 format 請求） | `:test-servers:test --tests '*DraftIssuersTest'` | 2/2 通過 |
| P1 既有測試（OpenID4VP 1.0、OpenID4VCI 1.0、Multipaz 互通、QR 編碼、欄位語系、網址政策） | `:test-servers:test` | 全部 59 項通過（ClaimLabels 2、Oid4vciE2e 18、Oid4vpE2e 18、Multipaz 互通 5、QR 2、網址政策 1、出示安全規則 4，加上上列 9 項）；InteropTest 9 項需 `DIW_INTEROP=1`，預設略過 |
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
4. **TWDIW 狀態清單以 key-2 簽章（只公布在 jku），原本驗簽失敗變成「未知」。** 改為讀取位元並標示「未驗證」，不當成可信結果。後續已改為以綁定發行端的 jku 金鑰驗簽，見 [p2-followup.md](p2-followup.md)。
5. 同意畫面不再列出比對用的結構欄位（type、credentialSchema、credentialStatus 等）。
6. OpenID4VP 草案的 DID client（`client_id` 為 `did:key:...`）原本被去掉 `did:` 前綴後再解析，任何 DID 簽章的要求物件都會被拒（kid does not reference the client DID）。TWDIW 與 Bonds 驗證端都用 did:key client，已修正並由 TWDIW 出示測試涵蓋。
7. 草案 11/12 發證端要求 `user_pin`，原本只送 1.0 的 `tx_code`。草案 11 方言改為同時送出。
8. 舊的「jku 取得簽章金鑰」測試已改為驗證錢包拒絕只能透過 jku 取得金鑰的憑證；TWDIW 實際的 iss did:key 由新的平台測試涵蓋。

PR 審查後再修正（`PresentationSafetyTest`）：

9. TWDIW 信任清單原本不分角色，只登錄為驗證端的機關簽發的憑證也會是 T1。改為必須在對應的一側（發行端 orgType 1、驗證端 2）登錄才是正式，否則為 T2。
10. 出示時會選到已過期的憑證。改為只提供有效期間內的憑證。
11. 草案 22/23 的 `x509_hash:` client 沒有比對葉憑證雜湊。改為與 1.0 相同的檢查。
12. Verified ID 合約指定可接受的發行端時，原本只比對憑證類型。候選清單與送出前都會檢查發行端。
13. Bonds 藍牙在 GATT service 建立完成前就開始廣播，查驗方太快連線會找不到 characteristic。改為等 `onServiceAdded` 成功後才廣播。

## 合併 main 與介面重整（2026-10-11）

分支 `claude/merge-conflict-ui-design-q5s134`：以 P2 為基礎合併 main（#2 release 簽章、#3 EUDI 發行端、#4 DC API 錯誤回傳），並依 EUDI Wallet 與 Bonds 的設計重整介面。

- 衝突處理：P2 的持有者金鑰與證明格式保留 main 的「發行端要求金鑰證明但沒有錢包提供者時仍送一般證明」；延遲發證（含草案 11 acceptance token）沿用原交易的回應加密金鑰；`EudiDialect` 併入常駐方言清單，移除 main 新增的「EUDI 相容模式」開關。
- 介面：取消「台灣數位憑證」專區。首頁改為證件、文件、使用、查驗、紀錄五個分頁；TWDIW 卡片與其他證件同一清單；卡片目錄移到「從清單選擇」，臨櫃條碼移到「使用」，信任清單移到設定，Bonds 查驗移到「查驗」。文件分頁與查驗方身分、線上查驗、NFC、零知識證明查驗為保留入口。
- 新增紀錄：領取、出示、拒絕、查驗各記一筆，只存欄位名稱。
- 實機回饋：遠傳門號卡（`97179430.wallet.gov.tw`）領卡時出現「credential_issuer in metadata does not match」。該發行端的中繼資料寫 `.../issuer/97179430`，領卡連結寫 `.../issuer/97179430/`，只差結尾斜線；OpenID4VCI 1.0 要求兩者相同，標準流程維持拒絕。新增方言 hook `IssuanceDialect.issuerIdentifier`，只有擁有該 session 的方言能放寬；TWDIW 方言只接受結尾斜線的差異，並沿用帶斜線的識別碼，token 端點為 `{識別碼}token`、proof `aud` 帶斜線，與 Bonds 相同。以 `TwdiwPlatformTest.issuerMetadataWithoutTrailingSlash` 重現並驗證，`InteropTest.twdiwTelecomIssuerMetadata` 對正式發行端確認。

| 範圍 | 指令 | 結果 |
|---|---|---|
| 協議與互通 | `:test-servers:test` | 76 項：64 通過、12 項需 `DIW_INTEROP=1` 略過 |
| 正式 TWDIW 發行端中繼資料（97179430） | `DIW_INTEROP=1 ... --tests '*twdiwTelecomIssuerMetadata'` | 通過：標準流程拒絕、TWDIW 方言接受，token 端點 `.../issuer/97179430/token` |
| App 共用模型（含紀錄寫入、重啟後讀回、清除，分頁返回順序） | `:app:desktopTest` | 9 項：6 通過、2 項需網路略過、截圖測試需 `DIW_SCREENSHOTS` |
| 主要畫面離屏截圖 | `DIW_SCREENSHOTS=<資料夾> ./gradlew :app:desktopTest --tests '*uiScreenshots'` | 12 張 PNG |
| Android | `:app:assembleDebug :app:assembleRelease`（R8） | 建置成功 |

## 需要實機驗證

| 項目 | 步驟 | 預期 |
|---|---|---|
| TWDIW 正式發證 | 在數位憑證皮夾的發行端網頁產生 QR，用本 App 掃描 | 顯示發行機關名稱與 T1（Arbitrum 已驗證）或 T2；卡面顯示發行端 logo 與顏色 |
| TWDIW 正式出示 | 以政府驗證端（如臨櫃服務）的 QR 出示 | 驗證端顯示成功；同意畫面只列要求欄位 |
| 靜態 QR 自訂欄位 | 掃描需要填寫欄位的靜態 QR | 欄位依 regex 檢查，送出後驗證端收到 |
| 7-ELEVEN 取貨條碼 | 「使用」分頁的「臨櫃出示」選 7-ELEVEN | 出示後顯示伺服器產生的條碼與倒數，螢幕保持常亮並調高亮度 |
| Cloudflare 1010 | 若出現 1010 或 403，到設定的「互通設定」改 User-Agent | 改用其他 UA 後可連線 |
| 信任清單與 Arbitrum | 設定中開啟「信任清單」，按重新整理 | 各組織顯示鏈上狀態；離線時顯示快照時間 |
| Bonds 藍牙 | Bonds iOS 查驗方產生挑戰，本 App 掃描後選「藍牙傳送」 | 第一次要求「附近的裝置」權限；傳送完成後對方顯示驗證結果 |
| Bonds 輪播 QR | 同上改用輪播 QR | 對方掃描完成並驗證 |
| 本 App 作為 Bonds 查驗方 | 「查驗」分頁產生查驗挑戰，以另一台手機的 Bonds 出示 | 判定卡顯示通過或注意，並列出出示者 DID、揭露欄位與發行端信任；「紀錄」新增一筆查驗 |
| 網頁完成後自動關閉 | 「從清單選擇」申請卡片、授權碼流程登入、Verified ID 登入 | 發行端頁面導回錢包後，網頁分頁自動關閉，返回鍵不會再回到該頁 |
| Microsoft Entra Verified ID | 以 Entra 租戶的發行 QR（`openid-vc://`）領卡，含 PIN 或登入 | 顯示網域與 T3；領卡後到 Verified ID 驗證端出示成功 |
| UAT 平台 | 設定開啟測試環境並把 TWDIW 前端改為 UAT | 頁面標示「測試平台（結果不具效力）」，信任等級為測試環境 |

## 2026-10-16 OpenID4VP 與 mdoc 信任清單補強（PR #11）

Digital Credentials API 新增 `openid4vp-v1-multisigned` 的 JWS JSON Serialization 解析、各簽名的受保護 `client_id`、獨立簽章／查驗者信任判定、`expected_origins` 檢查和簽章降級拒絕；測試增加有效、偽造、來源不符、缺少簽章等情境。

VICAL／RICAL 下載與匯入使用 COSE 驗簽和**分離的清單發行者信任根**，限 HTTPS，限制資料大小、禁止版本回退與跨環境信任升級，並管理 `nextUpdate`、`notAfter` 與使用者主動更新；RICAL 非信任錨點不作根憑證。需新增 `SignedMdocTrustListsTest` 驗證發行者不受信任、正常簽署清單、版本回退及到期。

本輪已增加 mdoc `transaction_data` 透過 Multipaz `TransactionType` 回應到 `DeviceSigned.nameSpaces`，於裝置簽署前檢查 MSO KeyAuthorizations；已加入允許／未授權兩種回歸測試。JWE Request Object 已建立以錢包自身 ECDH-ES 金鑰解密的核心路徑和身分綁定，但 App 尚缺解密金鑰註冊、發布與完整的簽章加密巢狀回應驗收。OpenID Federation Trust Chain 的信任錨與 Policy 驗證尚未實作；所有未完成路徑**保持明確拒絕**。Android HTTPS App Links 暫不規劃，不作本階段阻擋。

# P1 驗收結果（2026-10-10）

分支 `p1-standard-core`。所有測試以 `./gradlew` 執行，指令列於各節。

## 本地自動測試（不需網路）

| 範圍 | 指令 | 結果 |
|---|---|---|
| OpenID4VP 1.0 / DCQL 持有端與驗證層 | `:test-servers:test --tests '*Oid4vpE2eTest'` | 16/16 通過 |
| OpenID4VCI 1.0 用戶端、Token Status List | `:test-servers:test --tests '*Oid4vciE2eTest'` | 18/18 通過 |
| DIW 測試驗證端 對 Multipaz 錢包 SDK（uriSchemePresentment、digitalCredentialsPresentment） | `:test-servers:test --tests '*MultipazWalletInteropTest'` | 5/5 通過 |
| App 共用模型（預授權、授權碼經瀏覽器回跳、DC API origin 檢查、PIN 加密儲存） | `:app:desktopTest` | 4/4 通過 |
| Android APK | `:app:assembleDebug` | 建置成功（未在實機或模擬器執行） |

## 對外互通（需網路，`DIW_INTEROP=1 ./gradlew :test-servers:test --tests '*InteropTest'`）

| 對象 | 結果 | 說明 |
|---|---|---|
| Multipaz 發行端 issuer.multipaz.org | 部分 | 預授權 offer、metadata、token 請求、DPoP、client attestation 格式皆被接受；最後被拒於「CA not registered」，該伺服器只信任 Multipaz 自家錢包後端的 client attestation CA，需對方登錄我方錢包提供者 CA 才能完成發證。 |
| Multipaz 驗證端 verifier.multipaz.org | 無法測 | 測試當時回 503。改以 Multipaz 錢包 SDK 對我方測試驗證端互測（上表 5/5）。 |
| EUDI 發行端 issuer.eudiw.dev | 部分 | metadata、PAR、授權網址建立成功；27 種憑證全部要求 key attestation（iso_18045_high），需 EUDI 信任的錢包提供者，無法在雲端完成發證。 |
| EUDI 驗證端 verifier-backend.eudiw.dev | 通過 | x509_hash + direct_post.jwt + verifier_info（registration certificate）請求可解析與驗證；匯入 EUDI 參考實作 CA 為 TEST 錨點後顯示為 TEST 環境；DCQL 可執行（錢包無 EUDI PID 故回 access_denied）。完整出示需 EUDI 發行的 PID。 |

## 互通中發現並已修正

1. EUDI 驗證端憑證的 SAN 是 URI（https://verifier.eudiw.dev），回應位址在 verifier-backend.eudiw.dev。原本對「無錨點的 x509_hash」額外要求回應主機需在憑證 SAN 內，這不是 OpenID4VP 1.0 規定，會擋掉 EUDI。改為警告並顯示在同意畫面。x509_san_dns 的主機比對仍依規範強制。
2. Multipaz 0.101 錢包在 `direct_post` 模式送出 `response=<alg none JWT>`，不是規範的表單欄位（OpenID4VP 1.0 第 8.2 節）。測試驗證端改為接受並在結果中標示 `compatibility_notes`；核心驗證器預設仍拒絕。
3. 批次發證時軟體金鑰要求輸入 4 次 App PIN（建立 1 次加 3 個 proof 各 1 次），改為每次操作只問一次。
4. 實機遇到 SD-JWT 設定未宣告 vct 的發行端（舊版草案或 W3C 風格，如 TWDIW）被拒為 invalid_issuer_metadata。改為依 vct、credential_definition.type、設定 ID 依序決定本機歸檔型別；簽章金鑰可由同網域 jku 取得（信任等級 T3、標示未知錨點）。測試發行端新增 w3c_sd_jwt_legacy 設定重現此情境。

## 仍需處理

- 完整發證互通：需 Multipaz 或 EUDI 登錄 DIW 錢包提供者 CA，或使用其官方錢包後端；或在實機上以 Android key attestation 搭配對方錢包後端。
- Android 實機驗收：StrongBox/TEE 金鑰與生物辨識提示、Credential Manager（DC API）選取與回傳、QR 掃描、深層連結。
- CI：由使用者維護於 `.github/workflows/github-actions-ci.yml`，只在 push 到 main 與 pull_request 時執行。

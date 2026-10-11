# P1 驗收結果（2026-10-10）

分支 `p1-standard-core`。所有測試以 `./gradlew` 執行，指令列於各節。

## 本地自動測試（不需網路）

| 範圍 | 指令 | 結果 |
|---|---|---|
| OpenID4VP 1.0 / DCQL 持有端與驗證層 | `:test-servers:test --tests '*Oid4vpE2eTest'` | 18/18 通過 |
| OpenID4VCI 1.0 用戶端、Token Status List | `:test-servers:test --tests '*Oid4vciE2eTest'` | 19/19 通過 |
| DIW 測試驗證端 對 Multipaz 錢包 SDK（uriSchemePresentment、digitalCredentialsPresentment） | `:test-servers:test --tests '*MultipazWalletInteropTest'` | 5/5 通過 |
| App 共用模型（預授權、授權碼經瀏覽器回跳、由發行端網址領卡、DC API origin 檢查、PIN 加密儲存） | `:app:desktopTest` | 5/5 通過（另 2 項需網路，見下節） |
| 欄位名稱語系與網址政策 | `:test-servers:test --tests '*ClaimLabelsTest' --tests '*UrlPolicyTest'` | 3/3 通過 |
| Android APK | `:app:assembleDebug`、`:app:assembleRelease`（R8） | 建置成功（未在實機或模擬器執行） |
| 桌面 release（ProGuard） | `:app:packageReleaseDeb`、`:app:packageReleaseUberJarForCurrentOS` | 建置成功，Linux 上實際建立錢包、領取 PID 與 mDL |

## 對外互通（需網路，`DIW_INTEROP=1 ./gradlew :test-servers:test --tests '*InteropTest'`）

| 對象 | 結果 | 說明 |
|---|---|---|
| Multipaz 發行端 issuer.multipaz.org | 部分 | 預授權 offer、metadata、token 請求、DPoP、client attestation 格式皆被接受；最後被拒於「CA not registered」，該伺服器只信任 Multipaz 自家錢包後端的 client attestation CA，需對方登錄我方錢包提供者 CA 才能完成發證。 |
| Multipaz 驗證端 verifier.multipaz.org | 無法測 | 測試當時回 503。改以 Multipaz 錢包 SDK 對我方測試驗證端互測（上表 5/5）。 |
| EUDI 發行端 issuer.eudiw.dev | 通過 | 測試以其網頁流程（FormEU 測試國家）自動產生領卡連結：預授權（含交易碼）領取 PID 的 SD-JWT VC、mso_mdoc 與延遲發證 mso_mdoc；授權碼（PAR、PKCE、DPoP）領取 SD-JWT VC 與 mso_mdoc，皆為公開用戶端。27 種設定雖都宣告 key attestation（iso_18045_high），發行端實際接受不含金鑰證明的 jwt proof。授權碼流程需 EUDI 參考實作相容模式（見第 23 項）。 |
| TWDIW 方言開源發行端 issuer.mashbean.net | 通過（相容模式） | 需開啟「舊版草案相容模式」與「TWDIW 相容模式」：token 回應中的 c_nonce、vc+sd-jwt 無 vct、did:key 發行者金鑰；信任等級 T3，憑證顯示實際使用的規格（TWDIW、JWS jku 或 DID）。出示端採 PE 加 jwt_vp，P1 未支援。 |
| walt.id 發行端 issuer.demo.walt.id（OpenID4VCI draft 13） | 通過 | 以其 API 範例建立 offer：SD-JWT VC（x5c 與 did:jwk 兩種簽章）領卡成功；mDL 的協定流程成功，但 API 範例的文件簽署憑證已於 2026-09-02 過期，錢包依規拒收。120 種設定中 43 種可領，其餘為 jwt_vc_json、jwt_vc 等尚未支援格式，會列出但不影響其他項目。 |
| EUDI 驗證端 verifier-backend.eudiw.dev | 通過 | x509_hash + direct_post.jwt + verifier_info（registration certificate）請求可解析與驗證；匯入 EUDI 參考實作 CA 為 TEST 錨點後顯示為 TEST 環境；DCQL 可執行（錢包無 EUDI PID 故回 access_denied）。完整出示需 EUDI 發行的 PID。 |

## 互通中發現並已修正

1. EUDI 驗證端憑證的 SAN 是 URI（https://verifier.eudiw.dev），回應位址在 verifier-backend.eudiw.dev。原本對「無錨點的 x509_hash」額外要求回應主機需在憑證 SAN 內，這不是 OpenID4VP 1.0 規定，會擋掉 EUDI。改為警告並顯示在同意畫面。x509_san_dns 的主機比對仍依規範強制。
2. Multipaz 0.101 錢包在 `direct_post` 模式送出 `response=<alg none JWT>`，不是規範的表單欄位（OpenID4VP 1.0 第 8.2 節）。測試驗證端改為接受並在結果中標示 `compatibility_notes`；核心驗證器預設仍拒絕。
3. 批次發證時軟體金鑰要求輸入 4 次 App PIN（建立 1 次加 3 個 proof 各 1 次），改為每次操作只問一次。
4. 實機遇到 SD-JWT 設定未宣告 vct 的發行端（舊版草案或 W3C 風格，如 TWDIW）被拒為 invalid_issuer_metadata。標準流程維持拒絕；開啟 TWDIW 相容模式時以 credential_definition.type 決定本機歸檔型別，簽章金鑰可由同網域 jku 取得（信任等級 T3、標示未知錨點，規格列為 TWDIW 與 JWS jku）。測試發行端新增 w3c_sd_jwt_legacy 設定重現此情境，測試同時確認標準用戶端會拒絕。
5. 同一類發行端（issuer.mashbean.net）沒有 nonce 端點，c_nonce 放在 token 回應，原本 proof 不帶 nonce 而被拒（invalid_proof）。舊版草案相容模式會在無 nonce 端點時使用 token 回應的 c_nonce，invalid_nonce 錯誤附帶的 c_nonce 也會用於重試；接受單數 credential 回應；發行者為 did:key、did:jwk、did:web 時以 DID 解析金鑰。TWDIW 方言的完整支援（client_id、did:key proof、PE 與 jwt_vp 出示）排入 P2。
6. 測試伺服器網址填 Multipaz 發行端時，「匯入測試信任錨點」原本找 /pki/iaca.pem 而 404。改為偵測 Multipaz OpenID4VCI 伺服器，從各設定的 signing_certificate 取得 IACA 匯入；設定頁另有「匯入 Multipaz 測試發行端錨點」。Multipaz 發行端對公開用戶端回「clientId must be authenticated」，需錢包提供者的 client attestation，且簽發 CA 必須列在該伺服器的 trusted_client_attestations。

7. 相容各種發行端組合：發行端資訊中有不支援的格式時改為列出原因，不再讓整份資訊失敗；無 nonce 端點的發行端若拒絕 1.0 請求格式，舊版草案相容模式會改用 draft 13 格式（format 加型別參數與單一 proof）重送一次；一次領多種憑證時，單一項目失敗不影響其他項目。
8. 首頁輸入框可直接輸入發行端網址（可省略 https:// 與路徑，會嘗試 /issuer、/draft13、/openid4vci 等常見路徑），列出所有可領憑證供勾選，以授權碼流程領取。只支援預授權碼的發行端（如 mashbean）會提示改用其網頁產生的領卡連結。
9. 非標準實作與標準實作分離：OpenID4VCI 用戶端與憑證檢查只實作 1.0 標準，舊版草案（draft 13）與 TWDIW 的差異集中在 `core/compat` 的相容模式（`IssuanceDialect`），只在標準流程失敗的位置才會詢問，經由相容模式取得的憑證會記錄並顯示實際使用的規格（如 OpenID4VCI draft 13、TWDIW、JWS jku (RFC 7515)、DID did:key），不另造「非標準」狀態。設定頁可分別開關，舊版草案相容模式預設開啟，TWDIW 相容模式預設關閉。
10. EUDI 發行端授權頁回 500：同時送 scope 與 authorization_details（或只送 authorization_details）時對方伺服器出錯。改為所選設定都有 scope 時只送 scope，否則才送 authorization_details。
11. walt.id 發行端回 500「No issuance session found for given issuer state」：它不支援錢包自行發起，授權請求必須帶 offer 裡的 issuer_state。請在 portal.demo.walt.id 產生 offer 再掃描。
12. 登入失敗或關閉瀏覽器後，錢包原本一直停在等待畫面。改為回到 App 時若沒有收到回跳即顯示失敗，等待畫面也提供取消按鈕。
13. OpenID 認證測試套件（certification.openid.net）只在測試模組執行中才提供 metadata，否則回 404「No test found with alias」。找不到 metadata 時錯誤訊息改為附上伺服器回應原因，並提示先在套件啟動測試模組。
14. 實機連區網測試伺服器（如 http://10.133.11.189:8080）時被 Android 擋下「CLEARTEXT communication not permitted」。測試環境的本機 HTTP 改為也接受私有網段（10/8、172.16/12、192.168/16）；debug APK 的網路安全設定允許明文，正式版仍只允許本機與模擬器主機。
15. 測試伺服器新增驗證測試頁 `/verifier`：可選 DCQL 範本、client_id 前綴、回應模式與破壞選項，顯示 QR Code 與同裝置連結並輪詢結果，也可由瀏覽器以 DC API 出示。驗證端以 IP 位址對外時，x509_san_dns 的 client_id 與憑證 SAN 皆使用該 IP，已加測試。
16. 憑證與驗證請求可展開詳細資訊（設定頁可設為預設展開）：發證規格、設定 ID、格式、信任判斷、金鑰位置與演算法、簽章標頭、x5c 或 x5chain 憑證鏈、iat/exp、狀態清單位置、MSO 內容，以及驗證請求的 client_id、response_mode、nonce、憑證鏈與 DCQL。iss、iat、cnf、status 等 JWT 註冊欄位只列在詳細資訊，不混在憑證資料中。
17. 憑證狀態以 Token Status List 規格原文顯示（VALID、INVALID、SUSPENDED），發行端自訂值與保留值顯示原始數值（如 0x03），不對應成自訂狀態。
18. 欄位名稱：優先用發行端提供、符合使用者語系的名稱；發行端未提供時，依序使用其他發行端曾提供的名稱快取（保存所有語言，換語系後仍可用）、內建常用欄位中文名稱（OIDC、PID、mDL、W3C 約 90 項）、無語系標示的發行端名稱、Multipaz 型別名稱，最後才把欄位名轉為可讀文字。
19. 發佈建置改為 release 最佳化：Android 以 R8 縮減與最佳化（21.8 MB，debug 為 105 MB），桌面版以 ProGuard 最佳化（不混淆）。桌面 release 版原本因 Bouncy Castle 簽章檔在重寫後不符而無法啟動，改為 ProGuard 輸出與 uber jar 皆移除簽章檔；已在 Linux 以 release deb 實際建立錢包、領取 PID 與 mDL 並檢視詳細資訊。說明見 `docs/release.md`。
20. 實機回饋（2026-10-11）：一次領多張憑證後結果頁可捲動，點選即開啟該憑證，返回會回到結果頁；Android 返回鍵改為回上一頁，首頁才離開 App；憑證內容頁列出格式與類型；詳細資訊依發證、信任、簽章、有效期間、狀態清單、持有者金鑰分類，持有者公鑰只顯示類型與 JWK 指紋（RFC 7638），不顯示原始座標，私鑰不離開金鑰位置；簽章、驗證端與狀態清單的憑證可點選開啟證書詳情（主體、簽發者、序號、有效期間、金鑰用途、延伸金鑰用途、主體別名、CRL 發布點、指紋，並可切換憑證鏈中的其他憑證）；查詢狀態後顯示解析後的狀態清單權杖（狀態值、索引、bits、iat、exp、ttl、簽署憑證與信任錨點）；國碼類欄位顯示憑證內的原始代碼。

21. 實機（2026-10-11）由 EUDI 預授權連結領 PID，三種都失敗「Error creating key」：EUDI 的 c_nonce 是 720 bytes 的 JWE，錢包把它當作 Android 金鑰的 attestation challenge，而 KeyMint 上限為 128 bytes。超過 128 bytes 時改以 c_nonce 的 SHA-256 作為 challenge。平台錯誤訊息改為一併顯示底層原因（例如 Keystore 的錯誤碼）。
22. 發行端要求 key attestation 而錢包沒有錢包提供者（公開用戶端）時，原本直接停止（key_attestation_unavailable）。改為照送一般 jwt proof，由發行端決定是否接受；被拒時錯誤訊息註明發行端要求金鑰證明。EUDI 發行端接受，測試發行端（強制要求）拒絕，兩者皆有測試。
23. EUDI 授權碼流程「iss does not match authorization server (mix-up)」：其授權伺服器 metadata 的 issuer 為 https://issuer.eudiw.dev，授權回應的 iss 卻是 https://issuer.eudiw.dev/oidc（該路徑下的 metadata 又宣告 https://dev.issuer.eudiw.dev/oidc）。標準流程依 RFC 9207 維持拒絕，錯誤訊息列出兩個值；新增「EUDI 參考實作相容模式」（`EudiDialect`，預設開啟）：iss 位於授權伺服器 issuer 網址之下、且 token endpoint 位於該 iss 之下時才接受，授權碼仍送回簽發它的伺服器；這樣取得的憑證規格記錄為「EUDI 參考實作」。
24. EUDI 延遲發證（PID MSO Mdoc Deferred）輪詢時「Error decrypting」：EUDI 以第一次 credential request 帶的回應加密金鑰加密 deferred 回應，忽略輪詢時帶的新金鑰。改為同一 transaction 輪詢時沿用原本的金鑰（OpenID4VCI 1.0 允許）；測試發行端新增 `deferredToOriginalKey` 選項重現此行為。

## P1 狀態

P1 以本地測試可驗證的範圍完成後暫停（2026-10-11），之後遇到問題再重新處理。

## 仍需處理

- Multipaz 發行端完整發證：需對方登錄 DIW 錢包提供者 CA，或使用其官方錢包後端；或在實機上以 Android key attestation 搭配對方錢包後端。
- Android 實機驗收：StrongBox/TEE 金鑰與生物辨識提示（含第 21 項長 c_nonce 的金鑰建立）、Credential Manager（DC API）選取與回傳、QR 掃描、深層連結。
- CI：由使用者維護於 `.github/workflows/github-actions-ci.yml`，只在 push 到 main 與 pull_request 時執行。release 檔案由 `:app:assembleRelease`、`:app:packageReleaseMsi`（Windows）、`:app:packageReleaseDeb`（Linux）與 `:app:packageReleaseUberJarForCurrentOS`（需 Java 21）產生，版本可用 `-Pdiw.versionCode`、`-Pdiw.versionName`、`-Pdiw.desktopVersion` 指定。
- Android release APK 的 R8 結果尚未在實機執行驗證。

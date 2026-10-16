# bonds tw 系列（有備而來 / Bonds）深度調研筆記

> **研究資料的時間點說明：** 本文保留編寫時的技術比較與來源，不代表現在的功能完成度或最新規格版本。請以 [2026-10-16 專案狀態矩陣](../status-2026-10-16.md)確認 PR #11 的新實作及剩餘缺口。個人錢包依公開規格支援行動自然人憑證、CSC 及公文檔案，正式服務帳號／機關交換資格不屬必須完成的程式功能。

> 目的：為 KMP + Compose Multiplatform（底層 Multipaz）的台灣第三方數位身分皮夾（Android 先行）萃取 bonds tw 系列的非標準實作細節、已知問題與可重用程度。
> 調研日期：2026-10-10。標記：**【確認】** = 在 repo 原始碼／文件中讀到的事實（附路徑）；**【推論】** = 本筆記作者的推斷，需實測。
> 路徑前綴 `B/` = `scratchpad/src/Bonds-iOS`（commit `e22de5f`, 2026-09-13）；`VP/` = `twdiw-vp-verifier-lite`（`5742a5f`）；`VC/` = `twdiw-vc-issuer-lite`（`eed4316`）；`GH/` = `bonds-tw.github.io`（`295433e`）。

## 0. 資料來源狀態

| 來源 | 狀態 |
|---|---|
| Bonds-iOS repo（README、docs/ 全部 26 份、原始碼） | 已讀（UX 稽核兩份 ux-audit-2026-08-13/18、wall-signing-plan 只略讀） |
| mashbean/twdiw-vp-verifier-lite | clone 成功（**授權 GPL-3.0**） |
| mashbean/twdiw-vc-issuer-lite | clone 成功（**授權 GPL-3.0**） |
| bonds-tw/bonds-tw.github.io | clone 成功（無 LICENSE 檔）；`twdiw/zh/index.html` 為 TWDIW 實作筆記 |
| GitHub issues 頁面 | **讀不到**：WebFetch 被 robots 擋、`api.github.com` 與 github.com HTML 皆被本環境 proxy 拒絕（403）。以下 issue 編號只來自 repo 文件內的引用 |
| pro.mashbean.net 系列索引 | 讀到（WebFetch）；系列實有 **8 篇**（README 只列 6 篇，另有 2026-09-09 issuer-lite、2026-09-10 生態系監測儀表板） |
| pro.mashbean.net 六篇報告內文 | **讀不到**：WebFetch 回 SERVER_ERROR，curl 被 proxy 拒絕（connect_rejected）。只有索引頁的摘要 |

---

## 1. 專案概況與定位

- 【確認】iOS 16+、Swift 5/UIKit；bundle `tw.bonds.backupTW`；**研究原型，未上架**。「多數完成度是 Debug build 的完成度」。`B/README.md`「Project status」。
- 【確認】已有實機證據：OID4VCI 領卡＋OID4VP 出示（官方 demo）、一次真實 7-ELEVEN 電信卡取貨、MyData 真帳號保險箱、跨裝置離線驗證、網頁 ZK 年齡驗證、實體卡同意簽章。`B/README.md`。
- 【確認】Release 目前**無法簽章**：簽章 broker 在 UAT 且 start/poll 關閉。`B/docs/release-signing-backend-v0.md`、`B/docs/official-document-inbox-phase6.md`。
- 【確認】分支狀態（09-04）：main=`276f5db`（含 PR #58），PR #56（超商取貨）與 main 衝突、PR #57（MyData 保險箱）以 #56 為 base。`B/docs/app-development-checkpoint-2026-09-04.md`。
- 【確認】一手參考：denkeni《TWDIW: The Missing Manual》https://docs.denkeni.org/twdiw 與 `moda-gov-tw/TWDIW-official-app`（MIT）。`B/docs/twdiw-integration-plan.md` 開頭。

---

## 2. TWDIW 協定方言（最關鍵）

### 2.1 角色與「皮夾不存在」
- 【確認】發行端／驗證端有沙盒申請（`wallet.gov.tw/apply/applyAccount.html` → `issuer-sandbox`、`verifier-sandbox`），**沒有 wallet-sandbox、沒有皮夾註冊、沒有 wallet attestation**。`B/docs/twdiw-integration-plan.md` §一.A。
- 【確認】官方後端讀碼：49 張表無 client/wallet/app/device 註冊表；無 client_secret / client_assertion / mTLS / Play Integrity / App Attest / DeviceCheck；ID Token 簽章取出後未驗（`CredentialIssuer.java:209`）；`AccessTokenFilter` 整段被註解；`SecurityConfiguration:77` `/api/**` permitAll。同上 §十.B。
- 【確認】措辭邊界：領卡真正門檻是 pre-authorized code（QR）＋可選 `tx_code`。「拿得到那張 QR 的人，用任何自製皮夾都能走完全程」。同上 §十.B。
- 【推論】對 Android 版而言：今天沒有技術門檻，但**政策窗口風險最高**（若官方補 wallet attestation，第三方皮夾一夜失效）。務必把 `client_id` 等身分字串集中成可替換常數。

### 2.2 OID4VCI pre-authorized code 流程（實測順序）
來源：`B/backupTW/TWDIW/OID4VCICollection.swift`、`CredentialOffer.swift`、`B/docs/m52-live-collection-2026-08-26.md`、`B/docs/twdiw-integration-plan.md` §三 M5.2。

1. **進入點（三種 QR/連結形狀）**【確認】
   - `modadigitalwallet://credential_offer?credential_offer_uri=https://issuer-oid4vci.wallet.gov.tw/api/issuer/<taxId>/credential-offer-object?nonce=<uuid>&sub=<64hex>`（官方 App 自訂 scheme；host 位置是 `credential_offer`）。
   - 中轉頁：`https://frontend(-uat).wallet.gov.tw/api/moda/vcqrcode?mode=vc01&deeplink=<base64url(上述 deep link)>`，需解 `deeplink`。`CredentialOffer.swift` `relayDeeplink`。
   - 標準 `openid-credential-offer://?credential_offer_uri=…` 或 `credential_offer=`（by value）。兩者同時出現 → 拒絕（ambiguous）。
   - 靜態「申請卡片」QR：`https://frontend.wallet.gov.tw/api/moda/qrcode?mode=vc&vcUid=<UID>` **不是 offer**，要打 `GET /api/moda/dwapp/serviceUrl/{vcUid}?mode={mode}`（DW-MODA-201i）取得 `{type,name,issuerServiceUrl}`，`type==1` 外開瀏覽器、否則內嵌 WebView，待發行端網頁回傳 `modadigitalwallet://credential_offer`。`B/backupTW/TWDIW/ModaServiceURLResolver.swift`。
   - ⚠️ **官方 deep link 在 `credential_offer?` 後夾帶 CR+LF**（`modadigitalwallet://credential_offer?\r\ncredential_offer_uri=…`），不剝除就解析失敗。`CredentialOffer.swift` `parse(scanned:)`。
2. **GET offer**【確認】回 `{"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"…"}},"credential_configuration_ids":["00000000_demo_drivinglicense_202504251418"],"credential_issuer":"https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/"}`。**`credential_issuer` 結尾有斜線**。**offer 一次性**：同 nonce 第二次 GET 就沒有 `grants`（任何先於皮夾 dereference 的工具都會把機會用掉）。`m52` §二、§三。
3. **GET metadata** `<issuer>/.well-known/openid-credential-issuer`，只讀 `credential_endpoint`，且其 host 必須等於 issuer host（否則拒）。【確認】metadata 701 KB、882 組設定、**全部 `"format":"jwt_vc_json"`**、文件中 `sd-jwt`/`_sd` 出現 0 次、binding `jwk`、alg `ES256`。`twdiw-integration-plan.md` §八.A。
4. **POST `<issuer>/token`**（`application/x-www-form-urlencoded`）【確認】
   - `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`
   - `pre-authorized_code=<code>`
   - `client_id=moda_dw`（見 2.3）
   - `authorization_details=[{"type":"openid_credential","credential_configuration_id":"<configId>"}]`
   - `tx_code` 未送（demo 無；有 tx_code 的 offer 需另做 UI，`requiresTransactionCode` 記錄）
   - 回 `access_token`、`c_nonce`（600 秒，`integration-plan` §三），可能有 `authorization_details[].credential_identifiers[0]`。
5. **POST `credential_endpoint`**（Bearer、JSON）【確認】`{"credential_identifier":<id 或 configId>,"proofs":{"jwt":[<proof>]}}`；回應兩種形狀都見過：`{"credentials":[{"credential":"…"}]}` 或 `{"credential":"…"}`。
6. **proof JWT**【確認】header `{"typ":"openid4vci-proof+jwt","alg":"ES256","kid":"<holder did:key, jwk_jcs-pub 拼法>"}`；payload `{"iss":"moda_dw","aud":"<issuer identifier，強制補結尾斜線>","iat":…,"nonce":<c_nonce>}`。**少斜線 demo issuer 會拒**。`aud` 由閘門的正規 host 重建，不用 offer 原字串。
7. **入庫前檢查**【確認】SD-JWT 驗簽（iss did:key）、`cnf.jwk` 座標等於本次新建金鑰、`iss` 等於已通過鏈上驗證的信任清單那筆 DID；以 `configurationID` 為儲存 id（同卡重領即覆寫）。失敗即刪除新建金鑰。
8. 卡面：`…/api/images/cover/<taxId>/<config>`【確認，文件記載】。
- 【確認】**Cloudflare 以 UA 指紋擋**：curl/Python 預設 UA → `POST /token` 403 `error code: 1010`；改 `User-Agent: backupTW/1.0 CFNetwork/1568 Darwin/24.0.0` 即過；瀏覽器 fetch 被 CORS 擋。frontend 也擋 curl TLS 指紋（`TelecomCardCatalog.swift`、`ModaServiceURLResolver.swift` 註解）。`m52` §四。
  - 【推論】**Android 重大風險**：OkHttp/Ktor 預設 UA（`okhttp/4.x`、`Ktor client`）與 TLS 指紋可能同樣被 1010 擋，須第一時間實測；可能需設定類似官方 Android App 的 UA。
- 【確認】demo 站歷史：08-26 曾卡在 `HTTP 400 {"resp_code":11007,"error":"invalid_grant","resp_message":"Pre-authorized_code not found"}`；08-27 查明原因是 client_id（見下）。`m52` §五、`OID4VCICollection.swift` 註解。
- 【確認】只支援 pre-authorized code；authorization_code grant 未實作（`noPreAuthorizedGrant`）。電信卡是否可能走 auth code 為未決。`roadmap` 未決問題。

### 2.3 `client_id=moda_dw` 限制
- 【確認】token 端以 `(client_id, pre_authorized_code)` **成對**查 code；code 鑄造時存的 client_id 來自發行端自簽 ID Token 的 `aud`，寫死 `"moda_dw"`（`twdiw-vc-handler/…/CredentialService.java:1715` 寫入、`twdiw-oid4vci-handler/…/CredentialIssuer.java:225` 讀出、`:1196` 查、`:1741` proof `iss` 比對）。
- 【確認】2026-08-27 實測：`tw.bonds.backupTW` → 400 `11007 Pre-authorized_code not found`；`moda_dw` → 200。因此 **proof JWT 的 `iss` 也必須是 `moda_dw`**。`OID4VCICollection.swift` L95–113、L131。
- 【確認】列入上游回報 A4，措辭須是「皮夾身分在流程中沒有被鑑別」而非「任何人能假冒官方皮夾」。`B/docs/upstream-reports.md`。
- 【推論】KMP 實作：`clientId` 做成設定值（預設 `moda_dw`），並在 UI/文件中揭露此相容性選擇。

### 2.4 did:key 方言（`jwk_jcs-pub`）
- 【確認】TWDIW DID：`did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWP…`，base58btc 解碼 129 bytes，前 3 bytes `D1 D6 03` = multicodec **0xEB51 `jwk_jcs-pub`**，其餘是 **JWK JSON 文字** `{"crv":"P-256","kty":"EC","x":…,"y":…}`。後端寫死 `substring(1)` 與 `substring(6)` 切前綴，不檢查 multibase/multicodec → 送 `did:key:zDn…`（p256-pub 0x1200）會被切壞成 JSON 錯誤。`integration-plan` §一.C、`B/backupTW/Crypto/JWKDIDKey.swift`。
- 【確認】規則：「**產生一律 JCS 正規（鍵序 crv,kty,x,y、無空白），解析一律不要求正規**」；比較 DID 時比較從金鑰重算的正規形式，不比原字串。原因：正式 43 個發行者 DID 全部 JCS 正規且自簽 43/43 驗過，但**官方皮夾 holder DID 鍵序是 crv,x,y,kty（不合規，n=1、二手、無版本）**。測試向量在 `GH/twdiw/zh/index.html` §二（數發部 DID 與一個非正規 holder DID）。
- 【推論】Multipaz 的 did:key 不支援 0xEB51（需自行實作 multicodec + JCS 序列化）。

### 2.5 SD-JWT 型別（VCDM 1.1 包 SD-JWT 的混血）
- 【確認】header `{"jku":"https://issuer-vc.wallet.gov.tw/api/keys","kid":"key-1","typ":"vc+sd-jwt","alg":"ES256"}`；payload `iss`(did:key)、`sub`、`jti`（URL，最後一段 UUID = 官方 UI 的「憑證序號」）、`nbf`、`exp`、`cnf.jwk`、`vc.type=["VerifiableCredential","<taxId>_<name>_<timestamp>"]`、`vc.credentialSubject._sd[]`、`_sd_alg`、`vc.credentialStatus`、`vc.credentialSchema.id`。**沒有 `vct`、`_sd` 在 `vc.credentialSubject` 底下不在頂層**。`B/backupTW/TWDIW/TWDIWCredential.swift`、`VC/docs/protocol-and-trust.md`。
- 【確認】compact：`<jws>~<d1>~…~<dn>~`（尾端 `~`、**無 KB-JWT**）。disclosure `base64url(JSON([salt,name,value]))`；digest = `base64url(SHA-256(disclosure 的 base64url 字串 ASCII))`（已用正式資料兩個 `_sd` 驗證）。`GH/twdiw/zh/index.html` §三。
- 【確認】接受 `typ` ∈ {`vc+sd-jwt`, `dc+sd-jwt`}；alg 僅 ES256；**驗簽金鑰只取 `iss` did:key，永不跟隨 `jku`**（`jku`/`kid` 只存為診斷）。`TWDIWCredential.swift`。
- 【確認】駕照電子卡六欄（全部 mandatory、demo 卡全為字串）：`name`、`id_number`、`roc_birthday`（民國 YYYMMDD，如 `0570605`）、`type`、`controlnumber`、`gDate`。萬用電信卡 `00000000_universal_telecom_card`：`phone`；便利商店取貨卡 `00000000_convenience_store`：`name`＋`Phone_number_last3`（metadata）。`integration-plan` §一.F、§八.A、`m52` §六。
- 【確認】**正式超商取貨請求實際要的是 `name` + `phonel5`**（手機末五碼），電信卡型別：`96979933_name_phonel5_phonel3`、`97179430_fet_vc_prod`、`97176270_twmdiwvc_postpaid`。`B/backupTW/TWDIW/ConvenienceStorePickup.swift`。【推論】96979933＝中華電信、97179430＝遠傳、97176270＝台灣大（依統編，未在 repo 明寫）。
- 【確認】**`statusListIndex` 是字串**（`"35"`），只收數字的讀取器會丟掉整個 status。`TWDIWCredential.swift` `statusEntry`。
- 【確認】IAL 不存在：IAL-1（自填 email）與 IAL-3 卡結構完全相同（同 jku、kid、typ、issuer）。`integration-plan` §一.G。
- 【確認】**沒有年齡述詞**：證明滿 18 只能揭露完整 `roc_birthday`；且實測「公路局駕照電子卡沒有揭露 roc_birthday」（`zkp-web-verification-2026-09-04.md`、`VP/docs/protocol-and-trust.md`）——兩處說法看似與 demo 卡有 roc_birthday 矛盾，【推論】正式公路局卡與 demo 卡欄位不同。
- 【確認】`SelectiveDisclosure` 對非三元素／非字串 disclosure **拒整張卡**；真實電信卡可能帶非字串值 → 路線圖未決（寬鬆顯示但不得弱化 digest 檢查）。`roadmap` 卡片顯示節。
- 【確認】卡片名稱只有 `vc.type[1]`（41 字元內部碼），人類可讀名稱在線上 metadata `display[].name` 且不受簽章覆蓋 → 離線無可信名稱（上游回報 A8）。Bonds 只做條件式去頭去尾（`CardInventory.readableType`），刻意不做對照表。
- 【確認】可連結性：`statusListIndex` 在 `_sd` 外、每次出示都送 → 跨查驗方可連結；`cnf.jwk` 終身固定 → 一卡一金鑰只切斷「卡與卡之間」，不切斷發行端與查驗端。`GH` §六、`integration-plan` §十一.A、`B/backupTW/Crypto/HolderKeyring.swift`。

### 2.6 OID4VP 出示
來源：`B/backupTW/TWDIW/OID4VPRequest.swift`、`OID4VPRequestFetcher.swift`、`OID4VPResponse.swift`、`OID4VPPresentation.swift`。
- 【確認】authorize 連結：scheme ∈ {`openid4vp`, `modadigitalwallet`}，`modadigitalwallet://authorize?client_id=<verifier did:key>&request_uri=https://verifier-oid4vp.wallet.gov.tw/api/oidvp/request/<id>`（或 `request=` inline）。同樣剝 CR/LF。
- 【確認】`request_uri` 回應 **body 是裸 compact JWS 字串**（非 JSON content-type）。header `typ: oauth-authz-req+jwt`、`kid` 是不透明字串 `verifier-did` → **驗簽金鑰取自 `client_id` did:key**（先試 jwk_jcs-pub，再試 p256-pub）。ES256 raw r||s。
- 【確認】request payload 必要欄位：`response_mode=direct_post`（其他拒）、`response_uri`、`nonce`、`state`、`presentation_definition.id`、`input_descriptors[]`（`id`、`format` 含 `vc+sd-jwt` 或 Bonds 擴充 `vc+moica`、`constraints.fields[].path` 如 `$.credentialSubject.name`、`$.type` + `filter.contains.const` 指定卡型、`group[]`、`name` 是 JSON 字串含 `vc_name`/`org_tw_name`）、`submission_requirements[]`（`rule: pick`、`from`、`max:1`…）。`VP/docs/protocol-and-trust.md` 另放 DCQL 平行分支（`dcql_query`，format `dc+sd-jwt`），TWDIW 仍用 DIF PE。
- 【確認】兩道閘門：`request_uri` host 在 GET 之前、`response_uri` host 在簽署之前都必須屬於信任清單 host 集合（`issuerMetadataBaseURL`、`serviceBaseURL`）＋沙盒。DEBUG 另加 `verifier.mashbean.net`。
- 【確認】**vp_token 格式**（照官方 `APP/APPSDK/lib/openid_vc_vp.dart` `generateVPKx`）：
  - header `{"typ":"JWT","alg":"ES256","jwk":{kty,crv,x,y}}`（金鑰放 header jwk，不用 kid）
  - payload `{"sub":holderDID,"iss":holderDID,"aud":<verifier client_id did 原字串>,"nbf":now,"exp":now+30天,"nonce":<request nonce>,"jti":"urn:uuid:…","vp":{"context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"verifiableCredential":[<SD-JWT 只留所選 disclosure，保留尾端 ~>]}}`
  - ⚠️ **`context` 沒有 `@`**（刻意複製官方錯字以被官方驗證端接受；上游回報 A6）；早期筆記寫 `aud` 有 `redirect_uri:` 前綴是**錯的**，已更正。
- 【確認】`presentation_submission`：`{"id":"submission-<state>","definition_id":…,"descriptor_map":[{"id":<descId>,"format":"jwt_vp","path":"$","path_nested":{"id":<同一 descId>,"format":"jwt_vc"（自發卡用 vc+moica）,"path":"$.vp.verifiableCredential[i]"}}]}`。扁平 `vc+sd-jwt`@`$` 或 `path_nested` 缺 `id` 皆被拒（code 2012，`PresentationSubmissionValidator.java`「descriptor_map id is not the same for each level of nesting」）。
- 【確認】POST `response_uri`（form-urlencoded）：`vp_token`、`presentation_submission`（JSON 字串）、`state`。
- 【確認】分組請求（超商）：同一張卡可依 descriptor 重複出現多次、每份帶不同 disclosure（姓名一份、末五碼一份）。
- 【確認】官方皮夾 SDK 缺陷（上游 A1）：以子字串比對整段解碼 JSON 決定保留哪些 disclosure → 會多送欄位（`id_number`/`controlnumber` 都含 `number`）；`sdJwtDecode` 三元素分支不驗 digest。**第三方實作必須比對 disclosure 陣列第二元素**。

### 2.7 信任清單（數位發展部）
- 【確認】`GET https://frontend.wallet.gov.tw/api/did?size=20&page=<n>&orgType=<1|2>&status=1`；回 `{data:{dids:[…]}}`（單筆時 `data` 即 entry）。entry：`id`(DID)、`did`(自簽 DID 文件 JWS)、`org{name,name_en,taxId,issuerMetadataBaseURL,serviceBaseURL,…}`、`orgType`、`orgGroup`、`updatedAt`、`onChainHistory[{net,scAddress,txHash,status,createdAt}]`、`x509_type`。`B/backupTW/TWDIW/IssuerAuthorization.swift` `init?(entry:)`、`TrustListFetcher.swift`。
- 【確認】⚠️ **size 被夾在 20 但 offset 依請求 size 算**：`size=100&page=1` 空 → 必須 `size=20` 逐頁抓到空頁為止；兩種 orgType 都抓，依 DID 去重（數發部兩邊都有）。實測 orgType=1 20 筆、=2 23 筆、共 43。單筆查詢：`GET /api/did/{urlencoded DID}`（`VP/docs/protocol-and-trust.md`，要求 `code=="0"`、`data.status==1`）。
- 【確認】請求須 `Cache-Control: no-cache, no-store`、不用快取決策。
- 【確認】`orgGroupDetail.name` 全部是「政府部門」（含全家、統一超商、中華電信…）**不可顯示**；`orgType` 1/2 疑為發行端/驗證端。
- 【確認】一 host 多機構：三所大學共用 `dcert.wallet.gov.tw`；數發部同時是發行與驗證 → gate 2 不可要求恰好一筆。issuer host 例：`<taxId>.wallet.gov.tw`、`moda.wallet.gov.tw`、`dcert.wallet.gov.tw`、`chtmecard.wallet.gov.tw`。demo `issuer-oid4vci.wallet.gov.tw` **不在**正式清單（需獨立 DEBUG 沙盒信任域）。
- 【確認】閘門規則：host 全等比對（拒前綴攻擊 `…wallet.gov.tw.evil.tw`，已實機攔截）；拒非 https、userinfo、非 443 port、尾點、非 ASCII/punycode、`%2e`/`..`。
- 【確認】例外：中國醫藥大學兩筆 `onChainHistory` 空、`x509_type=XCA`、`issuerMetadataBaseURL=null`（API 自述，未上鏈查證）。

### 2.8 Arbitrum 鏈上錨定
- 【確認】Arbitrum One，合約 `0x84172caf8dd126c76f1fa8a2733ca3233264d31f`；寫入 selector `0xf6e0d282`（ABI：3 個 string offset＝DID、自簽 DID 文件、org JSON，再 orgType、orgGroup、第 6 字）；現況查詢 `getDocById(bytes)` selector `0xfba6fe49`，回 `(signedDIDDocument, organisationJSON, orgType, orgGroup, revoked)`。RPC `https://arb1.arbitrum.io/rpc`。`B/backupTW/TWDIW/TWDIWOnChainVerifier.swift`。
- 【確認】**鏈上存明文**（數發部那筆 calldata 2,596 bytes 含完整 DID 與 DID 文件 JWS，非 hash）。
- 【確認】Bonds 閘門 1b：對 API 每一筆候選，批次 JSON-RPC：`eth_getTransactionByHash` + `eth_getTransactionReceipt`（status 0x1、to=合約）+ `eth_call getDocById latest`（未撤銷、內容與 API 相同）；任一不符/未錨定/RPC 不可用 → fail closed，不用快取放行。結果分 `verified/notAnchored/mismatch/unavailable/developmentSandbox`。
- 【確認】收卡成功後存 `OfflineIssuerTrustSnapshot`（issuer DID、名稱、統編、block、txHash、合約，無個資）供離線查驗。`OfflineIssuerTrustStore.swift`。
- 【確認】限制：只驗過 API 給的 tx；「只給合約位址列舉全部」未做。`VP` verifier-lite **未**自行跑 RPC，只顯示 API 帶的鏈上資料。
- 【推論】Android：可用任何 JSON-RPC（Ktor）＋手寫 ABI 解碼；單一公共 RPC 端點是可用性與信任單點，應考慮多 RPC quorum（verifier-lite 文件也建議）。

### 2.9 StatusList（撤銷）
- 【確認】StatusList2021：`GET https://issuer-vc.wallet.gov.tw/api/status-list/<configId>/r0` → ES256 JWT，`credentialSubject.encodedList` gzip+base64 bitstring，**MSB-first**；16,384 bytes = 131,072 位元；`nbf`→`exp` 剛好 86,400 秒且 `nbf` 是上次簽發時間（約每日 18:00 UTC）→ 剛抓下的清單剩餘效期 0–24h，UI 要顯示清單的 `exp`。`integration-plan` §一.E、§八.E；`VP/docs/protocol-and-trust.md`（另支援 OAuth Token Status List，LSB-first）。
- 【確認】⚠️ **狀態清單由 `key-2` 簽，該金鑰不在 iss DID、不在信任清單、不在鏈上**，只能經 `jku`（`/api/keys`）取得 → 撤銷路徑信任基礎只有 TLS，離線無法驗簽。Bonds 離線一律回報「未檢查」而非「未撤銷」。`integration-plan` §九。
- 【推論】KMP：撤銷狀態三態（valid/revoked/unknown），unknown 不得顯示為有效。

### 2.10 超商取貨條碼
來源：`B/backupTW/TWDIW/ConvenienceStorePickup.swift`。
1. 【確認】`GET https://frontend.wallet.gov.tw/api/moda/dwapp/offline/vpList?name=&page=0&size=100` → `{code,data:{vpItems:[{vpUid,name,verifierModuleUrl,logoUrl}]}}`；7-ELEVEN `vpUid=22555003_711pickup`。
2. 【確認】`verifierModuleUrl` host 必須在信任清單 verifier hosts 且對應機構 Arbitrum `verified`。
3. 【確認】（官方稱 401）`GET <module>/api/ext/offline/qrcode/<vpUid>` → `{code:"0",data:{transactionId,deepLink}}`；deepLink 是 OID4VP authorize，`request_uri` host 必須等於 module host；request 的 `definitionID==vpUid`、`response_uri` host 同 module、要求欄位含 `name`、`phonel5`。
4. 【確認】出示 VP（disclosing `name`,`phonel5`）。
5. 【確認】（官方稱 402）`POST <module>/api/ext/offline/getEncryptionData` body `{"jwt":<ES256 JWT header{typ:JWT,alg:ES256,kid:<holder DID>} payload{transactionId}，用**剛才出示的同一把卡金鑰**簽>}` → `{code:"0",data:{qrcode:"data:image/png;base64,…",totptimeout:"<秒>"}}`。條碼必須是伺服器產生的 PNG（本地畫的不能用），≤5 MB、驗 PNG magic；倒數用絕對時間（UI 稱五分鐘）。可重新產生（重打 402）。
- 【確認】實測：一次真實 7-ELEVEN 取貨成功（使用者回報），不能外推到全部電信卡。`checkpoint-2026-09-04`。
- 【確認】電信卡申請目錄：`GET https://frontend.wallet.gov.tw/api/moda/dwapp/apply/vcList?name=&page=0&size=50` → `vcItems[{vcUid,name,type,issuerServiceUrl}]`，三張「門號電子卡」皆 `type==1`（外開到電信商）；電信商 App 完成門號驗證後**只用 `modadigitalwallet://credential_offer` 交回 offer** → Bonds 後來**改為註冊此 scheme**（與官方 App 共用，iOS 路由未定義）。`TelecomCardCatalog.swift`、`CredentialOffer.swift` L566–585、`B/backupTW/Info.plist`。
- 【確認】駕照電子卡不在 vcList（09-09 實測只有三張電信卡），由監理服務網登入後網頁發卡。`B/docs/sandbox-issuer.md`。
- 【推論】Android：註冊 `modadigitalwallet` intent-filter 時，Android 會跳出 App chooser（非 iOS 的未定義行為），體驗反而較可控；但與官方 App 競爭仍有政策風險。

---

## 3. 行動自然人憑證（TW FidO SP API v2.9）

來源：`B/backupTW/TWFidO/TWFidOClient.swift`、`SPChecksum.swift`、`TWFidOConfiguration.swift`、`B/scripts/twfido-sign.mjs`。規格名：《行動自然人憑證應用程式介面規格書 v2.9》(MOI_CA_DEV_API)。

- 【確認】Base URL：prod `https://fidoapi.moi.gov.tw`、UAT `https://fido-test.moi.gov.tw`。
- 【確認】端點：
  - ATH-01 `POST moise/sp/getSpTicket`（`op_mode=APP2APP`）
  - ATH-03 `POST moise/sp/requestAthOrSignPush`（推播；無 `op_mode`；可帶 `device_user_def_desc` 指定裝置別名，不帶則推所有綁定裝置）
  - ATH-02 `POST moise/sp/getAthOrSignResult`（輪詢，規格要求間隔 ≥4 秒）
- 【確認】請求欄位：`transaction_id`(UUID)、`sp_service_id`、`sp_checksum`、`id_num`（明文身分證號）、`op_code="SIGN"`、`op_mode`、`hint`、`time_limit`（**整數** 30–600）、`device_user_def_desc`、`sign_info{sign_data=base64(TBS), sign_type="PKCS#1", tbs_encoding="base64", hash_algorithm="SHA256"}`。PKCS#1 是 zkID 電路的硬限制。
- 【確認】**sp_checksum（AES-256-GCM）**：key = base64 32 bytes；`hexLower(SHA-256(payload))` 的 64 字元**字串**做明文（不是 32 raw bytes）；12-byte IV；輸出 `hex(IV)‖hex(ciphertext)‖hex(tag)` 共 184 個小寫 hex。規格範例與官方參考 App 用全零 IV，**Bonds 用隨機 IV**（伺服器接受；ATH-01 範例本身就是非零 IV）。payload 串接順序：
  - push（指定裝置）：`transaction_id‖sp_service_id‖id_num‖device_user_def_desc‖op_code‖hint‖sign_data`
  - push（全部裝置）：`transaction_id‖sp_service_id‖id_num‖op_code‖hint‖sign_data`
  - APP2APP：`transaction_id‖sp_service_id‖id_num‖op_code‖op_mode‖hint‖sign_data`
  - ATH-02：`transaction_id‖sp_service_id‖sp_ticket_id`
- 【確認】`sp_ticket` = `base64url(payload).base64url(digest)`，以**最後一個點**切；payload 內含 `transaction_id`、`sp_ticket_id`。
- 【確認】**`idp_checksum`**（回應側）：同構造同把 key，覆蓋 `transaction_id‖error_code‖hashed_id_num‖signed_response`（**不含 cert**）；用解密驗證（GCM 隨機無法字串比對）。回應 `{error_code, error_message, result{hashed_id_num, signed_response, cert, idp_checksum}}`，`error_code` 可能是數字或字串；pending 碼 `20002`、`20003`、`SP-API-ATH-02-SPTKTID_TXNLOG_NF`/`SPTKTID_TXNLOG_NF`。
- 【確認】`mobilemoica://moica.moi.gov.tw/a2a/verifySign?sp_ticket=…&rtn_url=<base64(回呼 URL)>&rtn_val=<base64url(transaction_id)>`，全部嚴格 percent-encode（`+`/`/` 不編會被 form-decode 成空白、返回失敗）。回呼到 `backuptw://`，**callback 只是觸發輪詢的訊號，不是結果**。iOS 實機：app 切換時第一次 poll 必被系統殺連線（`networkConnectionLost`）→ 傳輸錯誤可重試直到 ticket deadline。
- 【確認】ATH-02 回應含 `cert`（持卡人 X.509）與 `hashed_id_num` → 使用 ephemeral、無快取的 HTTP session。
- 【確認】**SP AES key 絕不能進 App**（`strings` IPA 即可取出，可冒用 SP 對任意身分證號推播簽章）；privacy-ethereum 參考 App 把 key 放 App 內，Bonds 刻意不跟。Debug 用 scheme 環境變數 `TWFIDO_SP_SERVICE_ID`、`TWFIDO_SP_AES_KEY`；Release 的 provider 固定拋 `requiresBackend`；CI 放 canary 掃 Release binary。`TWFidOConfiguration.swift`、`SPSecrets.swift`、`.github/workflows/ci.yml`。
- 【確認】**簽章內容（TBS）三種**：
  1. ZK 持證：固定 relying-party id `appID = "55349ff540392a077ca3dcc9bbda4c3"`（SHA-256("tw.bonds.backupTW") 前 31 hex；電路欄位上限 31 字元）。`scripts/twfido-sign.mjs` 預設 APP_ID 為另一值 `e775f2805fb993e05a208dbff15d1c1`。
  2. 自發身分證：`bonds-tw-credential-v1:<64 hex SHA-256(payload bytes)>`（87 ASCII）。
  3. 電子公文同意：`bonds-tw-official-document-consent-v1:<64 hex>`。
  - 為何不把 TBS 截成 31 字元放進電路：124 bits → 62-bit 碰撞，持有人可磨碎；所以兩用途分開簽。`TWFidOClient.swift` L13–46。
  - 【確認】未測：SP API 是否接受 ~1 KB `sign_data`（若可，PKCS#1+SHA256 = JOSE RS256 可直接做 `vc+jwt`）。`MOICASignedCredential.swift`。

### 3.1 App Attest 簽章 broker（Release）
來源：`B/docs/release-signing-backend-v0.md`、`app-attest-uat-test.md`、`official-document-inbox-phase3/4/6.md`、`B/backupTW/TWFidO/AppAttestSigningBroker.swift`。
- 【確認】獨立 `bonds-signing-broker`（私有 repo）：Cloudflare Worker + SQLite Durable Objects + Worker Secrets；UAT `signing-uat.mashbean.net`、dev `signing-dev.mashbean.net`；secrets 為空、`SIGNING_START_ENABLED=false`、`SIGNING_POLL_ENABLED=false`；尚無 MOICA UAT SP credential。
- 【確認】API v1：`POST /v1/attest/challenge`、`/v1/attest/register`（Apple chain、nonce、RP ID、AAGUID、counter==0）、`/v1/assertions/challenge`、`/v1/assertions/verify`（UAT 檢查用）、`/v1/signatures/start`（request_id 冪等、assertion 綁 API version+method+path+challenge+request_id+canonical body hash；回 opaque `session_token`（AES-GCM，與 SP key 分離）、固定 return scheme 的 FidO deep link、`expires_at`）、`/v1/signatures/poll`（後端驗 `idp_checksum` 後才回 cert/signature；不持久化）。
- 【確認】**只允許三種固定 intent**：`zk_holding_proof_v1`、`national_id_credential_v1`、`official_document_inbox_consent_v1`；不提供任意 sign_data/hint/callback、不做 ATH-03 push。App 收到後仍以內建 MOICA trust anchor 再驗 cert/signature。
- 【確認】錯誤碼表：400 invalid_request、401 attestation_required/assertion_invalid、409 replay_detected、410 session_expired、422 provider_rejected、429 rate_limited、502 provider_response_invalid、503 signing_unavailable。
- 【確認】App 端：同一 App Attest key 的 request 用可取消 gate **序列化**（actor 會 reentrancy 導致 counter 亂序被判 replay）；不允許 redirect；ephemeral session；response 必須 `Cache-Control: no-store`。
- 【確認】Apple 2026 新增 launch metadata（`apple_validation_category_01`、`apple_bundle_version_01`）；iOS 27 development attestation 不帶 → dev broker 特例；TestFlight UAT 只收 category 2、App Store 4，並白名單 `CFBundleVersion`。尚未完成 TestFlight（缺 App Store Connect 權限）。
- 【確認】Cloudflare `apac-ne` 只是 hint，不保證資料在台灣；PITR 使 TTL 刪除≠不可恢復——production 須重新評估。
- 【推論】**Android 對應**：
  - App Attest → **Play Integrity API**（standard request，`requestHash` 綁 canonical body，對應 assertion 的 clientData）＋**Android Key Attestation**（Keystore 產生的硬體金鑰憑證鏈，可做 per-install 註冊與 counter 替代：伺服器發 challenge、裝置用 attested key 簽 canonical request）。Play Integrity 有每日配額、需 Google Play 服務（無 GMS 裝置要 fail closed）。
  - Play Integrity verdict 由 Google 伺服器解密／或自行解密 → broker 要另做 Google 端整合；與 Apple 不同，Integrity token 本身無遞增 counter，重放防護靠一次性 nonce/requestHash。
  - broker 協定若想 iOS/Android 共用，`/v1/attest/*` 需抽象出 platform 欄位。
  - `mobilemoica://` 在 Android 的對應：【推論】官方「行動自然人憑證」Android App 應支援相同 a2a URI 或 intent；需實測（repo 無 Android 證據）。回呼用 App Links 或自訂 scheme，注意 Android 會殺背景網路較少，但仍需重試策略。

---

## 4. 自然人憑證實體卡 PKCS#11 簽章
來源：`B/tools/official-document-physical-card-signer/`（Rust）、`B/scripts/physical-card-consent.sh`、`B/docs/official-document-inbox-phase7.md`。
- 【確認】架構：iPhone App 建立一次性 request JSON（無姓名/身分證/憑證）→ Mac 用 `xcrun devicectl` 從 App container 拉出 → Rust 工具驗證並經 PC/SC 讀卡機呼叫卡片 `SIGN` 私鑰做 `SHA256-RSA-PKCS` → response（`0600`、create_new）推回 → App 重建 request、驗 MOICA chain、RSA 簽章，通過才存 receipt（`signingChannel=physicalNaturalPersonCertificate`）。DEBUG-only。
- 【確認】request 格式：`format="bonds-tw-official-document-physical-card-request-v1"`、`version="bonds-tw-official-document-inbox-consent-v1"`、`scope="local-prototype-only"`、`created_at_unix_ms`、`nonce`（32 bytes base64url 無 padding）、`to_be_signed`；canonical = `"version=…\nscope=…\ncreated_at_unix_ms=…\nnonce=…\n"` → TBS `bonds-tw-official-document-consent-v1:<sha256 hex>`；15 分鐘有效、未來偏移 ≤60 秒、request ≤16 KiB。response：`format`、`request`、`certificate_der_base64`、`signature_base64`、`signed_at_unix_ms`。
- 【確認】PIN 只由隱藏終端提示讀取（無 `--pin`/env/file）；錯一次即停（避免鎖卡）；多張卡要 `--slot`。
- 【確認】依賴 `chouhsiang/open-gpki-pkcs11` rev `4684289…`（v0.1.1，**LGPL-2.1-or-later**，非官方實作，依 ISO 7816/PKCS#15；支援第一／二代卡、`SIGN`/`KEYX`）。macOS CCID 1.5.1 + Generic Smart Card Reader 實測通過一張卡；卡片世代未記錄。
- 【推論】**Android 可行性**：
  - 自然人憑證是接觸式 IC 卡（ISO 7816）。【推論】多數卡不支援 NFC 非接觸介面 → Android 上應走 **USB OTG + CCID 讀卡機**（Android USB Host API 自行實作 CCID，或用第三方 CCID 函式庫），而非 NFC IsoDep。若後續證實某代卡有雙介面，再評估 NFC。
  - open-gpki-pkcs11 依賴 PC/SC，Android 無 PC/SC；需把其 APDU/PKCS#15 層移植為「APDU over USB CCID」，可以 Rust（uniffi→Kotlin）或 Kotlin 重寫。注意 LGPL：動態連結/可替換義務，若靜態編入 Android App 需評估合規。
  - 也可考慮仿 Bonds 的桌面 helper 路線（開發用），正式產品不建議依賴實體卡。

---

## 5. 電子公文（電子公文個人接收站）
來源：`B/docs/official-document-inbox-phase2.md`～`phase8.md`、`B/backupTW/Model/OfficialDocument*.swift`、`B/backupTW/Storage/OfficialDocumentInboxArchive.swift`。
- 【確認】依檔案管理局《文書及檔案管理電腦化作業規範》：DI = 公文本文 XML；EN = 信封 XML（收發機關、主旨、檔案清單／雜湊）；ESW = 收文憑證卡號與加密資訊（不是本文）。重複收受且雜湊相同不再處理；規範要求收文確認、自動狀態、加解密、憑證註冊。
- 【確認】Bonds 實作：單檔 2 MiB、拒內部 ENTITY 與外部 entity；解析 EN 的 sender／service ID／application ID／subject／file list；以 EN 列的 **SHA-256** 比對 DI/ESW；同 application ID＋同 EN bytes → 冪等；同 ID 不同 bytes → 拒絕；原始 EN/DI/ESW 逐位元組保存在 `Application Support/OfficialDocumentInbox/packages/<id>/` + `metadata.json`；狀態 `unread → viewedLocally`（無法定效果）。ESW-only → `encryptedContentUnavailable`。來源驗證固定 `notVerifiedSynthetic`。
- 【確認】**G2B2C 公開地址簿**：`https://www.good.nat.gov.tw/regcenter/pub/addressbook/file/all_active_utf8.csv`（資料集 https://data.gov.tw/dataset/7617），每日更新，欄 `ORGID, ORGNAME, STATUSCODE(T/D/F), UPDATETIME`；09-01 為 3,015,834 bytes、40,013 筆。嚴格解析（5 MiB/100k 列上限），只有 `T` 且 ORGID+ORGNAME 完全一致才產生 `activeDirectoryListingOnly` 證據——**地址簿列名≠來源簽章驗證**。`phase6.md`、`OfficialDocumentAddressBook.swift`。
- 【確認】**合法送達**：《機關公文電子交換作業辦法》第 13 條：私人收件人由機關另訂規定 → App 不能自行把「查看」定義為法定收文/送達。目前查無自然人取得 G2B2C 地址的公開流程（人民團體申請需 XCA 憑證＋固定 IP）。索引頁摘要稱 G2C 電子公文交換出現在政府 115–119 年計畫。
- 【確認】主管機關需提供七項：資格與法律語意、註冊契約、傳輸信任（mTLS/IP allowlist）、格式版本（EN/DI/SW/ESW/DM DTD）、ESW 解密（recipient key 生命週期）、交換確認、測試證據。已備好但**未寄出**的詢問信草稿（收件 `support@archives.gov.tw`）。`phase6.md`。
- 【確認】Phase 8 DEBUG 沙盒：地址前綴 `G2C-SANDBOX-NOT-ROUTABLE-`、EN 附 ESW SHA-256、repo 自有 **Ed25519** 測試 sender key 簽 canonical target、ESW 內 DI 以 AES-256-GCM 加密；`legalEffect=noneDevelopmentSimulation`。
- 【確認】Phase 5：同意證據每次讀取重驗（MOICA chain、32-byte nonce、簽章、時間），只顯示 SHA-256 指紋，「刪除≠撤回」。
- 【推論】KMP：XML 解析需 XXE 防護（Android `XmlPullParser`/kotlinx 皆需關 DTD）；此功能目前無正式介接，建議只保留資料模型與介面，不做 UI 承諾。

---

## 6. MyData
- 【確認】取件方式：**WKWebView 直接登入 `mydata.nat.gov.tw`（使用者 session scrape，非官方資料需求方 API）**，攔截下載（`WKDownload`）。國民身分證端點 `https://mydata.nat.gov.tw/personal/detail/API.idPhotoRev`；下載為**未加密 ZIP 內一份以身分證號為密碼的加密 PDF**。登入頁 `https://mydata.nat.gov.tw/signin`，只攔截 `mobilemoica:` 導航以 App 切換。`roadmap` MyData 節、`B/scripts/check-pdf-signature.mjs`、`B/docs/mydata-compatible-return.md`。
- 【確認】PDF 密碼先原樣嘗試，失敗再 trim+大寫；錯誤可取消重輸、不重下載。`mydata-recovery.md`。
- 【確認】**八種保險箱文件**（`B/backupTW/Model/MyDataDocumentType.swift`）：財力/所得 `API.syWqjr4flJ`、勞保 `API.UZQkKbsOpz`、健保 `API.zH584wn59r`、健保費繳納 `API.1qIr0nM0BT`、納稅證明 `API.TeV2Md7SIx`、勞退 `API.yqkllwwTYl`、地籍/財產 `API.KvvyRZSc5K`、戶籍 `API.UDauDOLyZg`（路徑皆 `personal/detail/API.<code>`）；學歷不屬 MyData 項目而排除。
- 【確認】保存：`MyDataVaultArchive` 存原始檔於 Application Support、`.completeUnlessOpen`、`isExcludedFromBackup`、`.meta` 側檔記 `sha256`、副檔名、`importedAt`、`displayName`；PDF/ZIP 內 PDF 預覽、重驗指紋、重新取件、單項刪除。國民身分證 PDF **不保存**，在 `MyDataScratch`（temp、zip-slip 防護）解析後立即 purge。
- 【確認】**vc+moica 自簽憑證**（`B/backupTW/Model/MOICASignedCredential.swift`）：JSON envelope（非 JWS，故意避免被 JOSE 誤用）：`payload`（credential canonical bytes 的 base64url）、`proof{tbsConstruction="bonds-tw-credential-v1/payload-sha256-hex/RSASSA-PKCS1-v1_5-SHA256", certificate=base64 DER(來自 TW FidO result.cert), signature=base64(signed_response)}`、`issuerJWS`（每卡 did:key 簽的 compact JWS）、`disclosures[]`（SD 揭露，不在簽章內）。驗證：MOICA G3 chain、RSA 簽章（雜湊兩次：TBS 本身是 hex digest，再被 SP API SHA256）、**憑證 CN 必須等於 credential `name`**、disclosure 必須被承諾。語意：「這位持卡人主張這些值」，不是內政部背書（MyData 下載本身無簽章，2026-08-09 實測）。
- 【確認】OID4VP 中 `vc+moica` 是 Bonds 擴充 format；verifier-lite 支援（pinned MOICA G3）。`VP/README.md`。`over18AtIssuance` 述詞用於成年情境。
- 【確認】查驗情境與 `vct` 草案：`GH/vct/mydata-income|labor-insurance|household/v1.json`，`assurance: holder-derived`、`source.sha256`、`parser` 版本。`B/docs/mydata-vc-verifier-scenarios.md`。
- 【確認】索引頁摘要：「MyData 只傳輸不簽章、八小時後刪除」；建議查驗方承認這類文件。
- 【推論】Android：WebView 下載攔截用 `DownloadListener`/`shouldInterceptRequest`；`mobilemoica:` 在 Android WebView 中需 `shouldOverrideUrlLoading` 轉成 intent。WebView scrape 有被 MyData 改版、或 ToS 禁止的風險；正式應爭取資料需求方介接。

---

## 7. ZKP

### 7.1 OpenAC 年齡述詞（jwt_2k + show）
來源：`B/Native/OpenACAge/`（README、RELEASE-openac-age-v1.md、predicate.rs、build-ios.sh、*.patch）、`B/Native/OpenACAgePackage/Package.swift`、`B/backupTW/Presentation/AgePredicate*.swift`、`B/docs/zkp-web-verification-2026-09-04.md`。
- 【確認】基於 `ethereum/zkID` commit `b395e09c225ff45b003f0087c28e2e208e22f944` + Mopro 0.3.5 + witnesscalc_adapter `e5a82bc`；Spartan2/Hyrax over P-256（`ecdsa_spartan2`）；Circom 電路 `jwt_2k`（Prepare：驗 ES256 SD-JWT 發卡簽章與生日 disclosure 承諾）＋`show`（綁 `cnf.jwk` 對 verifier nonce 的簽章）；兩證明以共享承諾 link，reblind；`verify_linked` 比對 156+6 個公開值。生日欄位名候選：`roc_birthday, birthdate, birthday, date_of_birth, birth_date, 出生日期`；格式 2=ISO、3=ROC YYYMMDD；MAX_MESSAGE_LENGTH 2048。
- 【確認】需 **64 MB 專用 stack**（2K secp256r1 witness calculator 超過預設 thread stack）；建置兩個 slice 可吃 >8 GB。
- 【確認】資產（`openac-age-v1` release，gzip / 解壓）：`jwt_2k.r1cs` 28.2 MB / 374.3 MB；`show.r1cs` 0.59 / 4.0 MB；`prepare_proving.key` 23.6 / 431.9 MB；`prepare_verifying.key` 23.6 / 431.9 MB；`show_proving.key` 0.58 / 4.86 MB；`show_verifying.key` 0.58 / 4.86 MB；壓縮與解壓兩層 SHA-256 皆 pin。持卡端首次約 76 MB 下載。
- 【確認】效能：Mac release gate Prepare 19,203 ms、Show 777 ms（非手機數據）。網頁查驗：Worker 放不下 432 MB VK，轉送到 Mac 上的 Rust axum 服務 `VP/native/openac-age-verifier`（Cloudflare quick tunnel）。手機實測數據在報告內但**報告讀不到**。
- 【確認】請求 QR：`{"a":18,"b":"<UUID>","c":"<nonce>","d":"2008-09-04","p":"<用途>","s":"g"|"s","t":<秒>,"u":"https://verifier.mashbean.net/api/zkp/response/<id>","v":1}`；response host 白名單。
- 【確認】政府卡需有生日欄位（實測公路局駕照沒有 → `noBirthDate`）；自發卡由每卡金鑰派生只含 `birthdate` 的 SD-JWT，標 `selfIssued`。

### 7.2 持證證明（cert_chain_rs4096 + user_sig_rs2048）
來源：`B/backupTW/ZK/*.swift`、`B/docs/zk-verifying-key-manifest.md`、`B/NOTICE`。
- 【確認】README/NOTICE 稱 **Groth16**，經 `privacy-ethereum/openac-rsa-x509-swift`；電路 `ethereum/zkID` release `RSA-X.509-Cert-latest`（**滾動 tag**，manifest ID `ethereum/zkID:RSA-X.509-Cert-latest:2026-07-15`）。【推論】zkID 主線為 Spartan2 系，此處「Groth16」以 repo 說法為準，移植前須核對上游實際 proof system。
- 【確認】資產：`cert_chain_rs4096_proving.key` 41,321,996 B gzip → 693,663,394 B；`user_sig_rs2048_proving.key` 16,513,669 → 274,677,850；VK 為 proving key 去掉最後 32 bytes（`VerifyingKeyDerivation`，Mac 2.3 秒）；SMT 快照 `https://github.com/privacy-ethereum/moica-revocation-smt/releases/download/snapshot-latest/g3-tree-snapshot.json.gz`（**不 pin**，約每日兩次重建）。下載約 82 MB、磁碟約 950–968 MB（README 稱解壓後約 1 GB）。r1cs 不下載（會多 77.7 MB/823 MB）。
- 【確認】效能/記憶體：上游峰值證明記憶體 **1.96–2.27 GiB**（4 GB iPhone 有 jetsam 風險）；驗證兩電路 6.44 s + 2.19 s = 8.63 s，`linkVerify` 整體 14.47 s cold / 12.21 s warm（會重複驗兩次）；`ZKPackageVerifier` 12–14 s；roadmap 引「1.09 GiB／9.26 秒」。證明包 293,916 bytes（上游輸入）、**真卡實測 398,181 bytes**（iPhone 14）。
- 【確認】七條 caveat（`ZKProver.swift` `ProofCaveat`）：
  1. `signatureMaterialIsReplayable`：**TW FidO SIGN 簽的是固定 app_id 而非 verifier challenge**，`(cert, signed_response)` 是永久 bearer token，可對任何新 challenge 鑄證；內政部本身也持有此材料。只有內政部協定改動能修。
  2. `idNumberDisclosedToIssuer`：每次 SIGN 都把明文身分證號＋RP 交給內政部。
  3. `noGlobalUniqueness`：離線無 nullifier 名冊。
  4. `nullifierSharedAcrossVerifiers`：單一 `bondsAppID` → 所有查驗方看到同一 nullifier（可連結）。
  5. `certificateExpiryNotProven`：電路無日期。
  6. `revocationRootNotAnchored`：SMT root 鏈上比對未實作。
  7. `challengeNotBoundToVerifier`（條件式）：challenge 由持卡端自鑄時。
- 【確認】公開訊號無法經 iOS FFI 取出（缺 `zk_last_signals` 對等匯出，privacy-ethereum/zkID#105）→ 本機只得 Bool，無法驗 challenge/nullifier/smtRoot。
- 【確認】prover 自檢：上游對不滿足約束仍「成功」產出同尺寸 proof，唯一辨識法是跑 verifier → 產完必自驗。
- 【確認】上游 B1（未送）：`pk_commit` 隱藏性靠證明端提供新鮮 `pkBlind`（31 bytes），電路不強制 → 釘死 blind 會成為跨部署全域識別碼。`upstream-reports.md` B。
- 【確認】授權：zkID MIT；openac-rsa-x509-swift、go-zkid-verifier 現有 Apache/MIT、moica-revocation-smt 有 LICENSE（2026-08-10 複查；之前一度無 LICENSE）。`IssuerCertificate.swift` L85–96。
- 【確認】內建信任錨 `MOICA-G3.cer`（https://moica.nat.gov.tw/repository/Certs/MOICA-G3.cer）、`GRCA-G3.cer`；唯一 TODO：`IssuerCertificate.swift:68` trust-anchor。

### 7.3 Android / KMP 移植可行性【推論】
- Mopro 原生支援 UniFFI 產生 **Kotlin/Android（jniLibs `arm64-v8a`）** 綁定；OpenACAge overlay 的 `predicate.rs` 與 patch 可直接重用，改 build 腳本輸出 Android AAR（`cargo ndk`/mopro `android` target）。需在 Rust 側保留 64 MB 專用 thread stack。
- KMP 結構：`expect/actual` 包 prover 介面；Android 用 JNI(.so)、iOS 用 XCFramework（可直接用 Bonds 已發佈的 `OpenACAgeBindings.xcframework.zip`，checksum `9eb0807…`）。
- 資產 ~900 MB（年齡）～~1 GB（持證）+ ~2 GiB 峰值記憶體：Android 中低階機 LMK 風險高；需 `largeHeap` 也救不了 native 記憶體，應以裝置 RAM 門檻與 mmap 載入、串流解壓（Bonds 有串流 gzip + 大小上限）設計。
- 持證證明依賴 TW FidO SIGN（需 SP 帳號＋broker）且帶不可修的 replay caveat → 建議 Android v1 不做持證證明，只保留介面。
- 公開訊號 FFI 若用 Rust 直接自寫 uniffi，可在 Android 端一開始就匯出（避開 iOS mopro.swift 的限制）。

---

## 8. 離線驗證（Bonds 自有格式，不是 ISO 18013-5）
- 【確認】查驗方先出示挑戰 QR（`PresentationRequest`：16-byte challenge base64url、目的、`linkServiceID` 一次性 BLE service UUID）；持卡人以 W3C VC/VP over ES256 JWS（自發卡為 vc+moica）＋SD 揭露回應。`B/backupTW/Presentation/PresentationRequest.swift`。
- 【確認】**Chunked QR**（`QRTransport.swift`）：`BTWVP1:<Z|U>:<10 hex id>:<NN>:<NN>:<base45 chunk>`（Z=DEFLATE），全大寫以維持 QR alphanumeric mode；版本上限 18（89×89 模組）、EC level Q；每 frame 574 字元 = 364 payload bytes；最多 99 frames；重組上限 64 KB；id=payload digest，重組後驗 digest。卡簽 presentation 約 7.4–8 KB → **約 14–16 frames、輪播近 9 秒**。
- 【確認】**BLE**（`BluetoothLink.swift`、`LinkTransport.swift`）：持卡人＝peripheral 廣播一次性 service UUID、查驗方＝central（借用 ISO 18013-5 角色，但**不實作 session encryption**，明文傳輸，靠簽章＋challenge 防偽）。characteristic `2B1D0001-6B4E-4C3A-9E2F-4A7C51E0D9A1`（frames，notify）、`2B1D0002-…`（state，寫 0x01 表示收到）。frame header 10 bytes：version(1)=1、flags(1, bit0 DEFLATE)、total(2, BE)、index(2, BE)、transfer id(4)；payload 上限 1 MB、chunk 上限 4096；MTU 實務 185–512。ZK 證明包（~398 KB）只能走 BLE（QR 需 ~808 frames）。
- 【確認】快取信任：TWDIW 卡用收卡時存的 `OfflineIssuerTrustSnapshot`；MOICA 撤銷用本機 SMT 快照（說法須帶日期：「在這支手機上這份 <日期> 的撤銷名單裡未列為撤銷」）。`RevocationSnapshot.swift`。
- 【確認】自家 TrustList 承諾值曾可碰撞（`\t`/`\n`），部分修補，「任何承諾值都不可公開」。`trust-chain-recommendation.md`。
- 【確認】證件查驗與 ZK 查驗兩種 QR 不能互換（ZK 為配對 QR、challenge 自鑄）；合併提案待拍板。`proposal-unified-checker.md`。
- 【推論】Android：BLE peripheral 模式需 `BLUETOOTH_ADVERTISE`/`CONNECT` 權限且部分裝置不支援 peripheral；若要與 Bonds iOS 互通，需逐位元組實作 BTWVP1 與 LinkTransport。Multipaz 內建的是 ISO 18013-5 mdoc BLE（含 session encryption），兩者不相容——建議 KMP 版以 Multipaz/18013-5 為主，BTWVP1 作為選配相容層。

---

## 9. 上游問題與風險（`B/docs/upstream-reports.md`，**全部未送出**）
TWDIW（依使用者受害程度）：
- A1 選擇性揭露子字串比對多送欄位（可送）。
- A2 驗證端四個 fetch `setAllowedHostnames(null)` → 自訂 HostnameVerifier 恆 true，TLS 主機名驗證失效（含取 JWKS）（送前須確認是否已修）。
- A3 status list/schema 在驗簽前平行抓取（SSRF；`StatusListCheckTask` 直接走 jku）。
- A4 `client_id` 無鑑別力、ID Token 未驗、AccessTokenFilter 註解掉。
- A5 metadata `format` 882/882 寫 `jwt_vc_json` 實為 `vc+sd-jwt`。
- A6 VP 用 `context` 非 `@context`（對做 JSON-LD 展開的第三方才是問題）。
- A7 holder DID 非 JCS（暫緩，n=1）。
- A8 憑證無離線可讀名稱。
- 附：發行者 did:key 無法輪替金鑰（換鑰＝換身分，已發卡集體無法評估）。
zkID：B1 `pk_commit` 隱藏性依賴證明端。
其他風險（`integration-plan` §六、`roadmap` 風險節）：政策窗口（wallet attestation）、身分證號進裝置的資料風險、沙盒條款、上游修正後相容 hack 反向壞掉（每個 hack 註明日期與移除條件）、Release 簽章天花板、MyData 明文保存法遵、寬鬆揭露誤放偽造。

## 10. Roadmap 未完成項目（`B/docs/roadmap-2026-08-27.md` + 後續 checkpoint）
- 真實電信卡 offer 結構（mitmproxy 觀察）、台灣大 issuer host 是否在清單、非字串揭露處理、電信卡是否 auth-code grant。
- MyData：真帳號逐項驗證八種文件、`PDFSignatureScan` 定案（MyData PDF 是否帶機關簽章）、非 PDF 格式檢視器。
- ZK：Release 端到端（broker）、公開訊號 FFI、per-verifier nullifier、SMT root 鏈上錨定、能力頁誠實化（`.partial`）。
- 後端：broker B1–B4、I1–I3、Q1（約 30–50 工程日）；TestFlight／App Store 未上。
- 上游回報送出（需決定身分/條數）；`moda_dw` 收斂為具名常數。
- IdentityReset 兩缺陷（鎖定時「檔案沒了金鑰活著」、自家探針被算殘留）。
- 連儂牆（`backupTW/Wall/` 8 模組）寫好未接 UI。
- AASA/Universal Links 失效（GitHub Pages 回 `application/octet-stream`、缺 Associated Domains entitlement；`GH/.well-known/README.md`）。
- CI 不跑 UI 測試、無覆蓋率門檻。
- PR #56/#57 與 main 衝突待整合；Passkey 只有評估。
- 電子公文：主管機關介接全部待取得。
- issue 編號（文件引用）：#26（TrustList expectedCommitment 來源）、#38（Release 簽章 ADR）、#41（Arbitrum 收卡閘門真機觀測）、#42–#47（broker/App Attest/session/VK/UAT 矩陣）、#48（公開訊號 FFI 與查驗責任）、PR #65/#69（MyData 相容）。**issues 頁內容未能讀取。**

## 11. 姊妹專案（測試對手方）
- `issuer.mashbean.net`（`VC/`）：Cloudflare Worker 實作 OID4VCI pre-auth，發 TWDIW 方言卡（`kid: "<did>#0"`、16-byte salt、`_sd` 排序、`vc.type[1]` 含 `sandbox`、StatusList2021 `/status/1` 由同一把發行者金鑰簽）；預授權碼與 access token 為 `<session id>.<secret>`；token 端收 `client_id=moda_dw`（回音）。只信任自己 DID 的 OID4VP 驗證端。Bonds **Release 也信任**其釘住的 DID（`TWDIWIssuer.mashbeanSandbox`，2026-09-09 決定；`VC/docs` 文字仍寫「Release 不含」，已過時）。
- `verifier.mashbean.net`（`VP/`）：一鍵部署 OID4VP 驗證端；官方皮夾用 `modadigitalwallet://authorize`、Bonds 用 `openid4vp://`；request 同時含 PE 與 DCQL；三層結果（issuer trust／密碼學／policy）；不持久化個資；資安自查 `VP/docs/security-audit-2026-09-03.md`。
- 【推論】兩者是 Android 版最好的整合測試對手（無需真政府卡），但正式信任時應與 Release 嚴格分區（Bonds 的「模擬卡」分區設計可直接沿用）。

## 12. 授權與可重用程度
- 【確認】Bonds-iOS：**Apache-2.0**（`LICENSE`、`NOTICE`）；可移植邏輯到 Kotlin，須保留版權與 NOTICE、標註修改。
- 【確認】`twdiw-vp-verifier-lite`、`twdiw-vc-issuer-lite`：**GPL-3.0**——不可把其程式碼併入 Apache/閉源 App；作為外部服務互動測試不受影響。【推論】可參考其協定文件，但重寫時避免逐行移植。
- 【確認】`bonds-tw.github.io`：無 LICENSE 檔（預設保留所有權利）；vct JSON 與筆記只宜引用。
- 【確認】`open-gpki-pkcs11`：LGPL-2.1+；zkID：MIT；Mopro：Apache/MIT；openac-rsa-x509-swift：Apache/MIT；TWDIW-official-app：MIT；Zip(marmelroy)：MIT。
- 【推論】重用度評估：
  - 高（直接翻成 Kotlin 規格）：OID4VCI/VP 方言參數、jwk_jcs-pub did:key、SD-JWT digest 規則、信任清單分頁、Arbitrum ABI、sp_checksum/idp_checksum 演算法、超商 401/402 流程、閘門 URL 正規化規則、BTWVP1/LinkTransport 線格式、測試向量（`GH` 兩個真實 DID、`_sd` 驗算範例）。
  - 中：OpenACAge Rust overlay（Android build 需重做）、vc+moica envelope（自家擴充，非標準）。
  - 低／不建議：UIKit 畫面、App Attest 細節（需改 Play Integrity）、Mac+USB 實體卡流程、MyData WebView scrape（法遵與穩定性風險）。

## 13. 給 KMP/Multipaz 版的具體落差清單【推論】
1. Multipaz SD-JWT 預期 IETF SD-JWT VC（頂層 claims、`vct`、KB-JWT）；TWDIW 需自訂 parser（`vc.credentialSubject._sd`、無 KB-JWT、`typ vc+sd-jwt`）。
2. Multipaz OID4VCI/OID4VP 客戶端需可插拔：`client_id=moda_dw`、proof `iss=moda_dw`、`aud` 補斜線、metadata `format` 忽略、request object 金鑰取自 `client_id` did:key、vp_token header `jwk`、`aud`=DID、`context` 無 @、`presentation_submission` 巢狀 `jwt_vp`/`jwt_vc`。
3. did:key 0xEB51 編解碼與寬容解析。
4. HTTP 客戶端 UA/TLS 指紋過 Cloudflare 1010（最先驗證）。
5. 一卡一金鑰（Android Keystore/StrongBox，tag 用不透明隨機 handle，列舉 Keystore 當真相來源）；`IdentityReset` 等抹除流程需涵蓋所有 alias。
6. 撤銷三態＋清單 `exp` 顯示；狀態清單 key-2 無信任錨。
7. Release 簽章 broker 的 Android 證明（Play Integrity + Key Attestation）。
8. Deep link：`openid-credential-offer`、`openid4vp`、（評估）`modadigitalwallet`、`mobilemoica` 回呼。
9. 每一個相容 hack 加上「日期／原因／上游修好後移除」註解（Bonds 的紀律）。

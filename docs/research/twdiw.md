# TWDIW 官方 App 與 core-system 互通性調研筆記

> **研究資料的時間點說明：** 本文保留編寫時的技術比較與來源，不代表現在的功能完成度或最新規格版本。請以 [2026-10-16 專案狀態矩陣](../status-2026-10-16.md)確認 PR #11 的新實作及剩餘缺口。個人錢包依公開規格支援行動自然人憑證、CSC 及公文檔案，正式服務帳號／機關交換資格不屬必須完成的程式功能。

- 調研對象：moda-gov-tw/TWDIW-official-app，本地 commit 99e9deb（2026-07-27）
- 本地路徑：scratchpad/src/TWDIW-official-app。下文路徑都以 repo 根目錄為準。
- 目的：用 KMP + Compose Multiplatform 撰寫第三方皮夾（Android 先行），並與 TWDIW 互通。
- 標記說明：
  - 【已確認】：已讀過程式碼、文件或網頁。
  - 【推論】：由證據推得，尚未實測。
- 行號以本次閱讀為準。重構後可能偏移，以檔名與函式名為主要依據。

---

## 0. 結論先講

1. **TWDIW 不是標準的 OID4VCI 1.0、OID4VP 1.0 或 SD-JWT VC 實作。** 它是「OID4VCI draft-13 風格 + W3C JWT-VC 包 SD-JWT 揭露 + OID4VP draft（PE v2、jwt_vp）」，再加上多項私有約束。第三方皮夾必須做一個「TWDIW 相容 profile」，不能只靠標準函式庫。
2. **發證時的硬性條件【已確認】：**
   - `client_id=moda_dw`。
   - proof 的 `iss=moda_dw`。
   - proof 的 `kid` 必須是 `did:key:z<base58btc(0xd1 0xd6 0x03 + JWK JSON)>`，即 jwk_jcs-pub。
   - token 請求必須帶 `authorization_details`，且帶 `tx_code`（可以是空字串）。
   - 符合以上條件，就能拿到憑證。
3. **出示時的硬性條件【已確認】：**
   - VP 是 `jwt_vp`。
   - VP 由 holder 私鑰簽章，且該私鑰必須等於 VC 的 `cnf.jwk`。
   - VP 的 `aud` 等於 client_id（verifier 的 DID），`nonce` 等於 request 的 nonce。
   - VP 必須帶 `jti`、`nbf`、`exp`。
   - VP 以 form `direct_post` 送出。
   - 不使用 KB-JWT。
4. **入口 scheme：** 是 `modadigitalwallet://credential_offer?...` 與 `modadigitalwallet://authorize?...`，外層再包一層 https 的 QR wrapper。第三方皮夾無法註冊 App Links 的 `frontend.wallet.gov.tw`，只能靠「掃 QR 後自行解析」或「註冊同名自訂 scheme」。後者有衝突與政策風險。
5. **官方皮夾自身的已知缺陷：** SD 揭露選擇採子字串比對（issue #28），且不驗 request object 簽章。第三方皮夾應修正這兩點，不應照抄。

---

## 1. APPSDK（Flutter / Dart，APP/APPSDK/lib）

### 1.1 介面【已確認】

- `message_handler.dart:10` 定義 MethodChannel `did_sdk_channel`，SDK_VERSION 為 `0.0.1`。
- `message_handler.dart:28-158` 是方法清單：
  - `getVersion`
  - `initKx{keyTag,type,PIN}`
  - `generateKey`、`generateDID`
  - `applyVC{didFile,qrCode,otp}`、`decodeVC`
  - `verifyVC{credential,didFile,frontUrl}`
  - `verifyVCOffline{credential,didFile,issList,vcList}`
  - `parseVPQrcode{qrCode,frontUrl}`
  - `generateVP{didFile,request_token,vcs,custom_data}`
  - `generateVPNFC`、`verifyVPNFC`
  - `downloadIssList{url}`、`downloadAllVCList`
  - `transferVC`
  - `sendRequest{url,type,body}`、`sendJWTRequest{url,payload,didFile}`
- 簽章頻道的原始碼與二進位不一致：
  - `openid_vc_vp.dart:13-14` 宣告簽章頻道為 `com.example.flutter_method_channel_example/keyxentic`，方法為 sign、getP256Key、init。
  - 預編譯 flutter_release AAR 的 libapp.so 字串卻是 `com.flutter_method_channel/gov.moda.dw`，與 TokenSDKManager 一致。
  - 【推論】公開的 Dart 原始碼不是實際上架二進位的完整來源。

### 1.2 OID4VCI：applyVCKx（`openid_vc_vp.dart:20-95`、`http_service.dart`）【已確認】

1. **解析 offer**
   - 用 `qrCode.split('credential_offer_uri=')[1]` 取出網址，再 `Uri.decodeFull`。
   - 只支援 by-reference 的 `credential_offer_uri`，不支援 by-value 的 `credential_offer`。
2. **取得 offer**
   - GET offer，從中取出 `grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]`、`credential_configuration_ids[0]` 與 `credential_issuer`。
3. **取得 metadata**
   - GET `'$credential_issuer' + '.well-known/openid-credential-issuer'`（`http_service.dart:38`）。
   - 這是「附加式」路徑，而且依賴 credential_issuer 以 `/` 結尾。
4. **token 請求**
   - POST `${credential_issuer}token`，form-urlencoded（`http_service.dart:56-90`）。
   - 參數：
     - `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`
     - `client_id=moda_dw`
     - `pre-authorized_code`
     - `authorization_details=[{"type":"openid_credential","credential_configuration_id":"..."}]`
     - `tx_code`
   - 只讀取回應中的 `access_token` 與 `c_nonce`。
5. **proof JWT**（`openid_vc_vp.dart:58-70`）
   - header：`{alg:ES256, typ:"openid4vci-proof+jwt", kid:<did>}`。kid 是裸 DID，沒有 `#fragment`。
   - payload：`{iss:"moda_dw", aud:credential_issuer, iat, nonce:c_nonce}`。
6. **credential 請求**
   - POST `${credential_issuer}credential`，帶 Bearer token。
   - body：`{"credential_identifier":cfgId,"proofs":{"jwt":[jwt]}}`。
   - 只讀取回應的 `data["credential"]`（`http_service.dart:92-127`）。
7. **其他**
   - timeout 為 10 秒（`http_service.dart:5`）。
   - 錯誤碼：2011 至 2014；9999 代表網路錯誤。

### 1.3 VC 驗證（`openid_vc_vp.dart:113-210`）【已確認】

- **信任查詢**
  - GET `{frontUrl}/api/did/{iss}`（`http_service.dart:131`）。
  - `status==1` 視為可信；`org` 中有 `x509_type` 時給 trust_badge。
- **狀態查詢**
  - GET `credentialStatus.statusListCredential`，回應為 `{statusList: <jwt>}`。
  - 取 `vc.credentialSubject.encodedList`，經 base64 與 gunzip 後轉成 bits；`bit[statusListIndex]==0` 視為有效（`checkVCValid`，第 593-609 行）。
  - **不驗 statusList JWT 的簽章。**
- **holder 綁定**：檢查 `sub == 自己的 did`。
- **exp**：直接與現在時間比較，沒有 skew 容忍。
- **簽章**
  - 只驗 `~` 之前的 JWS。
  - 公鑰取自 issuer DID 的 `verificationMethod[0].publicKeyJwk`。DID document 由 frontend 的 `/api/did` 取得，不是本地解析 did:key。
- **離線驗證**：`verifyVCOffline`（第 214-319 行）以 `sha256(vc)` 作為 key，與下載的狀態清冊比對。
- **發行者清單**：`downloadIssList` 呼叫 GET `/api/did?size=20&page=N&orgType=1&status=1`（`http_service.dart:174`）。

### 1.4 OID4VP（`openid_vc_vp.dart:398-533`、`http_service.dart:214-244`）【已確認】

- **parseVPQrcode**
  - 以 `split('request_uri=')` 再 `split('&')` 取出 request_uri，然後 GET。
  - 回應的 body 只做 decode：**不驗 JAR 簽章**，也不檢查 typ、iss、aud、exp。
  - 若 client_id 含 `did:`，查詢 `/api/did/{client_id}`；查不到時回傳 4012，App 仍可繼續。
- **parsePresentationDefinition**（第 613-668 行）的固定假設：
  - `fields[0].filter.contains.const` 是卡片類型。
  - `fields[1..].path[0]` 以 `credentialSubject.` 切分，得到欄位名。
  - 支援 `submission_requirements` 的 group、from、rule、count、max。
- **generateVPKx**（第 441-533 行）
  - **SD 選擇**：`utils.dart:121` 使用 `decoded.contains(field)`，是子字串比對，可能多揭露（issue #28）。
  - **VP JWT header**：`{typ:"JWT", alg:"ES256", jwk:<holder JWK>}`。
  - **VP JWT payload**：
    - `sub` 與 `iss` 都是 holder DID；`aud` 為 client_id。
    - `nbf=now`，`exp=now+30天`，`nonce` 取自 request。
    - `jti="https://digitalwallet.moda:8443/vp/api/presentation/<uuid>"`，網域寫死。
    - `vp={context:[...], type:["VerifiablePresentation"], verifiableCredential:[<SD-JWT 字串>]}`。注意用的是 `context` 而不是 `@context`（issue #32）。
  - **presentation_submission**：`{id, definition_id, descriptor_map:[{id, format:"jwt_vp", path:"$", path_nested:{id, format:"jwt_vc", path:"$.vp.verifiableCredential[i]"}}]}`。
  - **custom_data**：使用同一個 header 簽 JWT，payload 為 `{"customData":[{cname,ename,value}]}`。
  - **送出**：POST response_uri，form-urlencoded，欄位為 `state`、`vp_token`、`presentation_submission`、`custom_data`。
    - 以 JSON `code==0` 判定成功。
    - **不處理 `redirect_uri` 與 `response_code`。**
- **NFC 與轉移**
  - `generateVPNFC`：`aud` 為自己的 DID，nonce 為隨機 uuid。
  - `verifyVPNFC`：是未完成的 stub（第 576-589 行）。
  - `transferVC`：POST `{vc.jti}/transfer`。

### 1.5 did:key（`did_key_gen.dart:106-123`）【已確認】

- 計算方式：`did = "did:key:z" + base58btc([0xd1,0xd6,0x03] + utf8(JWK JSON 字串))`。
  - 0xeb51 是 jwk_jcs-pub 的 multicodec，0xd1d603 是它的 varint 編碼。
- **沒有做 JCS 正規化**。JSON 字串由 native 端產生，key 順序為插入順序 kty、crv、x、y（issue #16 第 3 點）。
- DID document：
  - `@context` 為 `[did/v1, jws-2020]`。
  - VM 的 id 為 `did:key:X#X`，type 為 `JsonWebKey2020`。
- 【推論】第三方皮夾必須逐字節重現官方 JSON 字串（欄位順序、無空白），否則 DID 雖然可被 server 解碼，卻與官方 App 產出的不同。不過 server 只是解碼 JWK，所以任意合法 JSON 都可用（見 4.1）。

### 1.6 SD-JWT 處理（`utils/utils.dart`）【已確認】

- **sdJwtDecode** 支援兩種 disclosure：
  - 3 元素的 `[salt,name,value]`。
  - 2 元素的陣列元素，以 `credentialSubject[key][0]['...']` 比對 sha256。
- **verifySignature** 使用 PointyCastle ECDSASigner。

---

## 2. Android App（APP/moda-digitalwallet-holder-androidapp）

### 2.1 建置與 Manifest【已確認】

- `app/build.gradle.kts`：
  - applicationId 為 `tw.gov.moda.diw`，minSdk 28，targetSdk 35，`isMinifyEnabled=false`。
  - prod flavor 的設定：
    - `DID_ISSUER_URL=https://frontend.wallet.gov.tw`
    - `CITIZEN_DIGITAL_URL=https://issuer-moica.wallet.gov.tw`
    - `OFFICIAL_IMAGE_URL=https://www.wallet.gov.tw`
    - `APPLINK_HOST=frontend.wallet.gov.tw`
- `AndroidManifest.xml`：
  - App Links：https、`${APPLINK_HOST}`、pathPrefix `/api/moda/qrcode`，並設 `autoVerify`。
  - 自訂 scheme `modadigitalwallet`。
  - `uses-feature nfc required=true`。
  - `allowBackup=false`。
  - network_security_config 只信任系統 CA，**沒有 certificate pinning**。

### 2.2 Deep link 與 QR【已確認】

- `AppConstants.kt` 的 Deeplink 定義：
  - SCHEME 為 `modadigitalwallet`。
  - host 有 `credential_offer`、`authorize`、`staticqrcode`。
  - `staticqrcode` 帶 `mode=vc|vp` 與 `vpUid`/`vcUid`。
- `DeeplinkManagerImpl.kt:33-67` 只接受兩種輸入：
  - 上述三種 host。
  - 包含 DID_ISSUER_URL 且帶 `?type=` 的 https 網址。
  - **`openid-credential-offer://` 與 `openid4vp://` 會被拒絕。**
- **靜態 QR 流程**
  1. GET `{DID_ISSUER_URL}/api/moda/dwapp/serviceUrl/{uid}?mode=`。
  2. VP 情境下，再 GET `{verifierServiceUrl}/{vpUid}` 取得 deepLink。對應代號為 `DwModa201i` 與 `DwVerifierMock101i`。
- **清單**
  - `/api/moda/dwapp/apply/vcList`（DwModa301i）
  - `/api/moda/dwapp/offline/vpList`（DwModa401i）
- QR 外層格式（issue #15）：https 的 `vcqrcode` URL，`deeplink` 參數以 base64 包著 `modadigitalwallet://...`。

### 2.3 DWVP-05 離線出示（私有）【已確認】

程式位置：`ShowCredentialViewModel.selectShowCredential`、`VerifiablePresentationViewModel.generateBarcode`、`ShowCredentialBarcodeViewModel`。

1. GET `{verifierModuleUrl}/api/ext/offline/qrcode/{vpUid}`，回應為 `{transactionId, deepLink, description, fields}`。
2. 走一般 OID4VP 流程送出 VP。
3. 以 `sendJWTRequest`（moda-201i）呼叫 `{verifierModuleUrl}/api/ext/offline/getEncryptionData`。
   - body 為 `{jwt: 以 holder DID 金鑰簽章的 {transactionId}}`，header 帶 `kid=did`。
4. 回應為 `{qrcode: base64 PNG, totptimeout}`。App 顯示該 QR 並倒數，預設 60 秒。
5. QR 內容為 `{t,d,h,k}`（見第 5 節）。產生與加密由 verifier 端完成；**皮夾只負責顯示圖片**。
   - 【推論】第三方皮夾只要能完成步驟 1 至 3，並顯示伺服器回傳的 PNG，即可支援 DWVP-05。

### 2.4 儲存【已確認】

- **Room**
  - DB 名為 `DigitalWallet_Secret`，版本 11，使用 `fallbackToDestructiveMigration`（`AppConstants.kt`、`ApplicationModule.kt:129-138`）。
  - 資料表：wallet、verifiable_credential、issuer、card_record、credential_record、presentation_record、operation_record、favorite_show_credential、search_record。
  - VerifiableCredential 的欄位：credential（完整 SD-JWT）、types、credentialSubject、status、invalidReason、imageBase64、trustBadge 等。
    - status：0 失效、1 正常、2 過期、3 未知。
- **SQLCipher**
  - passphrase 為 20 bytes 隨機值的 base64，存在 EncryptedSharedPreferences。
  - EncryptedSharedPreferences 使用 AES256_SIV/GCM，MasterKey 盡量用 StrongBox。
  - pref 名稱為 `MODA_DATA`，前綴 `MODA_WALLET_`。
- **PIN**
  - 新建時 `pincode = sha256(pin + keyTag)`（`CreatePinCodeViewModel.kt:65`）。
  - 變更時 `WalletManagerImpl.changePinccode`（第 112-117 行）改用 `sha256(pin + randomSalt)`。前後不一致，屬 bug。
  - 雜湊沒有使用 KDF，兩位數或六位數的 PIN 可以被暴力破解。
- **keyTag**：`UUID.nameUUIDFromBytes(20 隨機 bytes)`，同時作為 KeyStore 別名。

### 2.5 生物辨識【已確認】

- `ModaBiometricManagerImpl` 使用 `BIOMETRIC_STRONG|DEVICE_CREDENTIAL`，**沒有 CryptoObject**。
- 金鑰 `MODA_DIGITAL_BIOMETRIC` 未設 `setUserAuthenticationRequired`。
- 結論：生物辨識只是 UI 閘門，簽章金鑰沒有綁定使用者驗證。

### 2.6 SDK 呼叫對應（`KxIdentifierManagerImpl.kt`）【已確認】

| 代號 | 對應方法 |
|---|---|
| dwsdk-101i | generateKey |
| dwsdk-102i | generateDID |
| dwsdk-103i | initKx(keyTag, "platform", "") |
| dwsdk-201i | applyVC |
| dwsdk-301i | verifyVC |
| dwsdk-302i | verifyVCOffline |
| dwsdk-401i | parseVPQrcode |
| dwsdk-402i | generateVP |
| dwsdk-501i | decodeVC |
| dwsdk-601i | downloadIssList |
| dwsdk-602i | downloadAllVCList |
| moda-101i | sendRequest |
| moda-201i | sendJWTRequest |

錯誤碼對應見第 355-401 行。

### 2.7 tx_code（OTP）【已確認】

- **Android**：`WalletRepositoryImpl.mVerificationCode` 預設為 `""`。UI 沒有呼叫 `setVerificationCode`，所以實際送出 `tx_code=`（空字串）。
- **iOS**：`CustomTabBarViewModel.swift:68` 隨機產生兩位數 otp。
- **UI 流程**：strings 中的「顯示驗證碼」是反向流程，使用者把 App 顯示的碼輸入到發行端網站。
- **錯誤碼**：`sdk_error_code.xml` 中 11032 代表 tx_code 不符。
- 【推論】正式環境的多數情境未開啟 enable_tx_code；若開啟，則 tx_code 由 App 產生、使用者輸入到發行端網站，與 OID4VCI 原意（發行端給碼、使用者輸入到錢包）相反。

### 2.8 裝置安全、NFC 與 libs【已確認】

- **裝置安全**
  - 原始碼中沒有 root 偵測，也沒有 Play Integrity；只有 ProviderInstaller 與 Google Play Services 檢查。
  - issue #11（2026-01-23）要求「放寬裝置安全檢測」，暗示上架版有 root 或 bootloader 檢測。
  - 【推論】上架版與公開原始碼不同，與 1.1 的頻道名不一致相呼應。
- **libs**
  - `nfc-release.aar`：`tw.gov.moi.eid` IsoDepReader，讀取內政部自然人憑證或 eID。
  - `PermissionCheck.aar`：中華電信 CheckCert，處理 X.509。
  - `moda-digitalwallet-holder-sdk.aar`：預編譯的 token SDK，含 KeyXentic kx701 智慧卡（`com.keyxentic.kxsmarttokenkits`）、signKx701、startScan。
- **App 不內建信任清單**：每次都即時查詢 frontend 的 `/api/did/{did}`，離線時改用已下載的 issList。

---

## 3. Token SDK（APP/APPSDK/moda-digitalwallet-holder-androidapp-token-sdk）【已確認】

- **TokenSDKManager.kt**
  - 頻道為 `com.flutter_method_channel/gov.moda.dw`。
  - 方法：`init{tag,type,pin}`（只支援 type `platform`）、`getP256Key`、`verifyUser`、`sign{header,payload}`、`delete`、`cancel`。
- **ModaDidKey.kt:142-196**
  - 別名為 keyTag，存於 AndroidKeyStore，EC secp256r1，用途為 SIGN|VERIFY，摘要為 SHA256。
  - 先試 StrongBox，失敗時退回一般 TEE 金鑰。
  - 沒有 user-auth 綁定，PIN 參數未使用。
  - 簽章演算法為 SHA256withECDSA。
- **JWSCreator.kt**
  - `parseDerSignature` 只處理單位元組長度，再用 `toFixedLengthBytes` 補成 32 bytes 的 r 與 s。
  - `publicKeyToJwk` 使用 `BigInteger.toByteArray()`，有 bug：x 或 y 可能是 33 bytes（前導 0x00），也可能少於 32 bytes。
  - 【推論】約 1/256 機率產生非標準 JWK，導致 did 與 cnf.jwk 異常。KMP 實作應固定輸出 32 bytes。
- **ModaNFCReader.kt**（IsoDep 傳送 VP）
  1. SELECT AID `F2 23 34 45 56 68`。
  2. 以 255 bytes 分段傳送。
  3. 送出結束標記 `FF FF FF FF`。
  4. 以 `00 A4 00 00 04 'resp'` 輪詢回應。
  - 接收端 `verifyVPNFC` 尚未實作，屬未完成功能。

---

## 4. core-system 四個 handler

### 4.1 twdiw-oid4vci-handler：`CredentialIssuer.java`，`@RequestMapping("/api/issuer/{id}")`【已確認】

- **POST /qr-code**（第 130-693 行，發行端後台呼叫）
  - 讀取 id_token 的 sub、aud、exp、nonce、credential_configuration_id、tx_code。其中 aud 成為 pre-auth 的 client_id。
  - **不驗 id_token 簽章。**
  - pre-auth code 的 TTL 為 10 分鐘。
  - `credential_offer_uri = issuerId + path + "?nonce=..&sub=<uid_enc>"`。
  - `link = app_url_scheme + "credential_offer_uri=" + 編碼後網址`。
- **GET /credential-offer-object**（第 695-1061 行）
  - **非冪等**：第一次取用後狀態改為 CHANGE，重複取用回 11023。第三方皮夾不可預抓或重試。
  - 若 cids 有值，會撤銷舊卡。
  - enable_tx_code 開啟時加入 `tx_code`，例如 `{"length":2,"input_mode":"numeric",...}`。
  - `credential_configuration_ids` 只有一個元素。
- **GET /.well-known/openid-credential-issuer**（第 1063 行）
  - 回傳 DB 中的 metadata。
  - **沒有 AS metadata**（`/.well-known/oauth-authorization-server` 回 404，見 issue #16）。
- **POST /token**（第 1118-1437 行）
  - `client_id` 與 `authorization_details` 都是必填。
  - pre-auth 以 `(client_id, code)` 查找。client_id 必須是 `moda_dw`，因為 issuer-api 的 `VCItemDataService.java:151` 把 aud 寫死為 `moda_dw`。
  - tx_code 只在開關開啟時比對。不過 issue #16 實測 UAT 會拒絕「缺少 tx_code」，只接受 `tx_code=`。
  - 回應：`access_token`（TTL 600）、`token_type`、`expires_in`、`c_nonce`、`c_nonce_expires_in`、`authorization_details`（含 credential_identifiers）。
- **POST /credential**（第 1439-1888 行）
  - `credential_identifier` 必填，且必須在 offer 的 ids 內。
  - 只使用 `proofs.jwt[0]`。
  - kid 必須以 `:` 切成剛好 3 段，並以 d1d603 前綴解碼出 JWK。
    - 不接受 `#fragment`，也不接受 `jwk` header（issue #16 第 5 點，錯誤碼 11016）。
  - typ 必須是 `openid4vci-proof+jwt`；alg 必須在 metadata 列表內。
  - `iss` 必須等於 client_id（`moda_dw`）；`aud` 必須等於 offer 的 credential_issuer。
  - nonce 必須等於 c_nonce。只有 ES256 會驗簽，iat 不檢查。
  - 錯誤時回傳新的 c_nonce。
  - 回應為 `{"credential":"<sd-jwt>"}`。
- **credential_issuer 格式**：`https://HOST/oid4vci/api/issuer/{businessId}/`，有結尾斜線（`SequenceService.java:443-452`）。
- **metadata 內容**（由 issuer-api 的 `SandBoxUtil.java:249-275` 產生）
  - `format:"jwt_vc_json"`。
  - `cryptographic_binding_methods_supported:["jwk"]`。
  - `credential_signing_alg_values_supported` 為 ES256，`proof_types_supported.jwt` 為 ES256。
  - configuration id 為 `orgId_serialNo`，含 display 與 background_image。
  - 【推論】metadata 裡的 credential_issuer 為 credentialIssuer+orgId，可能缺結尾斜線，與 offer 不一致。皮夾應做寬鬆比對。
  - background_image.uri 回傳 `text/plain` 的 data URI 字串，不是圖片 bytes（issue #16 第 6 點）。

### 4.2 twdiw-vc-handler（簽發與狀態）【已確認】

- **CredentialPrepareTask.java**
  - 以 authlete `SDObjectEncoder` 處理 credentialSubject：沒有 decoy，帶 `_sd_alg`。
  - VC 為 W3C VCDM 1.1 的 JWT 形式（`vc` claim）。
  - `credentialStatus` 是兩個 `StatusList2021Entry` 的陣列（revocation 與 suspension），id 格式為 `.../api/status-list/{type}/{r|s}{gid}#idx`。
  - 含 `credentialSchema`（JsonSchema）；狀態清單大小為 16KB。
- **CredentialSignTask.java**
  - header：`typ:"vc+sd-jwt"`（`Definition.java:28`）、`alg:ES256`、`kid`、`jku=.../api/keys`。
  - payload 額外放隨機 8 字元 `nonce`，以及 `cnf.jwk`（holder 公鑰）。
  - 序列化為 `jws~disc1~disc2~`。
  - **沒有 `vct`**，也沒有簽章過的顯示名稱（issue #33）。
- **StatusList**
  - GET `/api/status-list/{type}/{group}`，回應為 `{statusList: <StatusList2021Credential JWT>}`。
  - bitstring 經 GZIP 後 base64；位元順序為 MSB-first，1 代表撤銷或停用。
- **手機轉移**：以 `genIdToken` 產生 id_token，aud 同樣是 `moda_dw`。
- **TLS**：`HttpUtils.java:776,798,806` 有 EmptyTrustManager，對所有憑證皆信任（issue #29）。vp-handler 中也有同樣的程式（`HttpUtils.java:579,601,609`）。

### 4.3 twdiw-oid4vp-handler（verifier 前端協定）【已確認】

- **端點**：`OidvpEndpointController`，前綴 `/api/oidvp`
  - `GET qr-code`：client_id scheme 為 DID，JAR 以 REFERENCE 傳遞，response_mode 為 `direct_post`。
  - `GET request/{state}`：回傳 `application/oauth-authz-req+jwt`。
  - `GET presentation-definition/{state}`。
  - `POST authorization-response`：form 參數 vp_token、presentation_submission、state、custom_data。
  - `POST result`。
- **設定**（`oidvp_config_release.csv`）
  - endpoint-schema 為 `modadigitalwallet://authorize`。
  - response_uri 為 `domain/api/oidvp/authorization-response`。
  - request_uri 為 `domain/api/oidvp/request/{state}`。
  - session 預設 5 分鐘。
- **client_id**：裸 DID，沒有 `client_id_scheme`，也沒有 `decentralized_identifier:` 前綴（`OidvpClientIdentifier.java:57-63`）。
- **request object**（`OID4VP.java:154-208`）
  - typ 為 `oauth-authz-req+jwt`，`iss` 與 `aud` 都是 DID，帶 `exp`，以 DID 金鑰簽章。
  - 【推論】`aud` 不是 `https://self-issued.me/v2`，與 OID4VP 1.0 不同。
- **verifier DID**：同樣是 d1d603 的 jwk 格式（`DIDUtils.java:13-43`），由 `frontend.wallet.gov.tw/api/did/*` 產生並註冊。
- **vp_formats**：`jwt_vp` 與 `jwt_vc`，皆為 ES256（`MetadataEntity.java:104-118`）。FormatRegistry 另列 jwt_vc_json、ldp、vc+sd-jwt。
- **驗證**
  - `VerifierService.validateClientIdAndNonce`：VP 的 `aud` 必須等於 client_id，`nonce` 必須等於 session nonce。
  - `CustomDataValidator`：以 holder DID 的金鑰驗 custom_data 簽章，claim 名為 `customData`。
  - vp_token 可以是 JWT 字串、JSON 物件或陣列。
- issue #17：PE 的完整評估（JSONPath、filter）在後端。官方皮夾只拿到被攤平的「卡片類型 + 欄位名」。

### 4.4 twdiw-vp-handler（VP 與 VC 驗證）【已確認】

- **PresentationValidateTask**
  - VP 必須有 `aud`、`jti`、`nbf`（容忍 30 秒）、`exp`、`nonce`、`vp.verifiableCredential`。
  - VP 簽章以 VC 的 `cnf.jwk` 驗證。
- **CredentialValidateTask**
  - VC 需要 typ、jku、kid、iss、sub、jti、nbf、exp、nonce、cnf。
  - `cnf.jwk` 的必要參數必須等於 `sub` 的 did:key 解出的金鑰。
- **holder 一致性**：所有 VC 必須屬於同一個 holder key 與 sub。
- **其他檢查**：狀態清冊與 issuer DID 狀態。
- `PresentationServiceAsync.doValidateVC`：狀態清冊與 schema URL 與簽章驗證並行抓取，可能在驗簽前就對外連線（issue #30）。

### 4.5 對第三方皮夾的硬性限制（彙整）【已確認，除非另註】

1. 使用 pre-authorized_code flow，沒有 authorization_code flow。【推論】由 handler 端點推得。
2. `client_id=moda_dw`，proof 的 `iss=moda_dw`。
3. token 請求必帶 `authorization_details`（type 為 `openid_credential`，含 credential_configuration_id）。
4. proof 的 `kid` 必須是 d1d603 did:key，且不帶 fragment。
5. 每把金鑰只能用 P-256 與 ES256。
6. offer 只能取一次。
7. VP 是 `jwt_vp`：以 cnf.jwk 對應的金鑰簽章，`aud` 等於 client_id，帶 `nonce`、`jti`、`nbf`、`exp`。所有 VC 的 holder 必須相同。
8. 透過 direct_post 送出 form 參數，包含 `presentation_submission`（descriptor_map 使用 jwt_vp 與 path_nested jwt_vc）。

---

## 5. Docs/*.md（私有機制）【已確認】

### 5.1 `Docs/TWDIW_API_Specification.md`

- **沙盒**
  - `https://issuer-sandbox.wallet.gov.tw/`、`https://verifier-sandbox.wallet.gov.tw/`。
  - 沙盒只支援 DWVP-01。
- **發證 API**
  - DWVC-101：POST `/api/qrcode/data`，帶 `Access-Token`，回傳 `deepLink: modadigitalwallet://credential_offer?...`。
  - DWVC-201：GET `/api/credential/nonce/{transactionId}`，可取得已發卡的 credential。
  - DWVC-202 與 DWVC-203：查詢。
  - DWVC-301：PUT `/api/credential/{cid}/{revocation|suspension|recovery}`。
  - DWVC-302：批次處理。
- **出示 API（DWVP-01）**
  - DWVP-01-101：GET `/api/oidvp/qrcode?ref&transactionId`，回傳 `authUri: modadigitalwallet://authorize?client_id=...`。
    - 文件敘述寫 openid4vp://，範例卻用 modadigitalwallet，自相矛盾。
  - DWVP-01-201：POST `/api/oidvp/result`，回應 `{holder_did, verifyResult, data:[{credentialType, claims:[{ename,cname,value}]}]}`。
- **出示 API（DWVP-02）**
  - DWVP-02-101：GET `<業務系統>/api/verifier/deeplink/vp/{vpUid}`。
  - DWVP-02-201：callback。
- **出示 API（DWVP-05，離線 QR）**
  - DWVP-05-403：POST `/api/ext/offline/addKey`。
    - 欄位：`keyId`、`publicKey`/`privateKey`（X25519，DER base64）、`totpKey`、`hmacKey`（256 bit）、`isActive`。
  - DWVP-05-404：POST `/api/ext/offline/getDecryptionData`。
    - 輸入 `{t,d,h,k}`，回傳 decryptionData，含 totp。

### 5.2 `Docs/ECC_Service_Specification.md`（137 行）

- **演算法**：X25519 ECDH、SHA-256（直接當 KDF，非 HKDF）、ChaCha20-Poly1305，nonce 為 12 bytes。
- **密文格式**：`Base64(len(epk) 4 bytes + epk + nonce 12 bytes + ct||tag)`（§3.2 至 §4.2）。
- **金鑰格式**：公鑰為 X25519，私鑰為 PKCS#8，皆以 Base64 編碼。
- 程式範例：`SampleCode/ECCService.java`。
- 【推論】這是類 ECIES 的自訂格式，不是 HPKE 或 JWE，與 OID4VP 的 `direct_post.jwt` 無關。

### 5.3 `Docs/HMAC_Service_Specification.md`（149 行）

- HMAC-SHA256，金鑰 32 bytes 並以 Base64 編碼。
- 資料以 UTF-8 處理，輸出為 Base64。

### 5.4 `Docs/TOTP_Service_Specification.md`（168 行）

- 實作 RFC 6238 變體：HMAC-SHA256、6 位數、**時間步長 60 秒**、允許前後 30 秒偏移，金鑰以 Base64 編碼。
- 與 API 規格中「step 30 秒、有效 60 秒」的描述不一致。【已確認：文件互相矛盾】

### 5.5 `Docs/QR Code 驗證規格說明文件.md`（96 行）

- QR 內容為 `{"t":交易類型, "d":ECC 密文, "h":明文的 HMAC, "k":keyId}`。
- POS 端以 privateKey、totpKey、hmacKey 解密，再驗證 HMAC 與 TOTP。QR 有效 60 秒，偏移 30 秒。
- 測試網站：`https://demo.wallet.gov.tw/reverseqrcode/`；程式範例：`SampleCode/VerifyQRCodeController.java#L61`。
- 文件範例的 privateKey 是 `MIGHAgEAMBMGByqGSM49...`，屬 P-256 PKCS#8 前綴，與 X25519 不符，屬文件筆誤。
- 【推論】整個 DWVP-05 的加密在 verifier 後端完成，皮夾只轉送 JWT 並顯示 PNG。第三方皮夾不需要實作 ECC、HMAC 或 TOTP。

---

## 6. GitHub 社群（2026-10-10 以 WebFetch 讀取）

讀取狀況：
- issues 頁面：讀取成功，共 11 個 open。
- 已關閉 issues（`?q=is:issue+is:closed`）：被 robots 擋下，無法讀取。
- pulls：5 個 open、8 個 closed，closed 的細節因 robots 無法讀取。
- discussions：回傳 CLIENT_ERROR。【推論】可能未啟用 Discussions。
- 以 gh API 存取此 repo 時，本 session 無權限（403）。

### 6.1 Open issues 摘要（截至讀取時，**全部沒有維護者回覆**）

| # | 作者 | 日期 | 內容 |
|---|---|---|---|
| 33 | mashbean | 2026-09-08 | VC 內沒有簽章過的人類可讀名稱。`vc.type[1]` 是內部 id，例如 `00000000_demo_drivinglicense_202504251418`；名稱只在未簽章的 metadata。建議加入 `vct` 與 `vct#integrity`。 |
| 32 | mashbean | 2026-09-08 | VP 使用 `context`，不是 `@context`。 |
| 31 | mashbean | 2026-09-08 | metadata 宣稱 `jwt_vc_json`，實際回傳 SD-JWT。 |
| 30 | mashbean | 2026-09-08 | vp-handler 在驗簽前就抓 statusListCredential 與 credentialSchema.id（`PresentationServiceAsync.doValidateVC`）。 |
| 29 | mashbean | 2026-09-08 | `HttpUtils` 預設使用 EmptyTrustManager，且 hostname 允許清單為空時全部放行。 |
| 28 | mashbean | 2026-09-08 | SD 選擇用 `decoded.contains(field)`，可能多揭露（`utils.dart:121`）。 |
| 22 | Ianwu0812 | 2026-05-26 | spotless 格式檢查失敗。 |
| 17 | tony1223 | 2026-04-19 | 錢包端沒有實作 PE。`dwsdk-401i` 由後端攤平成卡片與欄位，丟棄 filter 與 input_descriptor.id。 |
| 16 | tony1223 | 2026-04-18 | OID4VCI 與 did:key 的五個落差，另加一項背景圖問題，細節見下方。 |
| 15 | tony1223 | 2026-04-17 | QR 與 scheme 不符合規範。建議同時輸出 `openid-credential-offer://` 與 `openid4vp://`，或改用 App Links。 |
| 11 | PL7963 | 2026-01-23 | 要求放寬裝置安全檢測（root、bootloader）。 |

issue #16 列出的落差：
1. client_id 寫死，且錯誤訊息誤導（11007）。
2. tx_code 一律必填，只接受 `tx_code=`。
3. did:key 使用 0xeb51 且沒有 JCS。
4. 沒有 AS metadata。
5. binding method 宣稱 `jwk` 卻拒收 jwk header（11016）。
6. 背景圖回傳 text/plain。

### 6.2 Open PRs

- #25：CI 加入 spotless:check。
- #24、#23：套用 Google Java Format。
- #21：SD-JWT 解碼改用 Dart 原生的 base64Url。
- #20：修正 import 之間的註解。
- 以上作者都是 Ianwu0812，屬格式或小修，沒有協定層面的修正。

### 6.3 解讀【推論】

- 社群已有至少兩位第三方皮夾開發者回報同一批互通問題：tony1223（React Native 皮夾）與 mashbean。
- 官方截至 2026-10 沒有公開回應，短期內不太可能改成標準格式。
- 第三方皮夾應以「相容現況」為主，並保留之後切換到標準格式的抽象層。

---

## 7. 與標準的落差與第三方互通問題

標記說明：S 代表 TWDIW server，W 代表官方 wallet。

### 7.1 OpenID4VCI 1.0

| 項目 | 1.0 規定 | TWDIW 現況 | 證據 | 第三方對策 |
|---|---|---|---|---|
| offer scheme | `openid-credential-offer://`，或 by-value 與 by-reference 兩種 | `modadigitalwallet://credential_offer?credential_offer_uri=`，外層包 https wrapper | 2.2、issue #15 | 掃描器自行解 wrapper（base64 deeplink）與自訂 scheme |
| metadata 路徑 | 在 host 與 path 之間插入 `/.well-known/openid-credential-issuer`（§12.2.2） | 直接附加在後面，例如 `.../issuer/{id}/.well-known/openid-credential-issuer` | `http_service.dart:38` | 兩種路徑都嘗試，附加式優先 |
| AS metadata 與 token_endpoint | 透過 `authorization_servers` 或 RFC 8414 探索 | 都沒有，token 端點為 `{issuer}token` | 4.1、issue #16-4 | 硬組路徑 |
| client_id | pre-auth 流程可省略 | 必須是 `moda_dw`，否則回 11007 | 4.1、`VCItemDataService.java:151` | 送 `moda_dw`。【推論】有冒用官方 client 的政策風險，應向數位部確認 |
| authorization_details | 選填 | 必填 | 4.1 | 照送 |
| tx_code | 只在 offer 宣告時才帶 | UAT 實測只接受帶上空值 | issue #16-2、2.7 | offer 沒有 tx_code 時送 `tx_code=` |
| nonce | 有 Nonce Endpoint（§7），token 回應不再帶 c_nonce | token 回應帶 c_nonce（draft 13），沒有 nonce endpoint | 4.1 | 從 token 回應取 c_nonce |
| proof 的 iss | pre-auth 匿名時省略 iss | 必須是 `moda_dw` | 4.1 | 照送 |
| proof 的 kid / jwk | `jwk` 與 `kid` 二選一，依 binding method 決定 | 只接受 d1d603 did:key 的 kid，jwk header 回 11016 | issue #16-5 | 使用 did:key（jwk_jcs-pub） |
| credential 回應 | `credentials:[{credential}]`（1.0） | `{"credential":"..."}`（draft 13） | 4.1 | 兩種都解析 |
| format | 宣稱與實際一致 | 宣稱 `jwt_vc_json`，實為 SD-JWT | issue #31 | 依實際內容判斷，看 `~` |
| offer 冪等 | 未規定，但通常可重取 | 只能取一次（11023） | 4.1 | 不要預抓或重試 |
| deferred / notification / batch | 有 | 都沒有 | 4.1 | 不需支援 |
| display 圖片 | URI 應回傳圖片 | text/plain 的 data URI | issue #16-6 | 寬鬆解析 |

### 7.2 OpenID4VP 1.0

| 項目 | 1.0 規定 | TWDIW 現況 | 證據 | 對策 |
|---|---|---|---|---|
| scheme | `openid4vp://`；HAIP 用 `haip-vp://`（舊稱 haip://） | `modadigitalwallet://authorize` | 4.3、issue #15 | 自行解析 |
| client_id | 帶前綴，例如 `decentralized_identifier:did:...`、`x509_san_dns:` | 裸 DID，沒有 client_id_scheme | `OidvpClientIdentifier.java:57-63` | 把裸 `did:` 當作 DID 前綴處理 |
| request object 驗證 | 必須依 client_id 前綴驗 JAR | S 有簽章；W **不驗** | 1.4、4.3 | 第三方應解析 did:key（d1d603）並驗簽，同時查 `/api/did/{did}` 信任狀態 |
| JAR aud | `https://self-issued.me/v2` | aud 是 verifier 的 DID | `OID4VP.java:154-208` | 不檢查 aud |
| 查詢語言 | DCQL（1.0 已移除 PE） | PE v2（presentation_definition 與 submission_requirements） | 4.3、issue #17 | 實作 PE v2 子集（JSONPath 與 filter），不要學 W 的寫死假設 |
| VP 格式 | `dc+sd-jwt` 使用 KB-JWT；W3C 格式使用 `jwt_vc_json` | `jwt_vp` 包 SD-JWT 字串，以 VP 簽章取代 KB-JWT | 1.4、4.4 | 產生 jwt_vp |
| VP 欄位 | – | `context` 錯用（S 不檢查）；`exp` 30 天；`jti` 寫死 | 1.4、issue #32 | 可改用 `@context` 與較短 exp。【推論】S 不驗這些欄位，需實測 |
| vp_token 結構 | 以 DCQL id 為鍵的 JSON 物件 | 字串，加上 `presentation_submission` | 4.3 | 照送 |
| response | `direct_post` 回應 `redirect_uri`；建議 `direct_post.jwt` 加密 | 只用 `direct_post`，回 `{code:0}`；沒有加密 | 1.4 | 以 code==0 判定成功 |
| 私有擴充 | – | `custom_data`（簽章 JWT） | 4.3 | 選擇性支援 |
| DWVP-05 離線 | 無 | 私有：getEncryptionData 回傳 PNG QR | 2.3、5 | 支援步驟 1 至 3 並顯示 PNG |

### 7.3 SD-JWT VC（`dc+sd-jwt`，draft-ietf-oauth-sd-jwt-vc）

- **typ**：TWDIW 用 `vc+sd-jwt`（`Definition.java:28`），不是 `dc+sd-jwt`。【已確認】
- **vct**：沒有 vct，用的是 W3C 的 `vc.type` 與 `credentialSubject`。標準 SD-JWT VC 解析器會因缺少 vct 而失敗。【已確認】
- **claim 結構**：SD 的 `_sd` 放在 `vc.credentialSubject` 內，不在頂層。【已確認】
- **KB-JWT**：沒有，holder binding 靠 jwt_vp 的 VP 簽章。【已確認】
- **issuer key 解析**：使用 `kid` 加 `jku`（`/api/keys`）與 issuer DID，不是 SD-JWT VC 的 x5c 或 `/.well-known/jwt-vc-issuer`。【已確認】
- **SD 細節**：沒有 decoy；有 `_sd_alg`；陣列元素揭露採 2 元素格式。【已確認】
- **對策**：
  - 解析器要同時支援「JWT-VC 包 SD」與標準 dc+sd-jwt。
  - 揭露選擇要依 claim name 精確比對，修正 issue #28。

### 7.4 HAIP 1.0（High Assurance Interop Profile）

| HAIP 要求 | TWDIW |
|---|---|
| 使用 dc+sd-jwt 或 mdoc | 都不支援 |
| Wallet Attestation（`attest_jwt_client_auth`）與 Key Attestation | 沒有；以 client_id `moda_dw` 寫死代替 |
| DPoP、PKCE、PAR | 沒有 |
| verifier 以 `x509_san_dns` 或 `x509_hash` 驗證 | 用 DID 加中心化的 `/api/did` 註冊；x509 只做 trust_badge |
| `direct_post.jwt`（JWE 加密回應） | 沒有 |
| DCQL | 沒有，使用 PE |
| IETF Token Status List | 沒有，使用 StatusList2021 |
| ES256 | 符合 |

【推論】要符合 HAIP，必須在 server 端大幅改版。短期內第三方皮夾只能走「TWDIW profile」。

### 7.5 StatusList

- 採 W3C StatusList2021（已被 Bitstring Status List v1.0 取代），不是 IETF Token Status List（`status.status_list.idx/uri`）。【已確認】
- 包裝方式非標準：`{statusList: jwt}` 外層再包一層 JSON。【已確認】
- 每張 VC 有 revocation 與 suspension 兩個 entry。【已確認】
- W 不驗 status JWT 簽章；第三方應驗。【已確認】

### 7.6 did:key

- 使用 0xeb51（jwk_jcs-pub，仍是 draft），不是 W3C did:key 的 P-256 標準 `0x1200`（33 bytes 壓縮點）。【已確認】
- 沒有做 JCS。第三方若產生 JCS 排序（crv 在 kty 之前），S 仍可解碼 JWK。【推論】S 只做解碼並比對 cnf，所以可接受，但需實測。
- `JWSCreator.publicKeyToJwk` 的長度 bug 會讓 x/y 偶爾不是 32 bytes。第三方應固定使用 32 bytes 的 base64url。【已確認 bug；影響為推論】

### 7.7 第三方互通的實際問題清單

1. **入口**
   - App Links 綁定 `frontend.wallet.gov.tw`，只開官方 App。
   - 自訂 scheme `modadigitalwallet://` 若被第三方註冊，會跳出 App 選擇器，也可能有政策或冒用疑慮。
   - 建議只用 App 內掃 QR 加剪貼簿貼上。【推論】
2. **身分冒用風險**：必須送 `client_id=moda_dw` 與 `iss=moda_dw`，技術上等同冒用官方 client。正式上線前應向數位部取得書面同意或白名單。【推論】
3. **信任清單**：沒有開放的 trust list 格式，只能呼叫 frontend 的 `/api/did/{did}` 與 `/api/did?orgType=1&status=1` 分頁 API，屬未文件化的 API，可能變動。【已確認，API 內容來自程式碼】
4. **顯示名稱**：卡片名稱與背景圖只在 issuer metadata 中，必須在發證時快取（issue #33）。【已確認】
5. **憑證轉移**：換機流程走 `{jti}/transfer` 與 `moda_dw` 的 id_token，屬官方 App 私有流程，第三方難以支援。【已確認】
6. **NFC 出示**：使用私有 AID `F2 23 34 45 56 68` 與分段協定，接收端尚未完成，不建議實作。【已確認】
7. **時間與重試**：
   - pre-auth code 10 分鐘，access_token 600 秒，OID4VP session 5 分鐘，DWVP-05 的 QR 60 秒。
   - offer 只能取一次。
   - 【已確認】
8. **沙盒限制**：沙盒只支援 DWVP-01，DWVP-05 只能在正式或 UAT 環境測試。【已確認，來自文件】
9. **伺服器 TLS**：core-system 預設信任所有憑證（issue #29），不影響皮夾端；皮夾端應使用系統 CA，並可考慮 pinning。
10. **公開碼與上架版不一致**：頻道名稱與 root 檢測都有差異，App 行為應以實測為準，不能只看原始碼。【推論】

### 7.8 KMP 皮夾建議實作（TWDIW profile 最小集合）【推論】

- **金鑰**：AndroidKeyStore 的 P-256（StrongBox 優先），可選擇性綁定 user-auth 並搭配 CryptoObject。
- **DID 與 JWK**：did:key 採 d1d603 加 JWK JSON，x/y 固定 32 bytes，key 順序為 kty、crv、x、y，不含空白，以符合官方行為。
- **VCI**：
  - 解析 wrapper 與 credential_offer_uri。
  - metadata 依附加式路徑取得。
  - token 請求帶 `moda_dw`、authorization_details 與 `tx_code`（可為空）。
  - proof 的 kid 為 did，iss 為 moda_dw。
  - 解析 `credential` 單數回應。
- **VP**：
  - 驗 JAR 簽章（did:key）。
  - 評估 PE v2。
  - 以精確的 claim 名稱選擇揭露。
  - 產生 jwt_vp（帶 aud、nonce、jti、nbf、exp）與 presentation_submission，以 form direct_post 送出。
- **狀態**：StatusList2021 的 GZIP bitstring，MSB-first；同時驗簽。
- **抽象層**：預留標準 OID4VCI 1.0、OID4VP 1.0、dc+sd-jwt 路徑，以便日後 TWDIW 改版或與 EUDI 互通。

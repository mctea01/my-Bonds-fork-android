# Multipaz／EUDI／Microsoft Entra Verified ID 研究筆記

調查日期：2026-10-10
標記方式：**[確認]** 表示由原始碼、官方 README 或規格原文直接證實；**[推論]** 表示根據證據推斷，尚未實測。
Multipaz 原始碼：`git clone --depth 1` 取得 commit `cd9578b3`（2026-10-09），本地路徑 `scratchpad/src/multipaz/`，下文以 `MPZ/` 代稱。
MS 程式庫原始碼：`scratchpad/src/ms-wallet/`（dev 分支），下文以 `MSW/` 代稱。
ARF 原文下載於 `scratchpad/dl/`，包含 `arf6.md` 與 `annex2.md`，來源為 github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework。

---

## A. Multipaz

### A1. 版本、座標與建置設定
- **[確認]** 最新正式版為 **0.101.0**（2026-09-10）。0.102.0 預計 2026 年 10 或 11 月發布。證據：`MPZ/CHANGELOG.md` 與 `MPZ/build.gradle.kts:38-39`（`projectVersionLast = "0.101.0"`）。
- **[確認]** 0.98.0 起改在 Maven Central 發布，0.97.0 以前位於 GMaven。groupId 為 `org.multipaz`，例如 `org.multipaz:multipaz:0.101.0`。快照版位於 `https://central.sonatype.com/repository/maven-snapshots/`，如 `0.102.0-SNAPSHOT`。證據：`MPZ/README.md`。
- **[確認]** 專案仍在 1.0 之前，API 與磁碟上的資料格式都可能變動。官方預估 2026 年底至 2027 年初到達 1.0。證據：`MPZ/README.md` 的「Versioning, and Stability」一節。
- **[確認]** 建置版本：Kotlin 2.2.21、Compose Multiplatform 1.10.1、AGP 8.13.1、compileSdk/targetSdk 36、**minSdk 26**、Ktor 3.3.3、androidx-credentials 1.5.0、registry-provider 1.0.0-alpha03、androidx-biometrics 1.2.0-alpha05（alpha 版）。證據：`MPZ/gradle/libs.versions.toml`。
- **[確認]** `multipaz` 核心的 KMP targets 為 androidTarget、jvm、js、wasmJs、iosX64、iosArm64、iosSimulatorArm64。證據：`MPZ/multipaz/build.gradle.kts:42-77`。
- **[確認]** 發布的模組（含 `publishing` 區塊者）：multipaz、multipaz-compose、multipaz-dcapi、multipaz-doctypes、multipaz-longfellow、multipaz-facenet、multipaz-utopia、multipaz-swiftui、multipaz-android-legacy、multipaz-cbor-rpc、multipaz-openid4vci（伺服器）、multipaz-verifier（JVM）、multipaz-server、multipaz-records。證據：`MPZ/settings.gradle.kts` 與各模組的 `build.gradle.kts`。
  - `multipaz-verifier` 僅為 JVM 函式庫（`org.jetbrains.kotlin.jvm`），是伺服器端驗證者，不能放進 App 使用。證據：`MPZ/multipaz-verifier/build.gradle.kts`。
- **[確認]** iOS 的取用方式：自 0.101.0 起移除 `Package.swift`，官方建議**自行用 Gradle 建置單一 umbrella XCFramework**（可搭配 SKIE）。原因是 Kotlin/Native 不支援多個 Kotlin framework 動態連結（diamond dependency 問題）。證據：`MPZ/README.md` 的「Consuming on iOS」一節，以及 CHANGELOG 0.101.0。
  - 我們的 iOS 也採用 CMP，因此 Multipaz 會和 App 的 shared Kotlin 程式碼編進同一個 framework，正好符合官方建議。**[推論]**
- **[確認]** iOS 部署目標：TestApp（CMP）與 SwiftTestApp 設為 iOS 26.0，SwiftBridge 設為 16.0。證據：`MPZ/samples/testapp/iosApp/TestApp.xcodeproj/project.pbxproj:318`、`MPZ/multipaz/SwiftBridge/...pbxproj:210`。

### A2. SecureArea 實作
- **[確認]** `AndroidKeystoreSecureArea` 支援 StrongBox（`useStrongBox`）、使用者驗證類型、金鑰證明（attestation），0.100 修正了 Ed25519 簽章。證據：`MPZ/multipaz/src/androidMain/kotlin/org/multipaz/securearea/AndroidKeystoreSecureArea.kt` 與 `AndroidKeystoreCreateKeySettings.kt:35-37,134`。
- **[確認]** `SecureEnclaveSecureArea` 僅限 iOS。證據：`MPZ/multipaz/src/iosMain/kotlin/org/multipaz/securearea/SecureEnclaveSecureArea.kt`。
- **[確認]** `CloudSecureArea`（CSA）提供 android/ios/jvm/web 實作，伺服器端為 `multipaz-csa-server`。證據：`.../securearea/cloud/*`。
- **[確認]** `SoftwareSecureArea` 支援全部平台，iOS 版使用 Keychain 的 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`。證據：`.../iosMain/.../software/SoftwareSecureArea.ios.kt:57`。
- **[確認]** 其他相關機制：`SecureAreaRepository`、`KeyUnlockDataProvider`，以及 0.101 新增的 `PreloadedKeyUnlockDataProvider` / `SecureArea.unlockKey()`（可在 NFC tap 前預先解鎖）與 `CertifiedKeyManager`（預先認證的金鑰池）。證據：CHANGELOG 0.101.0。
- **[確認]** 支援的演算法：ES256/384/512、ESP256/384/512（fully-specified）、ESB256–512（Brainpool）、EdDSA/Ed25519/Ed448、RSA RS/PS 各長度、**ML-DSA-44/65/87**、ML-KEM-512，以及 ECDH（P-256/384/521、Brainpool、X25519/X448）。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/crypto/Algorithm.kt:48-324`。
  - 各平台硬體是否真的支援這些演算法（例如 StrongBox 只支援 P-256）要另外確認，Algorithm 列舉不代表每個 SecureArea 都可用。**[推論]**
- 已知問題 **[確認]**：#1952 指出 iOS 上 `SecureEnclaveSecureArea.getKeyInvalidated` 永遠回傳 `false`，因此無法偵測生物辨識變更造成的金鑰失效。來源：https://github.com/openwallet-foundation/multipaz/issues 。

### A3. 文件儲存與加密
- **[確認]** `Storage` 抽象層的實作：`AndroidStorage`（`android.database.sqlite`）、`IosStorage`（SQLite，0.101 加入 5 秒 busy timeout）、`JdbcStorage`（JVM）、`WebStorage`（IndexedDB）、`EphemeralStorage`。證據：`MPZ/multipaz/src/*/kotlin/org/multipaz/storage/`。
- **[確認]** 函式庫本身**不做應用層加密**。只有 `GenericStorageEngine.transform()` 預留了加解密的 hook，預設是 identity function。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/storage/GenericStorageEngine.kt:42-52`。
  - 靜態資料的保護目前只靠 OS sandbox 與 FBE/Data Protection。若需要 at-rest 加密，必須自行實作，例如 SQLCipher，或以 SecureArea 包裝的 DEK 加密記錄。**[推論]**
- **[確認]** 其他：`DocumentStore` 與 Tags（key/value）、`DocumentModel`（0.101 可排序）、事件紀錄（`EventLogger`）。0.101 已稽核日誌，預設層級不含 PII。證據：CHANGELOG 0.97 至 0.101。

### A4. 憑證格式
- **[確認]** **ISO mdoc** 支援 18013-5:2021 與 Second Edition 的大部分功能：MSO、DeviceResponse、加密文件、新查詢語言、DeviceRequest 1.0 與 1.1 的 claim 比對、元素層級的 device key authorization、RICAL/VICAL。證據：CHANGELOG 0.96、0.98、0.101，以及 `MPZ/multipaz/src/commonMain/kotlin/org/multipaz/mdoc/{vical,rical,zkp,...}`。
- **[確認]** **IETF SD-JWT VC**：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/sdjwt/`（SdJwt、SdJwtKb、KeyBoundSdJwtVcCredential）。0.101 將格式字串由 `vc+sd-jwt`/`sd-jwt+kb` 改為 `dc+sd-jwt`。0.100 起可在 18013-5 的 DeviceRequest/Response 中攜帶 SD-JWT VC，也支援 SD-JWT 數位支付憑證（DPC）。
- **[確認]** **不支援 W3C VCDM**（jwt_vc_json、ldp_vc），**也不支援任何 DID 方法**：全 repo 搜尋 `jwt_vc|ldp_vc|did:web|did:jwk` 皆無結果。這點直接影響與 Microsoft Entra 的互通性。
- **[確認]** 撤銷檢查支援 IETF Token Status List、Identifier List、X.509 CRL，0.101 新增 `RevocationChecker` 與 `CachingRevocationChecker`。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/revocation/`。
- 已知問題 **[確認]**：#1946 `SdJwtVcCredential.getClaimsImpl` 會把 JWT envelope 的 claims 當成文件 claims；#1945 `CredentialMetadata` 會丟失 `credential_metadata.claims[]`。

### A5. OpenID4VCI（持有端客戶端）

**2026-10-16 程式補強：** 原本一般模式會用 `PublicClientWalletProvider`，無法滿足 Multipaz 發證端要求的註冊用戶端身分；PR #11 已新增依授權伺服器的 `token_endpoint_auth_methods_supported` 協商 `attest_jwt_client_auth`／`private_key_jwt`／`none`，Client Assertion 使用 RFC 7523 JWT；PAR、Token 與挑戰重試維持相同的用戶端驗證方式。可在 App「設定 > 互通」填寫被發證端認可的 HTTPS Wallet Provider 與 `client_id`。本機測試 CA 並不會自動取得 Multipaz 官方發證的信任，`clientId must be authenticated` 與 T3 提示來源不同。

- **[確認]** 位於 `MPZ/multipaz/src/commonMain/kotlin/org/multipaz/provisioning/openid4vci/`，支援以下功能：
  - PAR（**metadata 中的 `pushed_authorization_request_endpoint` 為必填**，見 `AuthorizationConfiguration.kt:42` 使用 `metadata.string(...)` 而非 `stringOrNull`）
  - DPoP、pre-authorized_code + tx_code
  - `OAuth-Client-Attestation`：Wallet attestation，對應 OpenID4VCI 1.0 Appendix E（`ClientAuthenticationType.kt:14`）
  - nonce_endpoint、batch_credential_issuance
  - proof types `jwt` 與 `attestation`（`key-attestation+jwt`，見 `OpenID4VCIBackendUtil.kt:116`）
  - display metadata、credential refresh
- **[推論]** 未支援 PAR 的發行者可能無法使用。
- 已知問題 **[確認]**：
  - #1948：deferred issuance 無法使用（202 處理、endpoint 解析、token/DPoP key 都有問題）
  - #1947：伺服器未宣告支援時仍送出 `authorization_details`
  - #1950：沒有可重新授權既有 Document 的公開 API
  - #1951：rotated authorization data 只在一個分支持久化
- 和 EUDI 程式庫相比：EUDI 支援 deferred、notification、signed metadata 政策（見 B4）。**[推論]** 若要對接 EU 發行者，Multipaz 的 VCI 客戶端可能不夠完整。

### A6. OpenID4VP（持有端）

**2026-10-16 補強：** OpenID4VP 多重簽章 DC API 現使用 JWS JSON Serialization，逐一檢驗受保護 `client_id`、簽章、查驗端憑證及 Browser Origin，且拒絕 signed／multisigned 要求回退為未簽章資料。仍需獨立實作 OpenID Federation Trust Chain（應由錨點與聯邦政策導出查驗方身分，不能相信 `client_metadata.jwks`）、JWE 加密 Request Object 的錢包解密金鑰／內層簽章驗證，以及 mdoc 交易資料依特定 docType 的 KeyAuthorizations。

- **[確認]** `OpenID4VP.Version` 只有 `DRAFT_24` 與 `DRAFT_29` 兩個值，`DRAFT_29` 用於 1.0（DC API protocol `openid4vp-v1-*`）。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/openid/OpenID4VP.kt:79-82` 與 `presentment/digitalCredentialsPresentment.kt`（`"openid4vp"` 對應 DRAFT_24，`"openid4vp-v1-unsigned|signed|multisigned"` 對應 DRAFT_29）。
- **[確認]** response_mode 支援 `dc_api`、`dc_api.jwt`、`direct_post`、`direct_post.jwt`。回應加密只支援 `ECDH-ES` 搭配 A128GCM/A192GCM/A256GCM。證據：`OpenID4VP.kt:357-432`。
- **[確認]** DCQL 支援以下 format：`mso_mdoc`、`mso_mdoc_zk`、`dc+sd-jwt`。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/openid/dcql/DcqlQuery.kt:142-170`。
- **[確認]** 支援 `transaction_data`（0.101 重構為具型別的模型）與 `trusted_authorities`（AKI）。證據：`OpenID4VP.kt:437`、CHANGELOG 0.101。
- **[確認]** client_id 與驗證者身分（持有端）：
  - **只接受以 `x5c` 簽章的請求**：
    - DC API signed：缺少 x5c 時 `check(info.x5c != null)` 會失敗
    - multisigned：遇到沒有 x5c 的簽章會 `continue` 略過，註解為「we only support X509-certified keys」
    - URI scheme：直接取用 `info.x5c!!`
    - 證據：`presentment/digitalCredentialsPresentment.kt` 的 `digitalCredentialsOpenID4VPProtocol`、`presentment/uriSchemePresentment.kt:120-135`
  - 未簽章的 DC API 請求依規格忽略 client_id，改用 `web-origin:<origin>`。證據：`OpenID4VP.kt:467-493`。
  - **沒有任何程式碼檢查 client_id prefix 與憑證是否吻合**：`x509_san_dns` 未比對 SAN dNSName，`x509_hash` 未比對憑證雜湊。全 repo 搜尋 `subjectAlternativeNames` 與 `"x509_` 檢查，持有端皆無結果。`x5c.validate()` 只驗證鏈本身的完整性。
  - **不支援** `verifier_attestation`、`decentralized_identifier`（did）、`redirect_uri`（持有端）、`pre-registered`、`openid_federation`。依據為搜尋無結果，屬「未見實作」。
  - **[推論]** 若要符合 OpenID4VP 1.0 §5.9 的 prefix 驗證，需要自行補上。
- **[確認]** URI scheme 流程（`openid4vp://`、`mdoc://`）：
  - 只支援 `request_uri`，不支援以值傳遞的 `request`（程式碼有 TODO）
  - `request_uri_method=post` 時不送出 wallet metadata（TODO）
  - `direct_post` 時以 `alg:none` 的 JWT 放在 `response` 參數回傳
  - 證據：`uriSchemePresentment.kt:60-160`
  - **[推論]** `direct_post` 的實作方式和規格（以 form 參數傳送 `vp_token`）不同，可能影響互通，需實測。
  - 另見 #1949：`uriSchemePresentment` 會丟掉驗證者的錯誤回應 body。
- **[確認]** **不支援 `verifier_info`／registration certificate（WRPRC）**：全 repo 搜尋 `verifier_info|registration_cert` 皆無結果。

### A7. 向使用者呈現驗證者身分（持有端 UI 與信任）
- **[確認]** `Requester` 包含三項資訊：`requesterIdentities`（每個簽章各一個 `certChain`）、`appId`、`origin`。`TrustedRequesterIdentity` 則包含 `identity` 與 `TrustMetadata`。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/request/*.kt`。
- **[確認]** `TrustMetadata` 只有 displayName、displayIcon/Url、privacyPolicyUrl、disclaimer、testOnly、extensions。**沒有**法人／自然人類型、組織識別碼、代理對象、目的等欄位。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/trustmanagement/TrustMetadata.kt`。
- **[確認]** 信任判斷由 App 實作的 `PresentmentSource.resolveTrust(requester)` 決定。TestApp 的做法：
  1. 先檢查 Multipaz 專用的 X.509 擴充欄位（Google 帳號 email 與頭像）
  2. 再用 `readerTrustManager.verify(certChain)` 驗證
  3. 顯示名稱取自**本地 trust point 的 metadata**，不是讀取 leaf 憑證的 subject
  - 證據：`MPZ/samples/testapp/src/commonMain/kotlin/org/multipaz/testapp/App.kt:295-330`。
- **[確認]** Compose 同意畫面（`Consent.kt`）的顯示規則：
  - 有 `trustMetadata` 時顯示 displayName、icon、privacy policy、disclaimer
  - 沒有時，若是 web origin 就顯示 origin，若是 app 就顯示 appId
  - 其他情況顯示 unknown requester，並提示「verifier not in trust list」
  - 「Requester information」頁可用 `X509CertViewer` 翻閱整條憑證鏈
  - 另有「known/unknown encryption target」的文案
  - 證據：`MPZ/multipaz-compose/src/commonMain/kotlin/org/multipaz/compose/presentment/Consent.kt:107-129,348-500`。
- **[確認]** TrustManager 家族：`TrustManager`、`ConfigurableTrustManager`、`CompositeTrustManager`、`VicalTrustManager`、`RicalTrustManager`，TrustEntry 類型有 X509Cert、Vical、Rical。Compose 端有 `TrustManagerModel` 與 `TrustEntryInfo`（0.98 加入編輯 trust list 的 composable）。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/trustmanagement/`、`MPZ/multipaz-compose/.../trustmanagement/`。
- **[確認]** 請求目的：mdoc Second Edition 的 `UseCase.purposeHints` 有解析（`mdoc/request/UseCase.kt`），0.100 起有「use-case driven consent prompts」。但 OpenID4VP 沒有對應的目的欄位，因為 `verifier_info` 未實作。
- **[推論]** 若要做到「以 WRPAC 為證據顯示身分、身分類型（個人／法人／代表組織的個人）、目的、隱私政策、over-asking 警告」，需要自行補上以下工作：
  - 解析 leaf 憑證的 subject（O、organizationIdentifier、CN、givenName/surname）與 SAN
  - 用 LoTE 驗證 WRPAC
  - 實作 `verifier_info` 與 mdoc `requestInfo` 中 `euWrprc` 的 WRPRC 解析
  - 自行寫一個 `PresentmentSource` 和同意畫面，或擴充 `TrustMetadata.extensions`
  - 可參考 EUDI wallet-core 的 `WrpRegistrationEvaluator` 設計，見 B5。

### A8. 驗證者／讀取端（主動驗證）
- **[確認]** 核心 `org.multipaz.verification`：
  - `VerificationSession` 可產生 DC API 請求、處理 OpenID4VP（DC API／URI scheme）與 18013-5 proximity 的回應，並可序列化
  - 0.100 起與 DCQL 脫鉤
  - 證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/verification/VerificationSession.kt`，`VerificationUtil.verifyOpenID4VPResponse`，`VerifiedPresentation.revocationStatus`
- **[確認]** Reader authentication（mdoc）由 `DeviceRequestGenerator` 產生 readerAuth。0.101 起 COSE x5chain 不再包含 root。驗證者端支援 Second Edition 檢查程序：
  - DS 憑證效期對照 signedAt/validUntil
  - 國家／州名比對
  - VICAL 授權的 doctype
  - 證據：CHANGELOG 0.101、`mdoc/request/DeviceRequestGenerator.kt`
- **[確認]** OpenID4VP 驗證者的 client_id：`VerifierIdentity` 支援 `x509_san_dns:` 與 `x509_hash:`，也支援 multisigned。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/verification/VerifierIdentity.kt:11`、`MPZ/multipaz-verifier/.../verifyCredentials.kt:401,445`、`MPZ/samples/testapp/.../DcRequestScreen.kt:359`。
- **[確認]** TestApp 的驗證者功能（CMP，Android 與 iOS）：
  - `IsoMdocProximityReadingScreen`
  - `NfcReaderScreen`、USB 外接 NFC 讀卡機
  - `DcRequestScreen`（W3C DC API 請求）
  - `ShowResponseScreen`
  - `TrustManagerScreen`（VICAL/RICAL 編輯）
  - `IsoMdocMultiDeviceTestingScreen`
  - 證據：`MPZ/samples/testapp/src/commonMain/kotlin/org/multipaz/testapp/ui/`。
- **[確認]** 在 iOS 上，`DigitalCredentials.defaultRequest` 會 `throw NotImplementedError`，因此**原生 iOS App 不能透過 DC API 當驗證者**，只能用 proximity 或自行實作 OpenID4VP。證據：`MPZ/multipaz-dcapi/src/iosMain/kotlin/org/multipaz/digitalcredentials/DigitalCredentialsExt.ios.kt:265`。
- **[確認]** Multipaz Identity Reader 是 18013-5 proximity 讀取 App，使用 **CMP + KMP（Android/iOS）**，backend 負責認證 reader 金鑰（identityreader.multipaz.org），另有實驗性的 SwiftIdentityReader。來源：https://github.com/openwallet-foundation/multipaz-identity-reader 。
- **[確認]** Multipaz Wallet 的 Android 端使用 Jetpack Compose，**iOS 端使用 SwiftUI**，另有 Kotlin/JS web 端。shared KMP 模組會建成 umbrella XCFramework。來源：https://github.com/openwallet-foundation/multipaz-wallet 。
  - 我們的 iOS 採 CMP，因此較適合參考 TestApp 與 Identity Reader，而非 Multipaz Wallet。**[推論]**
- **[確認]** 其他工具：tools.multipaz.org（各種 decoder，以及含 ZKP 的 DC verifier）、verifier.multipaz.org（Web 驗證者）。證據：CHANGELOG 0.101、https://developer.multipaz.org/ 。

### A9. ISO 18013-5 engagement 與傳輸
- **[確認]** connection method 有 BLE、NFC、NFCv2（0.100 加入，支援 sequence number 與 multi-tap）、HTTP、WifiAware。但 **WifiAware 只有 connection method 的定義，沒有 transport 實作**：transport 目錄只有 Ble*、Nfc*、NfcHybrid*。證據：`MPZ/multipaz/src/commonMain/kotlin/org/multipaz/mdoc/connectionmethod/`、`.../mdoc/transport/`。
- **[確認]** BLE 支援 central/peripheral、L2CAP（0.100 加入重試機制），Android 與 iOS 都有實作（`BleCentralManagerAndroid/Ios` 等）。
- **[確認]** NFC：
  - Android 以 HCE 呈現 mdoc，相關類別為 `NfcApduService`、`MdocNfcDataTransferService`、`MdocNfcV2Service`、`CombinedNfcService`，位於 `MPZ/multipaz-compose/src/androidMain/kotlin/org/multipaz/compose/mdoc/`。
  - iOS 只有 `NFCTagReaderSession`（讀取端）。證據：`MPZ/multipaz/src/iosMain/kotlin/org/multipaz/nfc/NfcTagReader.ios.kt`。
  - **[推論]** iOS 持有端無法用 NFC engagement 或 NFC 資料傳輸呈現 mdoc，因為 HCE 需要 Apple 的特殊 entitlement（NFC & SE Platform），repo 中沒有相關程式碼。
- **[確認]** QR engagement 有 `MdocProximityQrPresentment` 與 `MdocProximityQrSettings` composable；另支援 Observe Mode（0.95）。

### A10. W3C Digital Credentials API

**2026-10-16 驗收策略：** 已有 Android DC API 收卡與出示、Browser Origin 綁定，以及本輪多重簽章驗證。Android HTTPS App Links 暫不規劃；沿用既有 URI Scheme 回呼與 DC API 機制，必要時再因網域部署需求評估。

- **[確認]** Android：
  - `multipaz-dcapi` 使用 GMS 的 `IdentityCredentialManager.registerCredentials`，搭配 `identitycredentialmatcher.wasm` matcher
  - 呈現端是 `CredentialManagerPresentmentActivity`（androidx.credentials provider `PendingIntentHandler`）
  - 支援的 protocol：`openid4vp`（draft24）、`openid4vp-v1-unsigned/signed/multisigned`、`org-iso-mdoc`/`org.iso.mdoc`（18013-7 Annex C）
  - 證據：`MPZ/multipaz-dcapi/src/androidMain/.../DigitalCredentialsExt.android.kt:11,118-170`、`MPZ/multipaz-compose/src/androidMain/kotlin/org/multipaz/compose/digitalcredentials/CredentialManagerPresentmentActivity.kt`、`presentment/digitalCredentialsPresentment.kt`
  - **[推論]** 需要 Google Play Services，非 GMS 裝置無法使用。
- **[確認]** iOS：使用 `IdentityDocumentServices` 註冊（iOS 26），僅支援持有端。證據：`DigitalCredentialsExt.ios.kt:221`、CHANGELOG 0.97。
- 已知問題 **[確認]**：#1996 matcher 無法回報選中的條目對應哪個 request 或 DCQL query。

### A11. ZKP（multipaz-longfellow）

**2026-10-16 信任清單：** Multipaz 的 `SignedVical.parse` 與 `SignedRical.parse` 可以驗 COSE 簽名，`TrustManager.addVical/addRical` 只建立信任點，**不會自動驗證清單發行者根憑證**，也不會自動因 `notAfter` 淘汰舊清單。PR #11 在 `TrustRegistry` 增加獨立的 `TRUST_LIST_PROVIDER` 錨點、版本防回退、同來源更新、過期移除，以及 RICAL `isTrustAnchor` 的嚴格處理（採保守拒絕非錨點清單）。VICAL 僅支援發行端；RICAL 僅支援查驗方。

- **[確認]** 整合 Google longfellow-zk（Rust FFI），提供 `run_mdoc_prover`/`run_mdoc_verifier`，**僅支援 mdoc**，依循 18013-5 Second Edition 草案。整合方式：Android/JVM 用 JNA，iOS 用 cinterop 靜態庫，另有 web 的 webMain 實作。證據：`MPZ/multipaz-longfellow/README.md`。
- **[確認]** 預建二進位：Android **只有 `arm64-v8a` 與 `x86_64`**（沒有 armeabi-v7a），JVM 有 macOS arm64/x86_64 與 linux-x86_64，iOS 有裝置 arm64 與模擬器 arm64/x86_64。證據：同上 README 的「Prebuilt Binaries」一節。
- **[確認]** 持有端與驗證端都支援：
  - API 為 `ZkSystemRepository` + `LongfellowZkSystem.addDefaultCircuits()`，交給 `SimplePresentmentSource` 使用
  - 驗證端呼叫 `VerificationUtil.verifyOpenID4VPResponse(…, zkSystemRepository)`
  - OpenID4VP 的 DCQL format 為 `mso_mdoc_zk`（`OpenID4VP.kt` 中的 `requestIsForZk`），proximity 為 DeviceRequest 的 `ZkRequest`（`mdoc/request/ZkRequest.kt`）
  - 0.99 起採用 Longfellow 0.9，circuit 已內建；0.96 起支援 iOS
  - 證據：https://developer.multipaz.org/docs/guides/zkp 、CHANGELOG。
- **[確認]** 限制：
  - **完整的 mDL 太大**，超過 circuit 上限，發行者必須簽發只含少數元素的「ZKP-friendly」精簡憑證
  - MSO 在簽發時就固定，呈現時無法裁剪
  - 官方指南只示範 age_over_18 且僅限 Android，原因是指南使用 DC API
  - 來源：https://developer.multipaz.org/docs/guides/zkp
  - EUDI ZKP.md 列出的具體上限：每個 IssuerSignedItem ≤ 119 bytes、elementIdentifier ≤ 32 bytes、value ≤ 64 bytes、MSO ≤ 2533 bytes。來源：https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/main/ZKP.md 。
- **[推論]** 不支援 SD-JWT VC 的 ZKP。proof 產生耗時與 APK 體積（`.so` 與 circuits）需要實測。

### A12. 可能遇到的問題（Multipaz）
1. API 與資料格式在 1.0 前會變動（例如 ByteArray 改為 ByteString），升級時資料可能需要遷移。發布節奏為 4 到 8 週一版。
2. 持有端不驗證 client_id prefix 與憑證的綁定，有被冒用身分的風險，需要自行補上。
3. 持有端不支援 did、verifier_attestation、redirect_uri、pre-registered 等 client_id，也不支援 WRPRC/`verifier_info`。與 EUDI 驗證者互通時，無法依 ARF 顯示目的、隱私政策與 over-asking 警告。
4. 同意畫面的名稱來自本地 trust list metadata，而非憑證內容。若要以憑證作為證據，必須自訂 `resolveTrust` 與 UI。
5. 不支援 W3C VC 與 DID，無法與 MS Entra 互通，見 C 節。
6. OpenID4VCI 的 deferred issuance 與 PAR 必填等問題（#1947、#1948、#1950、#1951）。
7. iOS 的限制：
   - Secure Enclave 無法偵測金鑰失效（#1952）
   - 原生 App 不能以 DC API 當驗證者
   - 持有端不支援 NFC HCE
   - 必須自行建置 umbrella XCFramework
   - TestApp 的部署目標為 iOS 26
8. ZKP 需要發行者配合簽發精簡 mDL，Android 不支援 32-bit ABI，且僅限 mdoc。
9. DC API 依賴 GMS；registry-provider 與 biometrics 都還是 alpha 版。
10. 儲存層沒有應用層加密。
11. WifiAware 沒有傳輸實作；URI scheme 不支援以值傳遞的 request，`direct_post` 的實作有偏差。

---

## B. EUDI Wallet 參考實作

### B1. 程式庫、KMP 狀態與授權
- **[確認]** `eudi-lib-android-wallet-core` 只支援 **Android**，不是 KMP。授權 Apache-2.0，**minSdk 26**，README 範例版本為 0.30.2。座標：`eu.europa.ec.eudi:eudi-lib-android-wallet-core`、`...-wallet-document-manager`、`eudi-lib-android-iso18013-data-transfer`。來源：https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core 。
- **[確認]** **wallet-core 依賴 Multipaz 0.101.0**：`org.multipaz:multipaz`、`multipaz-android`（應為舊名或 android 變體）、`multipaz-android-legacy`、`multipaz-longfellow-android`。其他依賴版本：openid4vci-kt 0.14.1、openid4vp-kt 0.16.2、sdjwt-kt 0.20.2、kmp-statium 0.5.2、kmp-etsi1196x2 0.4.0-alpha.3，Kotlin 2.2.21。證據：https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/main/gradle/libs.versions.toml 。
  - 因此可以和我們的 Multipaz 0.101.0 共存，SecureArea 與 Storage 都來自 Multipaz。**[推論]**
- **[確認]** `eudi-lib-jvm-openid4vci-kt`、`eudi-lib-jvm-openid4vp-kt`、`eudi-lib-jvm-sdjwt-kt` 都是 **JVM** 程式庫（README 寫明「targeting JVM」），授權 Apache-2.0，且都聲明「不建議用於生產」。來源：各 repo README。
- **[確認]** KMP 程式庫目前只有兩個：
  - `eudi-lib-kmp-etsi-1196x2`：targets 為 iOS/Android/JVM，但其中 DSS（TS 119 612）模組只支援 JVM/Android
  - `eudi-lib-kmp-statium`：Token Status List，targets 為 Android/JVM
  - 來源：https://klibs.io/organization/eu-digital-identity-wallet 、https://github.com/eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2
- **[推論]** EUDI 的 iOS 實作是另一套 Swift 程式庫（eudi-lib-ios-wallet-kit 等），無法在 CMP iOS 共用。若要在 iOS 共用 EUDI 邏輯，只能自行移植 JVM 程式庫，或改以 Multipaz 自行實作。
- **[確認]** `eudi-lib-android-rqes-core` 只支援 Android，版本 0.6.0，授權 Apache-2.0。提供 `RQESService`（service/credential authorization 走 OAuth2 + `signDocuments`）與 `DocumentRetrievalService`（以 `mdoc-openid4vp://` + X509 SAN 取得待簽文件）。範例端點為 `/csc/v2`，對應 CSC API v2（README 未明說，屬推論）。README 寫 API 29。來源：https://github.com/eu-digital-identity-wallet/eudi-lib-android-rqes-core 。

### B2. OpenID4VP 1.0 與 HAIP
- **[確認]** openid4vp-kt 支援的 client_id prefix：pre-registered、redirect_uri、**decentralized_identifier**、**verifier_attestation**、x509_san_dns、x509_hash。不支援 openid_federation。
- **[確認]** openid4vp-kt 支援 DCQL（以值傳遞或 scope）與 transaction_data。response mode 支援 direct_post(.jwt)、query/fragment(.jwt)、dc_api(.jwt)。v0.12 起移除 SIOPv2。來源：https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt 。
- **[確認]** WRPRC 只在 `x509_hash` 時從 `verifierInfo` 讀取。來源同上。
- **[確認]** wallet-core 只開放其中一部分：
  - client_id 只有 preregistered、x509_san_dns、x509_hash、redirect_uri
  - DCQL 支援 credential_sets、claim_sets、multiple、require_cryptographic_holder_binding
  - **預設加密政策為 HAIP**，只接受加密回應（direct_post.jwt / dc_api.jwt）
  - **transaction data 不支援**
  - 來源：wallet-core README
- **[確認]** openid4vp-kt 有待辦 issue 標記為「HAIP v1／ETSI TS 119 472-2」：#484 移除 X509Hash 以外的 client_id prefix、#485 只保留 direct_post、direct_post.jwt、dc_api、#486 移除未簽章請求。來源：https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt/issues 。
  - **[推論]** EU 生態系將收斂到 `x509_hash` 搭配簽章與加密回應。Multipaz 驗證者預設使用 `x509_san_dns`（`MPZ/multipaz-verifier-server/.../verifier.kt:372`），我們的驗證者應改為支援 x509_hash。

### B3. DC API（EUDI）
- **[確認]** 預設停用。支援的 protocol 為 `org-iso-mdoc`、`openid4vp-v1-signed/unsigned`，**不支援 multisigned**，也不支援 DCQL 的 `multiple:true`。需要另外加入 `registry-provider-play-services:1.0.0-alpha04`。**matcher 使用 Multipaz v0.101.0 的版本**。來源：https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/main/DIGITAL_CREDENTIAL_API.md 。

### B4. OpenID4VCI 1.0、WIA 與 WUA
- **[確認]** openid4vci-kt 以 OpenID4VCI 1.0 為目標，支援 auth code 與 pre-auth、PAR（若發行者支援）、DPoP、PKCE、attestation-based client auth（draft-07）、proof types（jwt、jwt+key attestation、attestation）、batch、**deferred**、**notification**、signed metadata 政策、請求與回應加密。W3C VC 僅支援 JWT 形式。來源：https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt 。
- **[確認]** wallet-core 提供 `WalletAttestationsProvider.getWalletAttestation`（WIA，做為 OAuth client attestation）與 `getKeyAttestation`（WUA／key attestation）。PoP 只支援 ES256，「Notify credential issuer」功能不支援。來源：wallet-core README。
- **[確認]** ARF 本文用 Key Attestation（KA）與 Wallet Instance Attestation（WIA）稱呼，規格為 TS3 WUA。KA 與 WIA **只提供給 PID 或 Attestation Provider**，不給 RP。來源：`scratchpad/dl/arf6.md` §6.5.3.4-6.5.3.5、https://eudi.dev/latest/technical-specifications/ts3-wallet-unit-attestation/ 。

### B5. WRPAC 與 WRPRC 如何呈現驗證者身分（ARF 3.0.0，2026-07-21）
- **[確認]** RP 認證（§6.6.3.2）的要求：
  - 請求必須附 access certificate 與中繼憑證（不含 trust anchor），並由 RP 簽章
  - 錢包用 Access CA LoTE 的 trust anchor 驗證憑證鏈，並以 CRL/OCSP 檢查撤銷，離線時使用快取的 CRL
  - 簽章或鏈驗證失敗時應中止
  - 無法取得撤銷資訊時，是否繼續由 Wallet Provider 決定
  - 來源：`scratchpad/dl/arf6.md` 第 1338-1398 行、https://eudi.dev/latest/main/06-trust-model/
- **[確認]** WRPRC 驗證（§6.6.3.3）：
  - 每個 intended use 各有一張證書，一個請求只能有一個 intended use
  - 錢包驗證以下項目：格式正確、簽章可由 registration certificate provider 的 LoTE 驗證、RP 識別碼與 Service 識別碼和 access certificate 相同（或透過 `usesIntermediary` 指向中介者）、未過期、未撤銷
  - 失敗時要警告使用者
  - 請求超出登記範圍（over-asking）時要警告，並由 Wallet Provider 決定處理方式（全部可同意、只送已登記項目、或全部拒絕）
  - 同意必須明確
  - **此要求在修訂 CIR 2024/2982 生效後 24 個月才強制**
  - 來源：`arf6.md` 第 1400-1460 行
- **[確認]** 顯示內容（§6.6.3.5.3-5.5）：
  - 顯示 **RP trade name 與 Service trade name**，資料來自 registration certificate
  - 顯示 **intended use 的描述**與**隱私政策 URL**，同樣來自 registration certificate
  - 請求 PID 肖像時須警告這是生物特徵資料
  - 有中介者時，**UI 不顯示中介者名稱**（只顯示被代理 RP 的名稱），但交易紀錄必須記錄中介者
  - 來源：`arf6.md` 第 1532-1606 行、§6.6.5（第 2127-2188 行）
- **[確認]** 交易紀錄的必要欄位包含：RP 的 trade name、識別碼、Service 識別碼與所在國；中介者資訊；請求與實際提供的屬性；註冊機構 URL；資料刪除聯絡方式；DPA 資訊；intended use 與隱私政策 URL。來源：`scratchpad/dl/annex2.md` 第 3845-3847 行（ARF Annex 2，Topic 19/44）。
- **[確認]** TS5 的資料模型包含以下欄位：
  - `tradeName`、`serviceTradeName`（顯示用）
  - 識別碼：EUID 優先，其次為國家方案
  - `intendedUseIdentifier`、`purpose`（多語）、`privacyPolicy`
  - `entitlements`、`credentials`（含 claims path）
  - `isIntermediary`、`usesIntermediaries`、`supervisoryAuthority`、`srvDescription`、`isPSB`
  - 證書內容依 ETSI TS 119 475 定義
  - TS5 附註指出，依 CIR 的識別碼清單，WRP 都是**法人**；自然人作為 RP 是選項之一
  - 來源：`scratchpad/dl/ts5-common-formats-and-api-for-rp-registration-information.md` 第 96、145、175、244 行，https://eudi.dev/latest/technical-specifications/ts5-common-formats-and-api-for-rp-registration-information/
- **[確認]** wallet-core 的實作方式：
  - 載體：OpenID4VP 的 `verifier_info` 中 `format="registration_cert"`（TS 119 472-2 §6.3.2.2），以及 mdoc proximity/DC API 的 `ItemsRequest.requestInfo.euWrprc`（§5.3.2）
  - `WrpRegistrationPolicy` 與 `DefaultWrpRegistrationEvaluator`
  - 結果為 `Verified(registration, overAskedClaims)` 或 `Failed(reason)`，失敗原因包括 CERTIFICATE_ABSENT、MALFORMED、SIGNATURE_INVALID、UNTRUSTED_PROVIDER、NOT_BOUND_TO_REQUESTER、EXPIRED、STATUS_MISSING、REVOKED、REVOCATION_STATUS_UNKNOWN
  - `requiresExplicitApproval` 旗標
  - **沒有設定 trust 時不做任何驗證，`wrpRegistration` 為 null**
  - 發行端對應為 `IssuerRegistrationPolicy`（entitlement 檢查與 over-providing）
  - 來源：https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/main/REGISTRATION_CERTIFICATE.md
  - **[推論]** 可直接參考這套設計，在 Multipaz 之上實作 KMP 版本。
- **[確認]** wallet-core 的 reader authentication 政策有 DoNotEnforce、EnforceIfPresent（預設）、AlwaysRequire。trust 可用 `EtsiReaderTrustStore`（LoTE）或靜態憑證（撤銷政策 HardFail、SoftFail、NoCheck）。限制：內建的 LoTE JWT verifier **只驗簽章，不做 PKIX、CRL、OCSP 檢查**。來源：wallet-core README。

### B6. 法人 PID、代理授權與 intended use
- **[確認]** ARF 3.0.0 已**移除**法人錢包與法人 PID 的主題，改由另行開發的 business wallet 處理。Topic 28 的 LP_01 等要求為空白。來源：`scratchpad/dl/03-roles-within-the-eudi-wallet-ecosystem.md:59`、`annex2.md:965,4730-4745`。
- **[確認]** 代理授權目前只有討論主題「I - Natural person representing another natural person」（Iteration 5，仍在精修階段）。來源：https://eudi.dev/latest/discussion-topics/ 。
- **[確認]** 驗證者（RP）多半是法人，也可能是中介者代表另一個 RP（§6.6.5）。intended use 與 purpose 寫在 WRPRC 中，見 B5。
- **[推論]** 要在 UI 區分「個人／法人／代表組織的個人」，可依序使用以下來源：WRPRC 的 legal entity 欄位；WRPAC subject 的 organizationIdentifier（ETSI EN 319 412-1 語意識別碼，如 `VATxx-`、`NTRxx-`、`LEIXG-`）；若 subject 只有 givenName/surname 則判為自然人；有中介者時依 `usesIntermediaries` 判斷。需對照 ETSI TS 119 475 確認。

### B7. ZKP（ARF 與 TS）
- **[確認]** ARF Annex 2 Topic 53 的要求：
  - ZKP_01 至 ZKP_04：證明屬性值、效期、未撤銷、裝置綁定；證明持有某類型 attestation；將 attestation 綁定到 PID；pseudonym
  - 必須同時可用於遠端與近場流程，不可讓 UX 延遲到失去意義
  - SHOULD 能直接用於已簽發的 18013-5 與 SD-JWT VC 憑證
  - 不得引入可追蹤的資訊
  - 只能使用 ECCG Agreed Cryptographic Mechanisms v2.0 的演算法
  - 來源：`scratchpad/dl/annex2.md:7204-7300`
- **[確認]** TS4（v1.0 2025-05-21、v1.0.1 2026-01-30）只是**技術概覽**，比較 BBS+、BBS#、ECDSA-based（Ligero/Longfellow 類）、Crescent，**尚未選定方案**。TS13（zkSNARK）與 TS14（ZKPs from MMS）也已列出。來源：`scratchpad/dl/ts4-zkp.md`、https://eudi.dev/latest/technical-specifications/ 。
- **[確認]** wallet-core 已透過 Multipaz Longfellow 支援 ZKP（v7 circuits），但**產生 proof 失敗時會自動退回一般 DeviceResponse**（不含 ZKP）；BLE central 模式可能傳輸不完整。來源：ZKP.md。
  - **[推論]** 這個自動退回機制有隱私風險，我們應該讓使用者明確選擇是否退回。

### B8. Token Status List 與 Trusted List／LoTE
- **[確認]** wallet-core 支援 JWT 與 CWT 格式的 status list，可設定時鐘偏差，status list 簽署者可用 ETSI TL 驗證，實作程式庫為 `eudi-lib-kmp-statium`。Multipaz 本身也支援 IETF Status List，見 A4。
- **[確認]** LoTE（ETSI TS 119 602）與 TL（TS 119 612）由 `eudi-lib-kmp-etsi-1196x2` 提供，包含 PID、Wallet、WRPAC、WRPRC provider 各自的 profile 限制。來源：https://github.com/eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2 。

### B9. EUDI 已知問題
- **[確認]** wallet-core 的 open issues（來源：https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/issues ）：
  - #360 `OpenId4VpReaderTrustImpl.isTrusted()` 在 2 層 PKI 時失敗
  - #383 不支援 BLE L2CAP
  - #378 不支援 NFC 資料傳輸（README 也寫明 proximity 只支援 BLE）
  - #336 `NfcEngagementService` 會干擾 EMV 感應支付
  - #385 DPoP key 預設沒有硬體使用者驗證
  - #391 取消呈現後不會 redirect
  - #353、#352 VCI 相關問題
- **[確認]** openid4vp-kt 有 #484、#485、#486（HAIP 收斂，見 B2）與 #399（mdoc 的 transaction data）。

### B10. 可能遇到的問題（EUDI）
1. 核心程式庫都是 JVM 或 Android 專用，無法在 CMP iOS 共用；iOS 端需要另走 Swift kit，或自行在 Multipaz 上實作。
2. 版本耦合：wallet-core 鎖定 Multipaz 0.101.0，如果我們升級 Multipaz，可能出現 binary 不相容。**[推論]**
3. HAIP 收斂後只接受 x509_hash 與加密回應，自建驗證者必須配合。
4. 所有程式庫都聲明不建議用於生產，而且只維護最新版。
5. WRPRC 必須搭配 LoTE trust 設定才有作用；未設定 trust 時不會有任何驗證。
6. 法人 PID 與代理授權在 ARF 3.0 都沒有定案。
7. ZKP 方案未定（TS4 只是概覽），Longfellow 可能不是最終選擇。

---

## C. Microsoft Entra Verified ID

### C1. 持有端程式庫
- **[確認]** 程式庫為 `microsoft/entra-verifiedid-wallet-library-android`，**授權 MIT**，只支援 Android（minSdk 26），不是 KMP。README 標示「Private Preview」並寫明「Releases are not maintained」。Maven 座標為 `com.microsoft.entra.verifiedid:walletlibrary`。最新 release 為 1.0.0（2023-06），1.0.1（2024-03）加入 P-256 支援。來源：https://github.com/microsoft/entra-verifiedid-wallet-library-android 、https://learn.microsoft.com/en-us/entra/verified-id/whats-new 。
- **[確認]** dev 分支仍在更新，最近的 commit 為 2026-10-08「Harden linked domain origin validation」、DID resolver hardening 等。證據：`MSW/` 的 `git log`。
- **[確認]** 協定方面：
  - deep link scheme 為 `openid-vc`，`SELF_ISSUED_V2 = https://self-issued.me/v2/openid-vc`（SIOPv2）
  - 使用 Presentation Exchange
  - OpenID4VCI 只在 preview feature flag 中（`OpenID4VCIAccessToken`、`OpenID4VCIPreAuth`，預設 false）
  - 證據：`MSW/walletlibrary/src/main/java/com/microsoft/walletlibrary/util/PreviewFeatureFlags.kt:10-35`
- **[確認]** 持有者識別碼**只支援 did:jwk + P-256**，存放在 `EncryptedSharedPreferences`。證據：`MSW/.../datasource/repository/HolderIdentifierDataRepository.kt:11-25`。
  - **[推論]** 持有者私鑰未綁定硬體，而且 androidx security-crypto 已被棄用。
- **[確認]** 依賴：nimbus-jose-jwt、Room、Dagger。
- **[確認]** iOS 對應程式庫為 `entra-verifiedid-wallet-library-ios`（Swift）。

### C2. 標準與版本
- **[確認]** 使用的標準：W3C VCDM v1.1、JWT-VC、**did:web**（2023-12 起是唯一的 trust system，did:ion 已移除）、SIOPv2、OpenID4VP（未標版本）、OpenID4VCI（連結指向 draft 11）、DIF Presentation Exchange v2.0.0、Well-Known DID Configuration、W3C Status List（2023-04 草案）。簽章演算法為 ES256K、EdDSA、P-256，**P-256K 金鑰在 2026-07-01 退役**。來源：https://learn.microsoft.com/en-us/entra/verified-id/verifiable-credentials-standards 、whats-new。
- **[確認]** 互通規範為 DIF JWT VC Presentation Profile：
  - 參照 SIOPv2 ID1 與 OpenID4VP ID1
  - 使用 `openid-vc://` 並以 `request_uri` 傳遞（`application/jwt`）
  - **client_id 為 RP 的 DID**
  - 回應為 id_token + vp_token，只支援 direct_post
  - 來源：https://identity.foundation/jwt-vc-presentation-profile/

### C3. Linked Domains 作為驗證者身分證據
- **[確認]** DID document 中有 `LinkedDomains` service，網域的 `/.well-known/did-configuration.json` 內含由同一 DID 簽署的 DomainLinkageCredential（JWT）。
- **[確認]** Authenticator 顯示「Verified 與網域」的條件：
  - 請求的簽章 DID 帶有 linked domain endpoint
  - 網域使用 HTTPS 且不 redirect
  - well-known 檔案可以取得
  - 檔案中的憑證由同一個 DID 簽署
  - 任一條件不成立時，顯示全頁「unverified」警告
  - 來源：https://learn.microsoft.com/en-us/entra/verified-id/how-to-dnsbind
- **[確認]** 程式庫模型：`LinkedDomainResult` 分為 `LinkedDomainVerified(domainUrl)`、`LinkedDomainUnVerified(domainUrl)`、`LinkedDomainMissing`，對外以 `RootOfTrust(source, verified)` 提供。證據：`MSW/.../did/sdk/credential/service/models/linkedDomains/LinkedDomainResult.kt`、`MSW/.../requests/RootOfTrust.kt`。
- **[推論]** Linked Domains 只能證明「這個 DID 控制這個網域」，強度約等同 DV 等級。它沒有法人或組織的驗證，和 WRPAC/WRPRC（受監管 CA 加上註冊機構）不是同一層級，UI 應該用不同的信任等級呈現。

### C4. 互通注意事項與可能問題
1. Multipaz 不支援 W3C VC、DID、SIOPv2、Presentation Exchange 或 `openid-vc://`，因此**必須另建一套協定堆疊**，例如自行以 KMP 實作，或在 Android 端包 MS 程式庫（只限 Android 且為 MIT 授權）。**[推論]**
2. MS 使用 OpenID4VP ID1（PE）與 OpenID4VCI draft 11，和 OpenID4VP 1.0（DCQL）及 OpenID4VCI 1.0 不相容。**[確認]** 依據 C2。
3. 需要 did:web 解析（DNS、HTTPS、快取、hardening）與 Linked Domain 驗證；MS 最近剛修補過 origin validation，表示這部分容易出現安全問題。**[推論]**
4. 持有者的 did:jwk 金鑰不在硬體中，和 EUDI 要求的 WSCD／金鑰證明不一致。**[推論]**
5. MS 的程式庫是 Private Preview 且不維護 release，長期可用性不確定。

---

## D. 對本專案的綜合建議（皆為推論）
- 底層採用 Multipaz 0.101.x（KMP，Android/iOS/CMP），驗證者 UI 參考 TestApp 與 Identity Reader。
- 需要自建的「驗證者身分層」（commonMain）：
  1. OpenID4VP client_id prefix 驗證，包含 x509_san_dns、x509_hash，可再加 did 與 verifier_attestation
  2. 以 LoTE 驗證 WRPAC，並檢查 CRL/OCSP
  3. 解析 WRPRC（`verifier_info` 與 mdoc `requestInfo.euWrprc`），做 binding 與 over-asking 檢查
  4. 解析 subject 以判斷身分類型
  5. 呈現 purpose 與隱私政策
  6. 處理中介者情境並寫入交易紀錄
  7. 呈現 Linked Domains 或 did:web 的結果，並標示為較低的信任等級
- 以上可參考 EUDI wallet-core 的 `WrpRegistrationEvaluator` 與 `RegistrationFailureReason` 設計。
- ZKP：持有端與驗證端都使用 multipaz-longfellow（mdoc），並要求發行者簽發精簡憑證；明確處理是否退回非 ZKP，並提供使用者選項。
- 協定版本矩陣應涵蓋 OpenID4VP draft24、1.0（HAIP 子集）與 ID1（MS），以及 OpenID4VCI 1.0 與 draft11（MS）。

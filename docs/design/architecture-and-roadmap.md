# DIW MY WALLET 技術背景與跨平台轉換規劃

撰寫日期：2026-10-10
## 結論

建議以 Kotlin Multiplatform（KMP）加 Compose Multiplatform（Android 與 iOS 共用介面）為主體，Multipaz 0.101.0 為憑證與金鑰底層，Android 先行。第二輪調研確認三件事：TWDIW 是自有方言而非標準 OID4VC、Multipaz 沒有「以驗證者憑證為證據」的能力、以及沒有任何開源庫能在 commonMain 完整驗證 PAdES 或 OFD，這三層都要自建。

- 標準必備、非標準可選：OpenID4VCI 1.0、OpenID4VP 1.0（DCQL）、SD-JWT VC、mdoc、ISO 18013-5、W3C DC API 為核心；TWDIW 方言、Bonds 風格的 G2C 功能與 Microsoft JWT-VC 皆以**常駐啟用、僅對所屬 session 生效**的方言外掛處理，不提供開關。
- 驗證者透明：請求先走標準認證（x509\_hash 等），再以 verifier\_info 攜帶驗證者自己的憑證（法人、代理、員工憑證）證明身分、代表關係與目的，皮夾依 T1 至 T4 四級提示。
- ZKP：短期用 Longfellow（mdoc，發行端不必改），並以 OpenAC 補 SD-JWT（已有 TWDIW 年齡證明 PoC），BBS 列為中長期。驗證端同樣支援。
- 文件：驗證核心先放 Android／JVM（BouncyCastle、EU DSS 部分模組、ofdrw），iOS 後續以 GmSSL、OpenSSL、PDFium 接上。
- 2026-10-16 進度：P0–P3 主體已落地，PR #11 補 OpenID4VCI Client Authentication、DC API 多重簽章、VICAL／RICAL 和 P3 簽署安全性。mdoc `transaction_data` 已加入 DeviceSigned＋MSO 授權處理，JWE Request Object 核心新增 ECDH-ES 解密；OpenID Federation 與 App 端 JWE 密鑰配置仍需完成；P4 長證明與 P6 iOS 為後續階段。Android HTTPS App Links 暫不規劃。
## 參考來源盤點

五個來源各有分工：Multipaz 是唯一的 KMP 底層，TWDIW 定義台灣生態系的實際方言，Bonds 示範第三方皮夾如何接上 G2C 服務，EUDI 提供標準與驗證者透明的規則，Microsoft 是企業端互通對象。

| 來源 | 定位 | 平台／語言 | 憑證格式 | 協定 | 授權 | 本專案用途 |
| --- | --- | --- | --- | --- | --- | --- |
| [Multipaz](https://github.com/openwallet-foundation/multipaz) | OpenWallet Foundation 數位身分 SDK，0.101.0（2026-09-10），仍在 1.0 前 | KMP：Android（minSdk 26）、iOS、JVM；Kotlin 2.2.21、CMP 1.10.1 | mdoc、SD-JWT VC（dc+sd-jwt）、mso\_mdoc\_zk | OpenID4VP draft24 與 1.0、DCQL、OpenID4VCI、ISO 18013-5、DC API | Apache-2.0 | 底層：金鑰、格式、近端、驗證者功能、Longfellow ZK |
| [TWDIW 官方 App](https://github.com/moda-gov-tw/TWDIW-official-app) | 數位發展部數位憑證皮夾 | Android Kotlin、iOS Swift、協定在 Flutter、後端 Spring Boot | VCDM 外層包 SD-JWT（typ vc+sd-jwt） | OID4VCI draft 13 風格、OID4VP draft（PE v2、jwt\_vp） | MIT | 相容目標與測試後端 |
| [Bonds（有備而來）](https://github.com/bonds-tw/Bonds-iOS) | 第三方台灣公民身分皮夾研究原型，對應 [準備好數位政府系列](https://pro.mashbean.net/?series=ready-digital-government) | iOS Swift＋Rust（ZK、PKCS#11） | TWDIW 方言、vc+moica、電子公文 EN／DI／ESW | TWDIW OID4VCI／VP、TW FidO SP API v2.9、BLE／QR 離線驗證 | Apache-2.0（兩個 lite repo 為 GPL-3.0） | G2C 非標準實作參考 |
| [EUDI Wallet](https://eudi.dev/latest/) | 歐盟 ARF v3.0.0（2026-07-21）與參考實作 | wallet-core 僅 Android且依賴 Multipaz；openid4vp／vci／sdjwt 為 JVM | mso\_mdoc、SD-JWT VC | OpenID4VCI、OpenID4VP、HAIP、rQES（CSC）、Token Status List | Apache-2.0，官方聲明非生產用 | 標準對齊、WRPAC／WRPRC 驗證者透明、簽章 |
| [Microsoft Entra Verified ID](https://learn.microsoft.com/entra/verified-id/verifiable-credentials-standards) | 企業 VC 服務 | 雲端＋Android 程式庫（MIT、Private Preview） | JWT VC（VCDM 1.1） | SIOPv2、OpenID4VP ID1、PE v2、did:web、Linked Domains | 商用服務 | 企業員工證互通；Multipaz 不支援 W3C VC／ DID，需另建堆疊 |

完整調研筆記（各點附檔案行號或 URL，標註已確認／推論）放在專案檔案 research 資料夾。

## TWDIW 官方 App 現況

TWDIW 儲存庫的用戶端是三層拼接：原生 App 負責介面與儲存，內嵌的 Flutter 模組負責 OID4VCI／OID4VP 協定，原生 Token SDK 負責金鑰與 NFC，三者以 MethodChannel 傳 JSON 字串溝通。

| 元件 | 路徑 | 技術 | 觀察 |
| --- | --- | --- | --- |
| Android 持有端 App | APP/moda-digitalwallet-holder-androidapp | Kotlin 1.9.23、MVVM、Hilt、Room + SQLCipher、Biometric、ZXing，minSdk 28、targetSdk 35 | 約 234 個 Kotlin 檔，View（非 Compose）介面 |
| Flutter APPSDK | APP/APPSDK/lib | Dart，約 1,500 行，pointycastle、dart\_jsonwebtoken | 產生 did:key、ES256 簽章、pre-authorized code + tx\_code、presentation\_definition、StatusList |
| Android Token SDK | APP/APPSDK/...-androidapp-token-sdk | Kotlin 1.8.20、Android KeyStore／StrongBox、ISO-DEP NFC | P-256 金鑰產生與 JWS 簽章 |
| iOS 持有端 App 與 SDK | APP/moda-digitalwallet-holder-iosapp | Swift、Secure Enclave | 同樣內嵌 Flutter Framework |
| 發行端／驗證端後端 | core-system/twdiw-\* | Spring Boot 3.3.13、Java 17、Docker；前端 Vue 3 + Quasar 2 | 可作為本地測試環境；API 規格 v1.2.1（2025-12-23） |

TWDIW 實際方言（由原始碼與 Bonds 實機紀錄交叉確認）與標準的落差如下；第三方皮夾必須有一個 TWDIW Profile 才能互通。

| 環節 | TWDIW 實際做法 | 標準做法 | 對第三方的影響 |
| --- | --- | --- | --- |
| 發證端限制 | token 請求必須送 client\_id=moda\_dw，proof iss 也要是 moda\_dw，否則回 400 錯誤 11007（VCItemDataService.java:151） | Wallet Attestation 或登錄 client | 送 moda\_dw 等同冒用官方 client，上線前需取得數位部同意 |
| Metadata 與 token | 無 AS metadata，token 端點硬組；必帶 authorization\_details 與 tx\_code（可空）；c\_nonce 在 token 回應；offer 只能取一次；metadata 的 credential\_issuer 無結尾斜線而 offer 與 proof aud 有，well-known 只支援附加式路徑（2026-10-10 正式端點實測） | OpenID4VCI 1.0、Nonce Endpoint | 需客製流程並寬鬆比對 issuer 識別碼，失敗後無法重取 offer |
| 持有者金鑰 | proof kid 只能是裸 did:key（jwk\_jcs-pub 多種編碼 0xEB51，JSON 成員順序不限，JCS 排序亦被接受，2026-10-10 本地實測），帶 jwk header 回 11016 | jwk 或 key attestation | 自寫 did:key 編解碼並寬容解析 |
| 憑證格式 | typ vc+sd-jwt、無 vct、\_sd 在 vc.credentialSubject 內、無 KB-JWT；metadata 却宣稱 jwt\_vc\_json | SD-JWT VC（dc+sd-jwt、頂層 claims、KB-JWT） | Multipaz 無法直接解析，需自訂 parser |
| 出示 | client\_id 為裸 DID、PE v2、jwt\_vp（header 帶 jwk、aud=驗證者 DID、context 無 @）、form direct\_post、私有 custom\_data | DCQL、client\_id 前綴、KB-JWT、direct\_post.jwt | 需並存兩套出示程式碼 |
| 狀態 | StatusList2021 外包 {statusList: jwt}，statusListIndex 為字串，簽章金鑰不在 DID 文件中 | IETF Token Status List | 無信任錨可驗，只能標示為「未驗簽」 |
| 信任清單 | 數位部 trust list（分頁有陷阱）加 Arbitrum 鏈上錨定；前端 /api/did 無文件 | LoTE／Trust List | 需快取與驗證兩種信任來源 |
| 網路 | Cloudflare 曾依 User-Agent 擋請求（錯誤 1010）；2026-10-10 雲端實測 API 主機 7 種 UA 皆未擋，官網與 demo 站則封鎖雲端 IP | 無 | 台灣網路實機 D1 未被擋，正式 App 不需偽裝 UA |
| 入口 | modadigitalwallet://authorize、App Links 只開官方 App | openid4vp://、openid-credential-offer:// | 第三方以 App 內掃描為主 |

官方 App 本身的缺陷不應照抄：選擇性揭露用子字串比對而多送欄位（issue #28）、不驗 request object 與 status JWT 簽章、VP 有效期 30 天、publicKeyToJwk 偊然產生非 32 bytes 座標、生物辨識未綁定金鑰。GitHub 上 11 個 open issue 皆無維護者回覆，已關閉的 issue 本次無法讀取。DWVP-05 離線 QR 的 X25519、ChaCha20-Poly1305、TOTP 都在驗證端後端完成，兩份文件對 TOTP 步長寫法矛盾（60 秒與 30 秒）。

## 目標架構

&#91;embedded content: 目標架構 · 四層加外部服務\]

標準核心永遠啟用；虛線的非標準 Profile 只在使用者或設定開啟時參與，且一律經過信任引擎標示等級。平台層只放金鑰硬體、系統 API 與原生庫的對接，因此加上 iOS 時不需重寫協定、介面與儲存。

裝置完整性不以 Key Attestation 單獨判定：實機 D1 證實 root 機可產生偽造但簽章有效的證明鏈。App 端只收集金鑰證明與 Play Integrity 結果並上傳，由錢包提供者後端判定；依使用者決定（2026-10-10），多數情況只需確認金鑰證明有效，不特別檢查是否為 RKP 鏈；判定結果決定可否申請 EUDI 等要求 key attestation 的憑證，與軟體兜底層的降級標示一致。

## 協定與演算法支援矩陣

標準項目一律必備且預設開啟；非標準項目以 Profile 外掛，可個別關閉，且永遠不改變標準流程的行為。「底層」欄寫明哪些由 Multipaz 提供、哪些要自建。

| 類別 | 標準（必備） | 非標準／舊版（可選 Profile） | 底層 |
| --- | --- | --- | --- |
| 發證 | OpenID4VCI 1.0（pre-auth、auth code、PAR、DPoP、deferred、batch、key attestation） | OID4VCI draft 11（Microsoft）、draft 13（TWDIW）、vc+moica 自簽（Bonds） | Multipaz（deferred #1948 有問題、PAR 必填）＋自建相容層 |
| 出示 | OpenID4VP 1.0（DCQL、transaction\_data、verifier\_info、direct\_post.jwt）、HAIP、W3C DC API、ISO 18013-5／18013-7 | OpenID4VP draft＋PE v2（TWDIW、Microsoft）、SIOPv2、TWDIW DWVP-05、Bonds BTWVP1 QR／BLE | Multipaz（缺 expected\_origins 檢查、只接受 x5c）＋自建 |
| client\_id | x509\_hash（HAIP 必備）、x509\_san\_dns、verifier\_attestation、decentralized\_identifier、openid\_federation、redirect\_uri、origin | 裸 DID（TWDIW） | 多數需自建（Multipaz 未檢查 SAN／hash 是否吻合） |
| 憑證格式 | SD-JWT VC（dc+sd-jwt）、mdoc、mso\_mdoc\_zk | JWT-VC（VCDM 1.1）、VCDM 包 SD-JWT（TWDIW）、W3C Data Integrity（含 bbs-2023） | Multipaz 不支援 W3C VC，需自建 |
| 識別與信任 | X.509、IACA／VICAL、ETSI LoTE／Trusted List、OpenID Federation | did:key（含 0xEB51）、did:jwk、did:web＋Linked Domains、TWDIW trust list、Arbitrum 鏈上錨定 | EUDI etsi-1196x2（KMP）＋自建 |
| 狀態 | IETF Token Status List、ISO mdoc status、CRL／OCSP | StatusList2021、Bitstring Status List | EUDI statium（KMP）＋自建 |
| 簽章演算法 | ES256／384／512、EdDSA、RSA-PSS／PKCS#1、Brainpool、ML-DSA（後量子） | ES256K、SM2／SM3（國密）、RSA-4096 自然人憑證 | Multipaz 已列 Brainpool、Ed25519、ML-DSA，但需逐台確認硬體支援；SM2 用 BouncyCastle／GmSSL |
| 加密 | ECDH-ES、A128／256GCM（回應加密）、HPKE | X25519＋ChaCha20-Poly1305（TWDIW DWVP-05）、AES-256-GCM（TW FidO）、SM4 | Multipaz 回應加密只支援 ECDH-ES |
| ZKP | Longfellow（mso\_mdoc\_zk）、ISO／IEC 27565 指引 | OpenAC（SD-JWT）、BBS／bbs-2023、Groth16 應證鏈證明（Bonds） | Multipaz longfellow＋Rust FFI |
| 文件簽章 | PAdES、CAdES、XAdES、JAdES、ASiC、RFC 3161、RFC 4998 | 中國 OFD＋SES（GM／T 0031、GB／T 38540）、台灣公文 DI／SW XMLDSig、廠商 SM2 PDF 簽章 | 全部自建（見「電子文件與簽章解析」） |
| 遠端簽章 | CSC API v2（rQES） | TW FidO SP API v2.9、自然人憑證 PKCS#11 | EUDI rqes-core（JVM）＋自建 |

## 驗證者身分、代表身分與目的

目前沒有跨生態的標準讓驗證者用自己的可驗證憑證證明身分，Multipaz 的同意畫面也只顯示本地信任清單裡的名稱，沒有身分類型或目的欄位。建議做法是：先用標準方式完成 client 認證，再用 OpenID4VP 1.0 的 verifier\_info（近端則用 18013-5 的 requestInfo）放入一份「驗證者聲明」，由請求簽章金鑰簽署並綁定本次 nonce 與 client\_id。

證據採用順序（依你的要求，驗證者自己的憑證優先）：

1. 驗證者皮夾中的憑證出示（VP）：法人憑證、代理授權憑證（如 EUDI 試點的 urn:eu.europa.ec.eudi:por:1）、員工或職務憑證，以 KB-JWT 綁定 nonce 與 client\_id。
2. EUDI 註冊應證 WRPRC（verifier\_info 的 format registration\_cert），含法定名稱、是否公部門、多語目的、允許請求的憑證與 claim 範圍；eudiw.dev 已實測可取得，UI 需比對本次請求是否超出登記範圍。
3. X.509 存取應證（WRPAC 或在地 PKI），簽署 request object。
4. TWDIW DID 註冊資料中機關宣告的 x509\_serial 與 x509\_subject（XCA、MOEACA）：註冊 JWS 本身為自簽，錢包可依序號向政府 PKI 儲存庫取憑證比對，作為非標準的加強證據。
5. OpenID Federation 信任鏈。
6. did:web 加 Well-Known DID Configuration（只證明網域控制，強度約等同 DV 應證）。
7. 未經證實的自我聲明。

聲明內容與皮夾的檢查：

- 代表身分 actor.kind：個人、法人、代表法人的個人、代表個人的個人；法人識別碼可用統一編號、EUID、LEI。
- 目的 purpose：用途說明、法律依據、保存期間、隱私權政策、要請求的欄位清單。
- 一致性：憑證中的法人識別碼要等於存取應證或 WRPRC 的主體；代理憑證的法人要等於法人憑證；實際 DCQL 請求必須包含於聲明與登記的範圍內，超額欄位逐項標示。
- 驗證者的 ZKP：組織內的個人可用 ZK 只揭露「機關與角色」不揭露姓名；法人本身不可匿名。
- 互通：自訂的 verifier\_info format 會被其他皮夾忽略，因此一定保留 registration\_cert 標準路徑，自訂聲明只是增益。

信任分級與提示（同樣套用在發證者，即非官方憑證）：

| 等級 | 條件 | 提示方式 |
| --- | --- | --- |
| T1 官方或符合安全要求 | 簽章鏈到官方信任清單（數位部 trust list、LoTE、在地 RP PKI），證據有效且請求未超額 | 簡化提示：名稱、身分類型、目的、「已驗證」標籤 |
| T2 身分已驗證但目的未登記或超額 | 鏈有效，但缺 WRPRC 或請求超出登記範圍 | 黃色警告，超額欄位逐項標示，可只送已登記部分 |
| T3 非官方但可驗證 | 密碼學驗證通過，信任錨不在官方清單（DID、Federation、自訂 PKI） | 「此驗證者自稱為……，由……證明」，使用者確認後可接受，可記住此選擇 |
| T4 未知或匿名 | 未簽章或鏈驗證失敗 | 紅色「無法驗證請求者身分」，預設不送高敏感欄位，可設為一律阻擋 |

另加註獨立標籤：測試信任錨、經中介者、會保存資料、含 transaction\_data。EUDI 規定經中介者的請求不顯示中介者名稱（但要記錄），與 Multipaz 預設「代表某方請求」的顯示相反，需依 Profile 切換。

## 主動驗證能力

皮夾本身可切換為驗證者，沿用 Multipaz 的 VerificationSession（已支援 DC API、OpenID4VP 與 18013-5 近端，含 reader authentication），介面參考 Multipaz TestApp 與 Identity Reader（同為 Compose Multiplatform）。

- 驗證對象：mdoc、SD-JWT VC、mso\_mdoc\_zk、TWDIW 方言 VP、Bonds BTWVP1 離線包（chunked QR／BLE，與 ISO 18013-5 BLE 不相容，需另寫傳輸），以及 OpenAC 與 Longfellow 的 ZK 證明。
- 驗證者身分：發出請求時可附上自己的驗證者聲明，證據取自皮夾中的法人、代理或員工憑證；另需 x509\_hash 存取應證，私鑰放 Android Keystore／StrongBox 並附金鑰證明。
- 驗證結果：逐項列出簽章、信任錨、狀態、有效期、裝置綁定的結果，「部分通過」不得看起來像「通過」（沿用 Bonds 設計原則）。
- 離線：快取信任清單與撤銷快照，結果上標示快取時間。
- 限制：iOS 原生 App 不能透過 DC API 發出請求，WifiAware 傳輸在 Multipaz 尚未實作。

## ZKP 策略

以一個 ZkBackend 介面串接三種方案，依 DCQL 的 format 與 zk\_system\_type 路由；持有端產生證明、驗證端驗證證明使用同一組實作。

| 方案 | 適用格式 | 發行端需配合 | 行動裝置效能 | 標準化 | 實作來源 | 定位 |
| --- | --- | --- | --- | --- | --- | --- |
| Longfellow | mdoc（ECDSA P-256） | 不需要，但 MSO 需 ≤ 2533 bytes | Pixel 6 Pro 產生 0.8–1.2 秒、驗證約 0.6 秒、證明約 400 KB | IETF draft-google-cfrg-libzk-02，EUDI TS13 | Multipaz multipaz-longfellow（僅 arm64-v8a、x86\_64） | 短期主力 |
| OpenAC | SD-JWT ES256、mdoc | 不需要 | Pixel 10 Pro 準備 5.2 秒（峰值 2.27 GiB）、每次出示 308 ms | 無 | ethereum／zkID（MIT），Mopro／UniFFI；已有 TWDIW 年齡證明 PoC，電路內建民國日期 | 補 SD-JWT、TWDIW 年齡證明 |
| BBS／bbs-2023 | 新格式（W3C Data Integrity） | 需要改用 BLS12-381 簽章 | 證明 < 2 ms | CFRG draft-12、W3C CRD | zkryptium 等（Rust） | 中長期、預留介面 |
| Groth16 應證鏈證明 | 自然人憑證 X.509（RSA-4096／2048） | 不需要 | 資產約 1 GB | 無 | Bonds（Apache-2.0） | 可選，有可重放的已知風險 |

- 大型電路與金鑰依 circuit hash 按需下載並以 SHA-256 驗證，不放進 APK。
- 依裝置記憶體分級；超時或記憶體不足時退回一般選擇性揭露，並告知使用者隱私等級較低。
- 驗證端需預載發行者公鑰清單（證明會隱藏發行者應證）。
- 撤銷檢查若用 Token Status List 會破壞不可連結性，需選擇不暴露索引的方式（如 TS13 的 signed-pairs 或 Merkle 樹非成員證明）。
- ISO 18013-5 第二版仍在定稿，ZK 欄位名稱在 Multipaz、TS13、Google 之間已不一致，需做版本協商。

## 電子文件與簽章解析

沒有開源庫能在 commonMain 完整驗證 PAdES、XAdES 或 OFD，因此共用層只放資料模型、ByteRange 規則、OFD 解析、JWS 與保存功能，密碼驗證先放 Android／JVM；驗證結果統一用 ETSI EN 319 102-1 的 Indication／SubIndication 表示。

| 格式 | Android／JVM 實作 | iOS 實作 | 授權風險 | 重點問題 |
| --- | --- | --- | --- | --- |
| PAdES／PDF CMS（含自然人憑證 PDF 簽章） | PdfBox-Android（取 ByteRange、修訂版）＋BouncyCastle（CMS、TSP、OCSP）＋自寫 ETSI 驗證邏輯 | PDFium＋OpenSSL（cinterop）或商用 SDK | 低；iText 為 AGPL 不採用 | 需自行防禦 USF、ISA、SWA、Shadow 攻擊；EU DSS 的 PAdES 模組用到 java.awt，Android 可能不可用 |
| CAdES、JAdES、ASiC、RFC 3161 | BouncyCastle；可選 EU DSS 的 cades／jades／asic 模組 | OpenSSL、Signum（JWS 可在 commonMain） | DSS 為 LGPL-2.1，需法務確認 Android 合規做法 | BC 1.73 與 1.85 會在 Gradle 衝突；Android 上要傳 provider 實例而非名稱 "BC" |
| XAdES／XMLDSig（台灣電子公文 .di／.sw／.si） | Apache Santuario，關閉 DTD／XXE | xmlsec1＋libxml2 | 低 | 公文為簽核點逐一鏈式加簽、RSA-2048＋SHA-256；需防 XML 簽章包裝攻擊 |
| 中國 OFD＋SES 電子印章（v1 GM／T 0031-2014、v4 GB／T 38540-2020、v5 在 ofdrw 已見但未找到官方公告） | ofdrw（Apache-2.0）＋BC SM2／SM3，自補印章有效期、製章者應證鏈、撤銷、時戳 | commonMain 自寫 OFD 解析＋GmSSL | 低 | ofdrw 的驗證程式自註「僅用於測試」；簽章在 Signs／Sign\_N／Signature.xml，以 SM3 逐檔雜湊 |
| 中國 OFD 數位簽名（GB／T 35275）、國密 X.509 | BC（SM2 OID 1.2.156.10197.1.301、SM3withSM2 1.2.156.10197.1.501、預設 user ID 1234567812345678） | GmSSL | 低 | 信任錨沒有公開的機器可讀清單，境外可能連不到撤銷服務 |
| 中國 PDF SM2 簽章、數電發票 XML | PdfBox-Android＋BC SM2；XMLDSig 路徑 | PDFium＋GmSSL | 低 | 無國家標準，為廠商擴充，只能「盡力驗證」；發票權威驗證為線上查驗平台 |
| 無簽章文件、MyData 下載檔 | 匯入時雜湊＋RFC 3161 時戳＋ RFC 4998 Evidence Record，匯出用 ASiC-E | 同左（commonMain 可共用） | 低 | 已簽章 PDF 不可轉 PDF／A；MyData 格式與簽章無公開規格，需實際樣本 |

信任錨以簽章後的信任包下發，分台灣 GPKI（GRCA 不在 Mozilla 與 Adobe AATL，必須自帶）、歐盟 LOTL、中國 SM2（盡力收集並標示信任等級）三組。完整的 DSS 驗證（含視覺修改偵測）可另放後端驗證服務，由 App 保存經簽章的驗證報告。

時戳支援：

- 建立：文件匯入時計算雜湊，向 RFC 3161 TSA 取得時戳作為存在證明；PDF 可加 PAdES 文件時戳（B-LTA）；中國文件另支援 SM2 時戳。
- 驗證：解析並驗證文件內嵌的簽章時戳與文件時戳，以時戳時間評估當時的應證有效性。
- 長期保存：以 RFC 4998 Evidence Record 串接多次時戳，在 TSA 應證或雜湊演算法到期前自動續認，匯出用 ASiC-E。
- TSA 可設定多家且同樣分正式與測試；實際採用哪幾家台灣與國際 TSA 尚待選定。鏈上錨定（如 Bonds 的 Arbitrum）列為非標準可選項，不取代 RFC 3161。
- TSA 信任獨立分區，不直接沿用 TLS 系統根憑證庫：實測 Apple、Microsoft、FreeTSA 的根不在系統庫，需內建或讓使用者選擇加入。國內 TSA（TWCA、HiNet）無公開端點，需簽約後再測。
- 離線時先以本機時間記錄並標示「待時戳」，連線後補取，不重寫既有紀錄。

## 台灣 G2C 擴充接口

台灣 G2C 尚無公開標準，因此每種政府服務都對應一個 commonMain 介面，現階段的實作參考 Bonds（Apache-2.0，可移植），未來有標準時只替換實作。兩個 mashbean lite repo 為 GPL-3.0，只參考行為不併入程式碼。每個相容用的特殊處理都註明日期、原因與移除條件（沿用 Bonds 的紀律）。

| 介面 | 現階段實作（參考 Bonds） | Android 差異與問題 |
| --- | --- | --- |
| TwdiwProfile（發證與出示方言） | 前文「TWDIW 官方 App 現況」列的全部方言；發證前先過數位部 trust list 與 Arbitrum 鏈上錨定兩道關卡 | client\_id=moda\_dw 需取得數位部同意；台灣網路實機未被 Cloudflare 擋 |
| MobileCitizenCertSigner（行動自然人憑證 TW FidO） | SP API v2.9：getSpTicket、getAthOrSignResult、推播，sp\_checksum 用 AES-256-GCM，以 mobilemoica:// App 對 App；正式版只能經簽章 broker | SP 密鑰不可放 App，broker 以 Play Integrity＋金鑰證明把關；SIGN 不簽驗證者 challenge，簽章材料可重放 |
| CitizenCardSigner（實體自然人憑證） | PKCS#11 簽章（Bonds 的 Rust 工具參考 open-gpki-pkcs11，LGPL） | 推論應走 USB CCID 讀卡機而非 NFC，需實機確認 |
| OfficialDocumentInbox（電子公文個人接收站） | 檔管局 EN／DI／ESW XML 三件組、SHA-256 完整性、G2B2C 公開通訊錄、自然人憑證同意簽章 | 合法送達與採購問題尚未解決，先做接收、驗簽、歸檔 |
| MyDataImporter | 將 MyData 身分證下載檔轉為自簽 vc+moica 憑證（一卡一鑰），明文即刪；另保存八種文件並以 SHA-256 指紋 | vc+moica 為自訂格式，驗證者認可需政策配合 |
| OfflinePresentation | BTWVP1 chunked QR、BLE LinkTransport、快取信任清單與撤銷快照 | 與 18013-5 BLE 不相容，另寫傳輸 |
| ConvenienceStorePickup | 官方離線驗證者清單（vpList）、短效條碼 | 需處理 401／402 分支 |
| G2cServiceProvider（通用） | 保留的未來標準接口：服務描述、信任錨、請求／回應轉換、使用者提示等級 | 由設定檔註冊，可個別停用 |

金鑰設計同樣沿用 Bonds：一張憑證一把持有者金鑰，避免兩個驗證者關聯同一人的不同憑證；Keystore 別名用不透明亂數，全部清除時必須涵蓋所有別名。

## 軟體兜底層

每項平台能力都有一個 commonMain 介面加一個純軟體實作，當 SDK 不支援、平台未提供或標準方法失敗時自動退回；退回一定會降低保證等級並在 UI 標示，不會默默發生。這讓同一份程式可跑在模擬器、無 Google 服務的 AOSP、Linux 手機（Compose Multiplatform 桌面版跑在 JVM）與 PC。Multipaz 的 jvm 目標、SoftwareSecureArea（全平台）與 JdbcStorage 已提供基礎。

| 能力 | 優先實作 | 退回順序 | 退回後的代價與標示 |
| --- | --- | --- | --- |
| 持有者金鑰 | StrongBox → TEE Keystore；iOS Secure Enclave | PC：TPM 2.0（PKCS#11）或智慧卡；最後 SoftwareSecureArea（密碼衍生金鑰加密） | 無金鑰證明，要求 HAIP 或 key attestation 的發證端可能拒發；標「軟體金鑰」 |
| 密碼演算法 | 平台提供者（Keystore、CryptoKit） | 內嵌 BouncyCastle（JVM／Android）、GmSSL／OpenSSL（原生） | Ed25519、Brainpool、SM2、ML-DSA 等在硬體不支援時改用軟體金鑰 |
| 使用者驗證 | BiometricPrompt 綁定金鑰 | 裝置密碼 → App PIN（Argon2id 衍生） | 標示驗證方式 |
| 加密儲存 | Keystore 包裝的資料金鑰 | 密碼衍生金鑰加密 SQLite（JdbcStorage） | 需使用者密碼，忘記即無法復原 |
| 出示入口 | DC API（Credential Manager，需 GMS） | OpenID4VP 跨裝置 QR → 自訂 scheme → 貼上連結／匯入 QR 圖檔 | 無瀏覽器 origin 綁定，需依請求簽章判斷來源 |
| 近端傳輸 | BLE、NFC（ISO 18013-5） | QR 分包→ 線上中繼 | 模擬器與多數 PC 無 BLE／ NFC |
| 相機 | CameraX | 圖檔解碼、貼上文字 | 無 |
| 裝置完整性 | Play Integrity、Key Attestation | 無法退回，改由使用者知情同意 | TW FidO broker 等需完整性證明的服務將無法使用 |
| ZK 原生庫 | Longfellow（Android arm64／x86\_64、JVM 僅 macOS 與 linux-x86\_64）、OpenAC | 停用 ZK，改一般選擇性揭露 | Linux 手機（aarch64）與 32 位元 ARM 暫無 Longfellow，需自行編譯 |
| 推播 | FCM | 輪詢 | 較耗電、延遲較高 |
| 可信時間 | 網路時間、TSA 回應時間 | 本機時鐘 | 標「時間未經驗證」 |

發佈版可依能力個別禁止退回（例如正式身分憑證不允許軟體金鑰）。診斷頁列出本機實際使用的每項實作，類似 Bonds 的裝置自檢。

## PKI 環境分區與參考 SDK 信任鏈

同一個 App 同時內建正式與測試兩套信任錨，每個信任錨、憑證、驗證結果都帶環境標籤；Multipaz 的 TrustMetadata 已有 testOnly 欄位可沿用。

| 環境 | 來源 | 預設 | UI 區分 |
| --- | --- | --- | --- |
| 正式（Standard） | 官方信任清單與正式根應證 | 啟用 | 一般配色，可達 T1 |
| 測試（Test） | 沙盒、UAT、一致性測試、參考實作的測試根 | 關閉，在開發者設定開啟 | 整頁「測試環境」條帶與浮水印，最高只到 T3，結果不得顯示為綠色通過 |
| 使用者自訂 | 使用者自行匯入的根或 DID | 關閉 | 標「使用者自訂信任」，最高 T3 |

規則：測試環境的憑證存在獨立空間，不得與正式憑證合併在同一次出示；正式驗證者請求不會配對測試憑證；發佈版內建的測試錨永遠不被當成正式（Bonds 「Release 不接受沙盒 issuer」原則，CI 檢查）。信任包以簽章方式下發，整批驗證後才原子替換。

要支援的參考 SDK 信任鏈（每種以一個 TrustResolver 插件實作）：

| 來源 | 信任鏈類型 | 正式 | 測試 | 實作基礎 |
| --- | --- | --- | --- | --- |
| TWDIW | 數位部發行者信任清單（DID 登錄、前端 /api/did）＋ did:key＋ StatusList2021 | 正式信任清單 | TWDIW 沙盒、自架 core-system | 自建（注意分頁陷阱與狀態清單金鑰無信任錨） |
| Bonds | 數位部信任清單＋ Arbitrum 鏈上錨定 | 同 TWDIW | issuer-lite 的 did:key 釘選例外 | 自建，鏈上錨定為可選 |
| Multipaz | ISO 18013-5 IACA → Document Signer；Reader root → reader cert；VICAL、RICAL | 各發行機關 IACA | Multipaz 測試 IACA（issuer.multipaz.org、Identity Reader） | Multipaz TrustManager 家族（Composite、Vical、Rical） |
| EUDI | ETSI LoTL／Trusted List（TS 119 612）與 LoTE（TS 119 602）：PID 提供者、Wallet 提供者、WRPAC CA、WRPRC 提供者；Token Status List | 歐盟 LoTL | EUDI 參考實作與一致性測試的測試根 | eudi-lib-kmp-etsi-1196x2、statium；內建 LoTE 驗證器只驗簽章，需自補 PKIX 與 CRL／OCSP |
| Microsoft Entra | did:web＋ Well-Known DID Configuration（Linked Domains）＋ W3C Status List | 正式租戶 | 測試租戶 | 自建（Multipaz 不支援 DID）；強度約等同 DV 應證，標 T3 |
| OpenID Federation | Trust Anchor → Intermediate → Leaf | 各聯邦 | 各聯邦測試錨 | 自建 |
| 台灣 GPKI | GRCA → MOICA／GCA／XCA 等 | 正式根（不在 Mozilla 與 AATL，需自帶） | 測試憑證機構 | BouncyCastle |
| 中國 SM2 | 各 SM2 根與中繼 | 盡力收集、標示信任等級 | 廠商測試根 | BouncyCastle、GmSSL |

## 開發測試伺服器與互通

自建一個多 Profile 的測試發行端與驗證端（Ktor，JVM），直接重用 App 的 KMP 核心，每個 Profile 對應一個參考 SDK 的行為；再用各 SDK 官方的測試伺服器做交叉驗證，避免「自己測自己」。全部屬於測試 PKI，只在測試環境可見。

| 測試對象 | 自建 Profile | 可自架的官方實作 | 公開測試站 |
| --- | --- | --- | --- |
| 標準（OpenID4VCI／VP 1.0、HAIP、DCQL、SD-JWT VC、mdoc、DC API） | std-haip | [eudi-srv-pid-issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer)、[eudi-srv-web-verifier-endpoint-23220-4-kt](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt)、[OpenID 一致性測試套件](https://gitlab.com/openid/conformance-suite) | EUDI 與 OpenID 基金會公開測試站 |
| Multipaz（mdoc、近端、Longfellow ZK、reader auth） | multipaz | multipaz-server、multipaz-openid4vci、multipaz-verifier（JVM）；multipazctl 產生測試 IACA | issuer／verifier.multipaz.org、Identity Reader |
| TWDIW 方言 | twdiw-pe-v2026 | TWDIW core-system（Docker，MIT） | TWDIW 沙盒 |
| Bonds 行為 | bonds-compat | issuer-lite、verifier-lite 可原樣自架做黑箱測試（GPL-3.0，不併入程式） | issuer／verifier.mashbean.net |
| Microsoft（JWT-VC、did:web、SIOPv2、PE v2） | ms-jwtvc | P2 自建 ms 風格測試端供本地驗收；正式互通仍需 Entra 測試租戶 | Entra 測試租戶 |
| 文件與 PKI | test-pki | 自建測試 CA、OCSP、TSA（含 RSA、ECDSA、SM2），可簽發測試用 X.509 使用者應證 | — |

實際環境的互通做法：依請求內容自動辨識 Profile，標準優先、方言後備；互通矩陣至少涵蓋 TWDIW 官方 App、EUDI 參考皮夾、Multipaz 皮夾與 Identity Reader、Chrome DC API，以及我方皮夾與對方驗證端互換角色。模擬器或單一實作成功不算通過互通門檻。

## 使用者 X.509 應證與自然人憑證

使用者自己的 X.509 應證用於三件事：文件簽章（PAdES／CAdES／XAdES）、挑戰回應式登入、TLS 用戶端認證；也可作為驗證者聲明的證據。

| 來源 | Android | iOS | PC／Linux | 節點 |
| --- | --- | --- | --- | --- |
| 自然人憑證實體卡，NFC | TP07 開頭的雙介面卡支援非接觸（內政部行動自然人憑證 App 已用 NFC 靠卡，要求 Android 12 以上）；第三方經 IsoDep 送 APDU | Core NFC ISO 7816，需在 Info.plist 宣告卡片 AID（官方 App 要求 iOS 17 以上） | USB NFC 讀卡機（PC／SC） | 推論可行，需以 TP07 卡實測；APDU 指令集與卡片 AID 待參考 open-gpki-pkcs11 確認 |
| 自然人憑證實體卡，接觸式 | USB CCID 讀卡機（USB Host） | 無通用路徑 | PKCS#11（HiCOS）或 PC／SC | 所有有效卡皆可用 |
| 行動自然人憑證（TW FidO） | SP API v2.9，經簽章 broker | 同左 | 同左 | 簽章材料可重放的已知風險 |
| PKCS#12 檔匯入 | 匯入 Keystore（不可匯出） | 匯入 Keychain | 軟體金鑰庫 | 金鑰曾存在檔案中，保證等級較低 |
| 系統應證庫 | Android KeyChain（使用者安裝的用戶端應證） | Keychain 身分 | OS 應證庫 | 依各平台授權流程 |
| 一般智慧卡、PIV、FIDO 硬體金鑰 | NFC／USB | Core NFC／CryptoTokenKit | PKCS#11 | 依卡片而定 |

風險：NFC 傳輸中移開卡片會失敗，PIN 連續錯誤會鎖卡，需清楚顯示剩餘次數；非 TP07 卡不支援 NFC，需退回讀卡機或 TW FidO。來源：[行動自然人憑證 NFC 靠卡教學](https://fido.moi.gov.tw/pt/main/teaching)。

## 判定模型與上線門檻

採用附件 Bonds 藍圖的做法：不把「可以收卡」、「驗簽通過」、「官方信任」、「業務資格」與「法定效力」合併成一個成功狀態。

- 六個獨立欄位：signatureValid、issuerTrusted、credentialStatus、holderBound、businessRule、assuranceLabel，再加上本專案的 environment（正式／測試／自訂）與 fallbacks（使用了哪些軟體兜底）；任一 unknown 都不可被 UI 簡化為通過。
- 出示請求狀態機增加 CONDITIONAL（簽章成立但狀態不明、來源等級不足或待人工審核），nonce 只接受一次。
- 離線判定輸出三個時間：憑證簽發時間、信任快照最後驗證時間、本地檢查時間。
- 文件保證等級：政府直接簽發、機關簽章文件衍生、持有人衍生（如 MyData 自簽）、沙盒虛構卡，四級分開顯示。
- Profile 以明確 ID 區分（例如 twdiw-pe-v2026、oid4vp-dcql-v1、oid4vci-twdiw-sandbox），不以「新版／舊版」模糊判斷。
- 上線門檻 Gate 0 至 4：來源與 profile 固定、合成資料 CI、真實裝置安全、跨實作互通、營運與制度；模擬器或軟體兜底成功不能代替 Gate 2。
- 用途政策檔（purpose\_policy）統一產生驗證者模式的告知、簽章請求與驗證政策，也是「驗證者聲明」中 purpose 的來源。

## 轉換方式

原則是「規格與後端重用，用戶端重寫」：TWDIW 協定層在 Flutter，無法進入 KMP；Bonds 是 Swift，亦只能移植設計與邏輯。

| 項目 | 來源 | 處理方式 | 理由 |
| --- | --- | --- | --- |
| 流程與畫面設計 | TWDIW Android App、Bonds design-system | 以 Compose Multiplatform 重寫 | Bonds 的「誠實即版面、部分通過不得像通過」原則直接採用 |
| TWDIW 協定邏輯 | TWDIW Flutter APPSDK、Bonds TWDIW／ | 以 Kotlin 重寫為 TwdiwProfile，不照抄官方 App 的缺陷 | 移除 Flutter 引擎與 MethodChannel |
| 標準 OID4VC、mdoc、近端、DC API | Multipaz | 直接使用，缺口自補或貢獻上游 | 唯一的 KMP 實作；API 在 1.0 前仍會變，需鎖版本 |
| 驗證者透明（WRPRC、過度請求判斷） | EUDI wallet-core | 移植 WrpRegistrationEvaluator 的邏輯到 commonMain | wallet-core 只支援 Android |
| 信任清單、狀態清單 | EUDI etsi-1196x2、statium | 直接使用（已是 KMP） | Apache-2.0 |
| 金鑰與儲存 | TWDIW Token SDK、Room＋SQLCipher | Multipaz SecureArea；儲存自寫 transform() 加密 | Multipaz 不做應用層加密 |
| 發行端、驗證端、管理介面 | TWDIW core-system | 原樣部署為測試環境 | MIT，可作互通測試對象 |
| G2C 服務、ZK、離線驗證 | Bonds | 移植到對應介面，Rust ZK 以 Mopro／UniFFI 接 Android | Apache-2.0 |
| 文件驗簽 | BouncyCastle、PdfBox-Android、ofdrw、Santuario、可選 EU DSS | androidMain／jvm 實作，commonMain 介面 | 見「電子文件與簽章解析」 |

## Microsoft Entra Verified ID 相容

原計畫只在來源盤點與支援矩陣列出 Microsoft Verified ID，路線圖沒有對應階段。2026-10-11 起列入 P2，作為常駐啟用的 ms-verifiedid Profile，獨立成模組，不進標準路徑。

| 項目 | Microsoft 現況 | 本專案做法 | 階段 |
| --- | --- | --- | --- |
| 入口 | `openid-vc://` 加 `request_uri`，回應為 application/jwt | 統一入口解析，交給 ms-verifiedid Profile | P2 |
| 出示 | SIOPv2 ID1 加 OpenID4VP ID1，`claims.vp_token.presentation_definition`，response\_mode post | PE v2 引擎產生 id\_token 與 jwt\_vp vp\_token | P2 |
| 原生發證 | issuance request 加 manifest，attestations 含 idTokens、selfIssued、presentations、accessTokens | 支援 selfIssued、presentations、idTokens（外部登入頁）；accessTokens 需租戶設定，僅保留接口 | P2 |
| OID4VCI | draft 11，仍為 preview | 走 draft11 方言 | P2 |
| 識別 | Issuer、Verifier 用 did:web；持有者用 did:jwk P-256 | did:web 解析與 did:jwk 持有者金鑰 | P2 |
| Linked Domains | did-configuration.json | 驗證通過時信任等級最高 T3，不視為官方 | P2 |
| 憑證與狀態 | JWT-VC 加 StatusList2021 | JWT-VC 儲存、驗章與 StatusList2021 | P2 |
| 演算法 | ES256K 已於 2026-07-01 退役 | 僅用於驗舊卡，不用於新簽章 | P2 |
| 互通驗收 | 需要 Entra 租戶 | 自建 ms 風格測試端做本地驗收；正式互通需 Entra 測試租戶，列入實機清單 | P2 |

## P2 實作規劃：OpenID4VC 全組合與相容 Profile

P2 完成後，下列各維度可任意組合。標準路徑（OpenID4VCI 1.0、OpenID4VP 1.0）不變；draft13、draft11、TWDIW、Bonds、Microsoft 五個 Profile 常駐啟用、不提供開關（2026-10-11 使用者決定），但各自獨立成模組，只在標準流程無法處理的位置介入，每張憑證與每次出示都記錄實際使用的規格。

### OpenID4VCI

| 維度 | 支援項目 |
| --- | --- |
| 版本 | 1.0、draft13、draft11/12、TWDIW 官方、Microsoft 原生發證 |
| 入口 | openid-credential-offer、haip-vci、https、modadigitalwallet（credential\_offer、authorize、staticqrcode）、TWDIW 中轉頁、openid-vc、錢包端發起 |
| Offer | by value、by reference、draft11 credentials 與 user\_pin\_required |
| Grant | pre-authorized code（tx\_code、user\_pin、空 tx\_code）、authorization code（PKCE、PAR） |
| 探索 | 插入式與附加式 well-known、AS metadata 與 openid-configuration、authorization\_server(s)、issuer token\_endpoint、`{issuer}token` |
| 格式 | dc+sd-jwt、vc+sd-jwt、mso\_mdoc、jwt\_vc\_json、jwt\_vc\_json-ld、jwt\_vc、ldp\_vc |
| Proof | jwt（jwk、kid did:jwk、did:key、jwk\_jcs-pub）、attestation、di\_vp、cwt |
| Request 形狀 | 1.0、draft13 format 加 proof、draft11 format 加 types、batch endpoint |
| Response | credentials 陣列、單數 credential、acceptance\_token 與 transaction\_id、加密、deferred、notification |

### OpenID4VP

| 維度 | 支援項目 |
| --- | --- |
| 版本 | 1.0、draft 18 至 24（client\_id\_scheme）、ID1 加 SIOPv2、TWDIW 官方 |
| 查詢 | DCQL、PE v2（presentation\_definition、presentation\_definition\_uri、claims.vp\_token） |
| response\_type | vp\_token、vp\_token id\_token、id\_token |
| response\_mode | direct\_post、direct\_post.jwt、fragment、query、post、dc\_api、dc\_api.jwt |
| 格式 | mso\_mdoc（含 ISO 18013-7 舊版 handover）、mso\_mdoc\_zk、dc+sd-jwt、vc+sd-jwt、jwt\_vp\_json、jwt\_vp 與 jwt\_vc、ldp\_vp、vc+moica |
| 加密 | 1.0 jwks、舊版 authorization\_encrypted\_response\_alg/enc |
| 結果處理 | redirect\_uri、response\_code、TWDIW code 0 |

### TWDIW 官方與 Bonds 覆蓋範圍

| 項目 | 階段 |
| --- | --- |
| TWDIW 發證、出示、StatusList2021、信任清單、靜態 QR、中轉頁、DWVP-05 離線出示 | P2 |
| Bonds Arbitrum 鏈上錨定、超商取貨、電信卡目錄、vc+moica、BTWVP1 分段 QR、BLE frame、custom\_data | P2 |
| Bonds OpenAC ZK 與持證證明 | P4 |
| TW FidO、MyData、電子公文、實體卡 PKCS#11 | P3（TW FidO SP 簽章與電子公文收發等外部條件） |
| TWDIW 官方私有 NFC 出示、換機轉移 | 不支援（無公開規格） |

TWDIW 發證端要求 client\_id 為 moda\_dw，代表本錢包會以官方 App 的識別碼領卡。此值在設定中揭露給使用者並可修改，方言本身不可關閉。

UI：新增「台灣數位憑證」頁面，展示 TWDIW 憑證（卡面、發行機關、信任清單與鏈上錨定結果、狀態）與 Bonds 自訂內容（超商取貨條碼、電信卡申請目錄、離線出示）及各自圖示；Bonds 文件類支援排在 P3（2026-10-11 階段調整，見「文件憑證方案比較」）。P2 一併更新 AGENTS.md 與 README.md。

P2 驗收：自建測試端涵蓋各方言的本地測試全數通過；TWDIW 正式領卡與出示、Entra 租戶互通、BLE 等列入實機清單。

## P1–P3 當前可驗收邊界（2026-10-16）

- P1：OpenID4VCI 已支援公開用戶端、Wallet Attestation 與 JWT Client Assertion 協商；正式發證需要簽章者被發證端登記或信任，不能由測試 PKI 自行聲稱。App Links 暫不規劃。
- P2：Digital Credentials API 支援多重 JWS JSON 請求與完整驗簽、防降級；新增 VICAL／RICAL 的獨立清單發行者信任角色、到期與版本防回退。mdoc `transaction_data` 已依 MSO 授權產生 DeviceSigned；JWE Request Object 僅在錢包提供真正解密密鑰時才可解密，尚未完成 App 端金鑰發佈與簽章巢狀支持；OpenID Federation 未有信任鏈與政策時必須拒絕。
- P3：TW FidO、CSC v2、電子公文 SI／DI／XML 的公開規格可用於個人錢包；正式政府 SP、QTSP、機關公文交換權限屬外部帳號／法定授權，**不列為本專案未完成的軟體功能**。
- 自動測試通過與外部正式互通為不同驗收項；R8 Android Release、Windows／Linux 封裝、協定測試及實機驗證分別列示。

## 分階段路線圖

六個階段依序推進，每個階段都以「可在實機上展示的端到端流程」作為驗收；介面與核心從第一天就寫在 commonMain，iOS 在 P6 接上。

| 階段 | 內容 | 驗收條件 |
| --- | --- | --- |
| P0 骨架與風險實測 | KMP＋CMP 專案、鎖定 Multipaz 版本；實測 Cloudflare UA、moda\_dw 發證、EU DSS 與 ofdrw 在 Android 執行、BC 版本衝突；建立軟體兜底層與正式／測試信任分區，讓模擬器與 JVM 桌面版即可跑通流程；架設多 Profile 測試發行端與驗證端及測試 CA、OCSP、TSA | 三項實測有結論並更新本文件 |
| P1 標準核心（Android） | PIN／生物辨識綁定金鑰、OpenID4VCI 1.0、OpenID4VP 1.0（DCQL）、SD-JWT VC、mdoc、DC API、Token Status List、補 expected\_origins 與 client\_id 檢查 | 通過 Multipaz 與 EUDI 測試發行端／驗證端（2026-10-11 完成，PR #1 已合併） |
| P2 OpenID4VC 全組合與相容 Profile | OpenID4VCI／OpenID4VP 各版本、格式、grant、proof、response\_mode 全組合；draft13、draft11、TWDIW 官方、Bonds、Microsoft Verified ID 五個 Profile 預設啟用可關閉；StatusList2021 等狀態清單、TWDIW 信任清單與鏈上錨定、超商取貨、離線 QR／BLE、Linked Domains、非官方憑證接受提示 | 自建各方言測試端本地測試全數通過；實機從 TWDIW 發行端領卡並通過 TWDIW 驗證端，並以 Entra 測試租戶互通 |
| P3 文件、簽章與衍生憑證 | PAdES／CAdES（含 PKCS#7 .p7s／.p7m）／XMLDSig／OFD＋SES 驗證、三組信任包、保存與時戳；自然人憑證卡 NFC／USB／PC/SC 簽章與主動簽署（PAdES、ASiC-E、自製證書）；文件衍生憑證（SD-JWT VC，可匯出 vc+moica）與自然人憑證證據層；教育部、MyDoc、MyData、戶政、地政、移民署取件入口；戶籍 asdt 解析嘗試；OpenCerts 只匯入保存；行動自然人憑證用於內嵌頁面登入；行動自然人憑證 SP 簽章、CSC 遠端簽章、電子公文收發等外部條件前為停用列 | 以測試樣本通過 ETSI 驗證報告比對；實機以 TP07 卡 NFC 簽出可被 DSS 驗證的 PAdES；一份真實文件產生衍生憑證並被另一台手機查驗 |
| P4 ZKP（文件與憑證） | 共用原生 ZK 執行環境與裝置分級與退回；zkTLS（TLSNotary，先做即時模式，第一個對象學信網報告與移民署證明書查驗頁，兩者都不需自然人憑證，離線用裝置證明紀錄）；zkPDF 版型電路（含加密 PDF，第一個對象為中國大陸大學在學證明（未加密、RSA 簽章、有時戳），再做大陸國家移民管理局的出入境記錄與關聯證明（RC4 加密且使用者密碼為空））；Longfellow 持有與驗證、OpenAC SD-JWT 年齡證明 | 中階機完成一次文件 zkTLS 出示與一次 ZK 憑證出示與驗證；zkPDF 若手機做不到則以桌面產生並在畫面標明 |
| P5 驗證者透明與主動驗證 | 驗證者聲明、WRPRC、T1–T4 提示、驗證者模式（含自己的聲明與證據）；衍生憑證與 ZK 證明的查驗政策 | 兩台手機互為持有者與驗證者，顯示身分、代表關係與目的 |
| P6 iOS | iosMain：Secure Enclave、GmSSL、OpenSSL、PDFium、ZK 原生庫；另以軟體兜底層驗收 AOSP、Linux 手機與 PC（JVM） | P1 至 P5 在 iOS 實機通過 |

## P0 驗證結果（2026-10-10）

不需實體證件的 P0 項目已在雲端容器以本機服務驗證，未連線任何政府主機。完整結果見 research/validation-2026-10-10.md，程式與記錄在 validation/ 目錄。

| 項目 | 結果 | 對規劃的影響 |
| --- | --- | --- |
| Multipaz 0.101.0（JVM） | 通過：18 種軟體金鑰演算法、JDBC 儲存、mdoc、SD-JWT VC + KB、OpenID4VP 1.0 + DCQL | 可作底層；JVM 需自行接線 storage、SecureArea 與同意提示 |
| Longfellow ZK（linux-x86\_64） | 通過：證明約 1.7 秒、驗證約 0.9 秒、峰值約 400 MB | 發行端需產生 ZK 友善 mdoc，完整樣本 mDL 會超過 MSO 上限 |
| Multipaz 請求驗證 | 確認缺口：不檢查 expected\_origins、x509\_san\_dns、x509\_hash，無 verifier\_info | 自建請求驗證層列為 P1 必修 |
| PAdES/XAdES/CAdES/JAdES（EU DSS 6.5） | JVM 全通過，含 B/T/LT/LTA、竄改、撤銷、測試與正式信任分區 | 桌面與兜底層可直接用；Android 需自建 PAdES 驗證路徑 |
| OFD 與 SM2（ofdrw 2.4.0、BC） | 通過：GB/T 38540 印章、GB/T 35275 簽章、SM2 CMS、SM2 簽章 PDF | DSS 不支援 SM2，中國文件走自建 BC 路徑；ofdrw 驗證需補鏈與撤銷檢查 |
| RFC 3161 時戳 | 本地 TSA 通過 | 公開 TSA 互通待網路放行 |
| BouncyCastle 版本 | BC 1.83 使 ofdrw SM2 失敗，1.85、1.86 全通過 | 統一 BC 1.85 以上，避免 ofdrw-full（iText AGPL） |
| TWDIW 方言 | 真實 core 發證端重現 11007/11016；自製持有端發證、驗證、出示全通 | TWDIW profile 設定已定案；Multipaz 發證與 OID4VP 需相容層 |
| 測試伺服器 | EUDI Verifier、EUDI PID Issuer、OIDF 一致性測試、Multipaz 伺服器皆可本地執行 | EUDI Issuer 需 key attestation，軟體兜底金鑰無法通過 |
| TWDIW 正式端點（補驗） | API 主機可達且 UA 層未擋；官網與 demo 站封鎖雲端 IP；沙盒 API 需帳號 Access-Token | 實機 D1 確認台灣網路不被擋，此風險解除 |
| 公開 RFC 3161 TSA（補驗） | 10 家皆核發；Apple、Microsoft、FreeTSA 的根不在系統庫 | TSA 信任獨立分區 |
| eudiw.dev（補驗） | Verifier 請求帶 registration certificate，錢包函式庫以嚴格 PKIX 解析成功；Issuer 全面要求 key attestation | WRPRC 列為驗證者證據；需錢包提供者後端 |
| Android APK（補驗） | KMP + CMP 測試 APK 建置成功（release 25.9 MB）；桌面兜底以同一份程式碼通過 | ofdrw 需排除 xpp3 與 pull-parser；Longfellow 無 32 位元 ARM，需標示降級 |

補驗報告見 research/validation-network-2026-10-10.md。仍待完成：TWDIW 沙盒端到端（需使用者註冊沙盒帳號）、國內 TSA（需簽約）、OIDF 線上一致性測試，以及 Android 執行期、Keystore、生物辨識、NFC 與 ZK 的實機測試；實機以 validation/android-smoke 的測試 APK 與 device-test-checklist.md 為基準，正式 App 沿用同樣檢查項。

## 風險與待確認事項

最大的風險仍在信任體系：TWDIW 發證端只接受官方 client\_id，第三方皮夾若未獲數位部同意就上線等同冒用。以下依影響排序。

- 信任與政策：client\_id=moda\_dw 限制、Bonds 整理的 9 條上游問題均未揭露、TWDIW issues 無維護者回覆；後續可能加入皮夾認證而阻擋第三方。
- 網路阻擋：2026-10-10 雲端實測 TWDIW API 主機在 UA 層未擋，Bonds 記錄的 1010 可能來自 TLS 指紋或 IP 信譽；wallet.gov.tw 官網與 demo 站封鎖雲端 IP。台灣網路實機（D1）以 OkHttp 與 Dalvik 預設 UA 送 10 個請求全部成功、官網也可開，正式 App 不需偽裝 UA；雲端 CI 仍可能被官網封鎖。
- 錢包提供者後端：EUDI 發行端（本地與 eudiw.dev 皆實測）每種憑證都要求錢包提供者簽發的 key attestation（iso\_18045\_high），需規劃錢包提供者後端，以 Android Key Attestation 與 Play Integrity 為輸入；純軟體兜底金鑰無法取得 EUDI PID。實機 D1 發現 root 機可偽造 Key Attestation 鏈（顯示已鎖定與 Verified、簽章有效且不在撤銷清單），只有 RKP 鏈顯示真實狀態；使用者決定多數情況只需確認金鑰有效、不特別檢查 RKP，接受 root 機可能通過的殘餘風險；Play Integrity 可作為高保證場景的選用加強。
- Multipaz 在 1.0 前：API 與磁碟資料格式會變，有已知 issue（#1947–#1952，含 deferred 發證、iOS 無法偵測金鑰失效），且 2026-10-10 實測確認錢包不檢查 expected\_origins、不比對 x509\_san\_dns 與 x509\_hash、沒有 verifier\_info、testOnly 不強制，必須自建請求驗證層。
- 標準收斂：HAIP 要求 x509\_hash，EUDI 方向是只留簽章請求與加密回應；ISO 18013-5 第二版與 ZK 欄位仍在變。
- 驗證者聲明為自訂格式：其他皮夾會忽略，必須同時支援 WRPRC；WRPRC 在修法生效後 24 個月才強制，提示嚴格度需可調。法人與代理模型（ARF 3.0 已移除法人 PID，轉由 European Business Wallet）仍未定案。
- ZKP 資源：OpenAC 峰值記憶體 2.27 GiB、Bonds 應證鏈證明資產約 1 GB，中低階機可能 OOM；Longfellow 不支援 32 位元 ARM，實機 prove 約 0.8 秒、verify 約 0.4 秒但峰值記憶體約 1 GB，低階機需評估是否被系統終止；EUDI 要求只用 ECCG 核可演算法，BBS、Spartan 是否符合有疑義。
- 文件驗簽：已實測 EU DSS 的 PAdES 依賴 PDFBox 3 的 java.awt、驗證依賴 JAXB/StAX/XSD，不能直接上 Android；DSS 不支援 SM2；ofdrw 需 BC 1.84 以上，Android 端需排除 xpp3 與 pull-parser，且不引入 ofdrw-reader 的影像與關鍵字功能；LGPL 合規需法務確認；中國信任錨與撤銷服務境外不一定可取得；MyData 與數電發票 XML 簽章無公開規格。
- 台灣簽章：TW FidO SIGN 不簽驗證者 challenge，簽章材料可重放；SP 密鑰一定要放後端 broker；實體卡在 Android 的讀卡方式待實測。
- 未取得資料：本次環境無法讀取 GitHub 已關閉 issue，也無法連上 pro.mashbean.net 報告內文（只讀到索引，實際 8 篇），對應內容以 Bonds repo 的 docs 替代。

## 參考資料

- [moda-gov-tw/TWDIW-official-app](https://github.com/moda-gov-tw/TWDIW-official-app)（commit 99e9deb；APPSDK、Android App、Token SDK、core-system、Docs 全讀）
- [bonds-tw/Bonds-iOS](https://github.com/bonds-tw/Bonds-iOS)（commit e22de5f）、[twdiw-vp-verifier-lite](https://github.com/mashbean/twdiw-vp-verifier-lite)、[twdiw-vc-issuer-lite](https://github.com/mashbean/twdiw-vc-issuer-lite)、[bonds-tw.github.io](https://github.com/bonds-tw/bonds-tw.github.io)
- [準備好數位政府系列](https://pro.mashbean.net/?series=ready-digital-government)（僅讀到索引）
- [openwallet-foundation/multipaz](https://github.com/openwallet-foundation/multipaz)（commit cd9578b3）與 [Multipaz 入口](https://www.multipaz.org/)
- [EUDI ARF v3.0.0](https://eudi.dev/latest/)、[EUDI 參考實作](https://docs.eudi.dev/latest/)、[eu-digital-identity-wallet](https://github.com/eu-digital-identity-wallet) 各庫
- [Microsoft Entra Verified ID 支援標準](https://learn.microsoft.com/entra/verified-id/verifiable-credentials-standards)
- 文件簽章：EU DSS 6.5、ofdrw、PdfBox-Android、GmSSL、BouncyCastle 原始碼；ZKP：draft-google-cfrg-libzk-02、EUDI TS13／TS14、ethereum／zkID
- 五份詳細調研筆記（各點附檔案行號或 URL）已併附於本次回覆的專案檔案

# P0 驗證結果：不需實體證件的項目（2026-10-10）

> **2026-10-10 歷史驗證結果。** 原始測試方法與結果不可直接套用於後續 PR #11。最新協定、簽署流程、CI 與授權邊界詳見 [2026-10-16 專案狀態](../status-2026-10-16.md)。

所有驗證都在雲端容器內以本機服務完成，未連線任何 *.gov.tw 主機，也未以 client_id=moda_dw 對正式政府伺服器送出請求。
驗證程式與記錄保存在 `專案共用資料夾 validation/`（multipaz、docs、twdiw、servers 四個子目錄）。

## 環境限制

- 本專案使用內建雲端環境，網路政策只放行套件庫。被擋的主機：*.wallet.gov.tw、moica/grca.nat.gov.tw、公開 TSA（freetsa、DigiCert、Sectigo、GlobalSign）、eudiw.dev、certification.openid.net、bonds.tw、dl.google.com（Android SDK）、jitpack.io、repo.danubetech.com、maven.waltid.dev、ghcr.io 的映像 blob、quay.io。
- 因此以下項目尚未能驗證：TWDIW 正式與沙盒端點的 Cloudflare UA 阻擋、公開 TSA 互通、eudiw.dev 線上服務、Android APK 建置與實機行為。
- 若要驗證，需在 Project settings 新增雲端環境並放行這些網域（https://code.claude.com/docs/en/cloud-environments#network-access）。

## 總表

| 範圍 | 結果 | 重點 |
|---|---|---|
| Multipaz 0.101.0 JVM | 通過 | 軟體金鑰 18 種演算法、JDBC 儲存、mdoc 往返、SD-JWT VC + KB、OpenID4VP 1.0 + DCQL、Longfellow ZK 全部通過 |
| Multipaz 安全缺口 | 已確認 | expected_origins 未檢查、x509_san_dns 與 x509_hash 未綁定憑證、無 verifier_info、testOnly 只供顯示 |
| PAdES/XAdES/CAdES/JAdES（EU DSS 6.5） | JVM 通過 | B/T/LT/LTA 全部 TOTAL_PASSED；竄改、撤銷、測試/正式信任分區都如預期 |
| OFD + SM2（ofdrw 2.4.0） | JVM 通過 | GB/T 38540 電子印章與 GB/T 35275 簽章可簽可驗，竄改可偵測 |
| SM2 CMS 與 SM2 簽章 PDF | 通過（自建） | BC 可驗；EU DSS 不支援 SM2，需自建驗證器 |
| RFC 3161 時戳 | 通過（本地 TSA） | 雜湊時戳、驗證與竄改偵測正常 |
| BouncyCastle 版本 | 需 1.84 以上 | BC 1.83 使 ofdrw SM2 拋 NoSuchMethodError；1.85、1.86 全部通過 |
| Android 相容性 | 有阻礙 | DSS PAdES 依賴 PDFBox 3 的 java.awt；DSS 驗證依賴 JAXB、StAX、XSD |
| TWDIW 方言 | 通過 | 真實 core-system 發證端本地執行，重現 11007/11016；自製 JVM 持有端發證、驗證、出示全通 |
| EUDI Verifier | 通過（自原始碼建置） | x509_san_dns、x509_hash（HAIP）、DC API 皆可；請求帶 verifier_info |
| EUDI PID Issuer + Keycloak | 部分 | metadata 與授權伺服器正常；不支援 pre-authorized code；需 key attestation |
| OIDF 一致性測試套件 | 通過（自原始碼建置） | 81 個測試計畫，含 OID4VP/OID4VCI HAIP 的錢包端與發行端 |
| Multipaz 伺服器 | 通過（僅 JVM 模組） | verifier、backend、openid4vci 三個伺服器可在 JVM 執行 |

## 一、Multipaz 0.101.0（JVM）

- 依賴：multipaz、multipaz-doctypes、multipaz-longfellow 0.101.0 皆有 -jvm 版。Multipaz 發布件本身不帶 BouncyCastle，只用 JDK 加密；Brainpool 需把 BC 設為第一順位 provider。
- multipaz-doctypes 經 tink-android 拉入 androidx.annotation，需由 Google Maven 取得；在被封鎖環境需排除。消費端需 `optIn("kotlin.time.ExperimentalTime")`。
- SoftwareSecureArea：純 JDK 10 種、加 BC 共 18 種（ES256/384/512、Ed25519、Ed448、ECDH P-256/384/521、X25519、X448、Brainpool）。竄改簽章皆被拒。
- 儲存：EphemeralStorage、SQLite、HSQLDB 通過；SQLite 重開後金鑰與憑證仍在。
- mdoc：發 mDL、讀者簽章 DeviceRequest、DeviceResponse、VerificationUtil 驗證；未知 IACA 被拒；錯誤 session transcript 驗證失敗。TrustMetadata.testOnly 可帶出。
- SD-JWT VC：5 個揭露項只出示 2 個加 KB-JWT；錯 nonce、錯 aud、錯發行者金鑰、竄改 KB 皆拋例外。
- OpenID4VP 1.0 + DCQL（DC API 路徑）：簽章請求、加密回應、同時要 mDL 與 SD-JWT PID，本地往返通過。
- Longfellow ZK（linux-x86_64）：證明 1.6 至 1.8 秒、驗證 0.8 至 0.9 秒、證明約 360 KB、峰值 RSS 約 398 MB。完整樣本 mDL 會失敗（MDOC_PROVER_TAGGED_MSO_TOO_BIG），發行端需產生 ZK 友善憑證。
- JVM 限制：Platform.storage、promptModel、getSecureArea 在 JVM 拋 NotImplementedError，需自行接線；需使用者驗證的軟體金鑰在 JVM 會 KeyLockedException；BLE/NFC 傳輸、CloudSecureArea、multipaz-dcapi、multipaz-compose 無純 JVM 版。

### 安全缺口（以實際探測確認，0.101.0 與 main 分支相同）

1. 錢包不檢查 expected_origins：攻擊者來源也會得到回應。轉送給真驗證者時 mdoc 部分會因 transcript 失敗，但 SD-JWT 部分仍通過，因 verifySdJwtPresentation 不檢查 aud。
2. client_id 為 x509_san_dns 時不比對憑證 SAN：偽造網域被接受。
3. client_id 為 x509_hash 時不檢查雜湊：全零雜湊被接受。
4. 完全沒有 verifier_info。
5. 驗證端 VerificationUtil 不驗發行者鏈，呼叫端需自行 TrustManager.verify。
6. testOnly 不會被強制執行。

結論：Wallet 必須在 Multipaz 之上自建請求驗證層（origin、client_id 綁定、verifier_info、信任分區強制），這與規劃中的 Verifier Declaration 層一致。

## 二、電子文件與簽章（JVM）

- 版本：EU DSS 6.5（LGPL-2.1，BC 1.85、PDFBox 3.0.8、xmlsec 3.0.6）、ofdrw 2.4.0（Apache-2.0）、BC 1.85。
- 本地 PKI：RSA 與 ECDSA P-256 三層鏈、SM2 鏈、本地 TSA/OCSP/CRL HTTP 服務。
- RFC 3161：imprintOk、nonceOk、竄改偵測皆為 true，token 可存檔後重驗。
- PAdES：RSA 與 EC 各 B/T/LT/LTA 共 8 份，全部 TOTAL_PASSED 且等級正確。竄改得 TOTAL_FAILED/HASH_FAILURE；撤銷簽署者得 INDETERMINATE/REVOKED_NO_POE。
- 信任分區：同一檔案在測試信任下 TOTAL_PASSED，在正式信任下 INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND，證明單一 App 內兩套信任來源可行。
- XAdES-T、CAdES-T/LT、JAdES-T 皆通過。
- OFD：GB/T 38540 v4 印章（SM2 製章者）與 GB/T 35275 簽章，ofdrw 驗證通過，竄改得 FileIntegrityException。ofdrw 驗證器不檢查憑證鏈、效期、製章者簽章與撤銷，需 App 補上。
- SM2：BC 可簽驗 SM2 CMS；SM2 簽章 PDF 可依 ByteRange 驗證。標準 BC CMS 需補 GM OID 名稱對應才能驗 GB/T 35275。EU DSS 遇 SM2 拋 Unsupported algorithm，中國政府 PDF 需走自建 BC 驗證路徑。
- BC 版本：DSS 6.5 要 1.85、ofdrw 要 1.84；BC 1.83 使 ofdrw SM2 拋 NoSuchMethodError（ASN1Integer(int)）。規則：BC 至少 1.84，建議 1.85 以上。避免 ofdrw-full（PDFBox 2 衝突、iText 7 為 AGPL）。
- Android 阻礙：
  - DSS 的 PAdES 依賴 PDFBox 3，執行時載入 91 個 java.awt 類別；PdfBox-Android 是 PDFBox 2 移植且套件名不同，無法直接替換。
  - DSS 驗證需 dss-policy-jaxb，依賴 JAXB、StAX、XSD SchemaFactory，Android 皆無。
  - 可用於 Android 的乾淨模組：dss-cades、dss-cms、dss-spi、dss-token、dss-jades、dss-model。
  - ofdrw 的簽驗模組乾淨；產生與讀取 OFD 的 layout、reader 依賴 java.awt。
- 對規劃的影響：Android 端 PAdES 需自建（PdfBox-Android 解析 + BC CMS + 自建 ETSI 驗證流程），或交由 JVM/伺服器端 DSS；桌面與兜底層可直接用 DSS。

## 三、TWDIW 方言

- 真實 core-system `twdiw-oid4vci-handler` 以 Maven 建置並在本地 Postgres 執行。vc-handler 與 oid4vp/vp-handler 因依賴只在 repo.danubetech.com 與 jitpack.io（被封鎖）而無法建置，以 Node stub 依原始碼格式替代 vc-handler。
- 實測錯誤碼：client_id 非 moda_dw 得 11007；proof 用 jwk header、iss 非 moda_dw、kid 帶 #fragment、kid 為 0x1200 did:key、aud 少結尾斜線皆得 11016。
- 修正先前筆記：JCS 排序的 did:key 也被接受，core 只做 base58 解碼後剝前綴再解析 JSON，成員順序不影響，只要求 0xEB51。
- 本地 tx_code 參數可省略（未啟用時），與 UAT 觀察不同。
- lite issuer 很寬鬆，無法用來確認 11007/11016。
- 自製 JVM 持有端：發證、驗發行者簽章（取自 iss 的 did:key）、cnf 綁定、7 個揭露雜湊、StatusList2021 撤銷位元，再以 PE v2 jwt_vp direct_post 出示給 verifier-lite 得 verified。
- verifier-lite 會拒絕錯 aud、錯 nonce、非 cnf 金鑰簽 VP、扁平 submission；只抓公開 HTTPS 的狀態清單。
- Multipaz 差距（需自建 TWDIW profile）：proof 用 jwk header、只收 dc+sd-jwt/mso_mdoc 且要 vct、要求 credential_issuer 完全相等、well-known 路徑插入方式不同、要求 AS metadata 與 nonce_endpoint、只解析 credentials[]、OID4VP 只收 DCQL、狀態清單只支援 IETF Token Status List、沒有 did:key。SdJwt.filter() 與 verify(key) 可重用。
- 最小 TWDIW 相容設定見 `validation/twdiw/holder/src/main/kotlin/tw/wallet/twdiw/Profile.kt`。

## 四、測試伺服器與互通

- EUDI verifier endpoint（commit df07af2，需 JDK 25）：waltid-mdoc-credentials 需自行建置。請求物件為 ES512 + x5c，response_mode=direct_post.jwt，含 verifier_info（registration_cert）。HAIP 模式強制 x509_hash。expected_origins 只出現在 DC API 端點。request_uri_method=post 需 wallet_metadata 帶 issuer、response_types_supported、direct_post.jwt。
- EUDI PID issuer（commit 944e060）+ Keycloak 26.6.2：metadata 預設為簽章 JWT、openid4vci_version=v1、強制加密請求與回應、proof 需 key attestation（iso_18045_high）、只支援 authorization_code、offer 只能用 https 或 eu-eaa-offer://。
- OIDF 一致性測試套件（commit 11999aa）：自原始碼建置（需排除 androidx.annotation），81 個測試計畫，已用 EUDI 錢包函式庫跑通 oid4vp-1final-wallet-happy-flow 的請求解析；完整 HAIP 需設定憑證與狀態清單信任錨。
- Multipaz 伺服器：只建 JVM 模組並改用 0.101.0 發布件後，verifier、backend、openid4vci 三個伺服器可啟動。互通問題：host 帶埠號時 client_id 變成 x509_san_dns:localhost:8006，與憑證 SAN 不符，EUDI 函式庫拒絕。
- 錢包端 E2E（eudi-lib-jvm-openid4vp-kt 0.16.2）：X509SanDns、X509Hash GET/POST、DC API 解析皆成功；錯 origin 得 UnexpectedOrigin；request_uri 必須 HTTPS。EUDI 範例中繼憑證 basicConstraints CA:FALSE，嚴格 PKIX 會失敗，正式測試需合格 CA 鏈。

## 對規劃文件的更新

- P0 風險：Multipaz JVM 可行、ZK 可行、TWDIW 方言已確認、BC 版本規則已定、DSS 不可直接上 Android。
- 新增風險：Multipaz OpenID4VP 請求驗證缺口（必修）；EUDI PID issuer 需 key attestation，軟體兜底金鑰無法通過 iso_18045_high；TWDIW core 依賴非 Central 套件庫。
- 仍待網路放行或實機才能驗證：Cloudflare UA、TWDIW 沙盒、公開 TSA、Android APK 與實機 NFC。

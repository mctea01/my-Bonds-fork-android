# 補驗結果：需要外部網路的項目（2026-10-10）

> **2026-10-10 歷史驗證結果。** 原始測試方法與結果不可直接套用於後續 PR #11。最新協定、簽署流程、CI 與授權邊界詳見 [2026-10-16 專案狀態](../status-2026-10-16.md)。

本檔補充 `validation-2026-10-10.md`（不覆寫）。在新雲端環境執行，網路放行後補驗先前被擋的項目，並建置 Android 實機測試 APK。
所有程式、原始回應與記錄在 `專案共用資料夾 validation/network/` 與 `專案共用資料夾 validation/android-smoke/`。
對正式政府主機只送出公開 GET 與一次無效參數的 POST（不使用 `moda_dw`、不帶任何真實資料）。

## 測試環境注意事項（影響結論解讀）

- 容器出口 IP 為美國資料中心（Cloudflare 節點 IAD），且所有 HTTPS 經過環境的 TLS 終結代理。
- 因此「Cloudflare 擋 UA」的結論只代表 User-Agent 這一層；源站看到的 TLS 指紋是代理的，不是 OkHttp 或 curl 的。TLS 指紋與台灣行動網路行為必須實機測（見 `device-test-checklist.md` 的 A3）。
- 容器沒有 `/dev/kvm`，無法跑 Android 模擬器；APK 只驗證到「可建置」，執行期行為留給實機。

## 總表

| 項目 | 結果 | 重點 |
|---|---|---|
| TWDIW 正式 API 可達性 | 通過 | frontend、issuer-oid4vci、issuer-vc、verifier-oid4vp 皆可取用公開端點 |
| Cloudflare UA 阻擋 | 本環境未重現 | 7 種 UA（含 curl、okhttp、Ktor、Dalvik、空白）回應完全相同；POST /token 到達應用層（11001），非 1010 |
| wallet.gov.tw 官網與 demo 站 | 被擋 | 不論 UA 皆為 Cloudflare「Sorry, you have been blocked」，推論為 IP 或地區規則 |
| TWDIW 沙盒 | 部分 | 前台可開；API 無 Access-Token 一律 401，需使用者註冊帳號 |
| TWDIW 方言對外部測試發行站 | 通過 | 自製 JVM 持有端對 issuer.mashbean.net 全流程（領卡、驗章、狀態清單、出示與負向測試）通過 |
| 公開 RFC 3161 TSA | 通過 | 10 家 Granted；以系統根憑證驗證 7 家 OK，Apple、Microsoft、FreeTSA 需另加信任錨 |
| 台灣 TSA | 無法測 | TWCA、HiNet 等無公開 RFC 3161 端點可達 |
| eudiw.dev 發行端 | 通過（僅 metadata） | 27 種憑證，全部要求 key attestation（iso_18045_high），不支援 pre-authorized code |
| eudiw.dev 驗證端 | 通過 | 新版要求 registration certificate；EUDI 錢包函式庫以嚴格 PKIX 解析成功 |
| OIDF certification.openid.net | 仍被擋 | 代理回 502 |
| Android APK 建置 | 通過 | KMP + Compose Multiplatform，debug 67.7 MB、release（R8）25.9 MB |
| Android 執行期 | 未驗 | 無 KVM，改由實機測試 APK 驗證 |
| 桌面兜底（Linux JVM） | 通過 | 同一份共用程式碼無頭執行 6 項全過 |

## 一、TWDIW

### 1.1 正式端點與 UA（`validation/network/probe-ua.txt`）

- `frontend.wallet.gov.tw/api/did?orgType=1&status=1`：200，發行端 23 個；`orgType=2`（驗證端）27 個。存檔 `twdiw-did-orgType1.json`、`twdiw-did-orgType2.json`。
- `issuer-oid4vci.wallet.gov.tw/api/issuer/00000000/.well-known/openid-credential-issuer`：200，894 個 configuration，`format: jwt_vc_json`、`cryptographic_binding_methods_supported: ["jwk"]`、ES256。存檔 `twdiw-00000000-metadata.json`。
  - **確認先前推論**：metadata 的 `credential_issuer` 為 `https://issuer-oid4vci.wallet.gov.tw/api/issuer/00000000`，沒有結尾斜線，而 offer 與 proof `aud` 要求有斜線。錢包必須寬鬆比對。
  - 根路徑插入式 well-known（`/.well-known/openid-credential-issuer/api/issuer/00000000/`）回 404，只支援附加式路徑。
- `issuer-oid4vci.../token`（無效 code、client_id=diw-probe）：所有 UA 皆 400 `{"resp_code":11001,"error":"invalid_request","resp_message":"...missing parameter : authorization_details"}`，代表已到達應用層。
- `issuer-vc.wallet.gov.tw/api/keys`：200，兩把 P-256（key-1、key-2）。存檔 `twdiw-issuer-vc-keys.json`。
- `verifier-oid4vp.wallet.gov.tw/api/oidvp/request/<無效>`：404 `{"code":4002,"message":"request session is not exist"}`。
- `www.wallet.gov.tw`、`wallet.gov.tw`、`demo.wallet.gov.tw`：403 Cloudflare 封鎖頁（cf-ray 為 IAD），7 種 UA 皆同。
- `issuer-moica.wallet.gov.tw`、`issuer.wallet.gov.tw`：代理 CONNECT 502（推論為主機不存在或不對外）。

**結論**：在本環境，API 主機沒有 UA 阻擋；Bonds 記錄的 1010 可能來自 TLS 指紋、IP 信譽或已調整的規則。Android 端仍須在台灣網路、以 OkHttp 與 HttpURLConnection 的真實 TLS 堆疊實測（APK 內 A3 會自動判定 BLOCKED_1010 或 BLOCKED_WAF）。

### 1.2 DID 註冊資料結構（新發現）

每筆資料欄位：`id`（did:key，0xEB51 jwk_jcs-pub）、`did`（JWS）、`orgType`、`org`（`x509_type` 為 XCA 或 MOEACA、`x509_subject`、`x509_serial`、`taxId`、`serviceBaseURL` 形如 `https://<統編>.wallet.gov.tw`、`name`、`name_en`）、`status`、`onChainHistory`。

- `did` 欄位的 JWS 標頭 `jwk` 就是 DID 自己的金鑰，屬自簽，只證明持有私鑰。
- 與政府 PKI 的關聯只有宣告的 `x509_serial` 與 `x509_subject`，JWS 本身沒有憑證鏈。
- 【推論】錢包可依序號到 XCA/MOEACA 儲存庫取得機關憑證比對，作為「驗證者身分證據」的加強；這是可選實作，非標準。

### 1.3 沙盒

- `issuer-sandbox.wallet.gov.tw`、`verifier-sandbox.wallet.gov.tw` 前台可開（Vue 打包，含 LoginPage、ActivatePage、DIDregister）。
- `/api/qrcode/data`、`/api/credential/nonce/*`、`/api/oidvp/qrcode`、`/api/oidvp/result` 無 Access-Token 一律 401 `"UNAUTHORIZED"`，UA 不影響。
- 要完成沙盒端到端，需使用者在沙盒註冊帳號並取得 Access-Token（見清單 N1）。

### 1.4 對外部測試發行站的端到端（`validation/network/twdiw-live/`）

- 對象：`issuer.mashbean.net`（twdiw-vc-issuer-lite 公開部署，使用虛構資料）。
- 使用先前的 JVM 持有端，只改兩行允許此主機並走系統代理（`holder-online.patch`）。
- 結果：官方 JWK 順序與 JCS 排序 did:key 都領卡成功；驗章（iss did:key）、cnf 綁定、8 個揭露、StatusList2021 撤銷位元皆通過；對內嵌驗證端出示 `verified`，錯 aud、錯 nonce、非 cnf 金鑰、扁平 submission 皆被拒。
- 負向測試顯示此站很寬鬆（接受非 moda_dw 的 client_id、jwk header 等），與先前本地觀察一致，不能用它確認官方 core 的 11007/11016 行為。

## 二、RFC 3161 時戳（`validation/network/tsa/`）

| TSA | 端點 | 結果 | 系統根憑證驗證 |
|---|---|---|---|
| DigiCert | http://timestamp.digicert.com | Granted | OK |
| Sectigo | https://timestamp.sectigo.com | Granted | OK |
| Entrust（實際由 Sectigo 簽） | http://timestamp.entrust.net/TSS/RFC3161sha2TS | Granted | OK |
| GlobalSign | http://timestamp.globalsign.com/tsa/r6advanced1 | Granted | OK |
| Certum | http://time.certum.pl | Granted | OK |
| SSL.com | http://ts.ssl.com | Granted | OK |
| IdenTrust | http://timestamp.identrust.com | Granted | OK |
| Apple | http://timestamp.apple.com/ts01 | Granted | 失敗：Apple Root CA 不在系統庫 |
| Microsoft | http://timestamp.acs.microsoft.com | Granted | 失敗：Microsoft Identity Verification Root 2020 不在系統庫 |
| FreeTSA | https://freetsa.org/tsr | Granted | 系統庫失敗；以其自簽根為錨則 OK |

- 竄改資料後驗證得 `message imprint mismatch`，偵測正常。
- Java/BC 路徑（APK 與桌面共用的 C6）對 DigiCert、Sectigo 皆通過，imprint 正確。
- 台灣：`tsa.twca.com.tw`、`timestamp.twca.com.tw`、`tsa.hinet.net` 無法解析或連線，`timestamp.hinet.net` 只回 HTML。【推論】國內 TSA 多為簽約服務，需申請帳號後再測。
- **對規劃的影響**：TSA 信任需獨立分區，不能直接用 TLS 系統根憑證庫；Apple、Microsoft 等根需內建或可選加入。

## 三、eudiw.dev（`validation/network/eudiw/`）

### 3.1 PID Issuer（issuer.eudiw.dev）

- 27 種 configuration：mso_mdoc 16、dc+sd-jwt 11（PID、mDL、EHIC、PDA1、IBAN、photoid 等）。
- **每一種都要求** `key_attestations_required: {key_storage: [iso_18045_high], user_authentication: [iso_18045_high]}`，proof 只收 ES256。
- `batch_credential_issuance.batch_size=100`、有 `nonce_endpoint`、`deferred_credential_endpoint`、`notification_endpoint`；請求與回應加密皆為可選。
- `issuer_info` 帶 `registration_cert`（typ `rc-wrp+jwt`）。
- AS：`authorization_code`、`implicit`、`jwt-bearer`、`refresh_token`，**沒有 pre-authorized code**；token 端驗證為 `public` 或 `attest_jwt_client_auth`。
- 結論與本地相同：純軟體兜底金鑰拿不到 EUDI PID；Android 需硬體金鑰證明，且 OID4VCI 的 key attestation 是錢包提供者簽發的 JWT，等同要有錢包提供者後端（新增風險，見第六節）。

### 3.2 Verifier（verifier-backend.eudiw.dev）

- 新版 `POST /ui/presentations/v2` 若沒有 `registration_certificate` 或 `intended_use_id` 會回 `MissingRegistrationCertificate`；`GET /ui/intended-uses` 提供 `TEST-01`。
- 請求物件：ES256、`x5c` 只有 1 張葉憑證、`client_id=x509_hash:...`（自行計算雜湊相符）、`response_mode=direct_post.jwt`、`verifier_info=[{format:registration_cert}]`、授權 URI scheme 為 `haip-vp://`。
- 葉憑證 `CN=Web Verifier (PROD), O=NiScy, organizationIdentifier=LEIXG-...`，SAN `URI:https://verifier.eudiw.dev`，由 `PID Issuer CA 02`（EU）簽發；AIA 取得 CA 後 `openssl verify` OK，CRL 為當日更新。
- registration certificate 內容：`name`、`purpose[]`（多語）、`sub`（LEI）、`country`、`registry_uri`、`privacy_policy`、`policy_id`、`credentials[]`（允許請求的 claim 清單）。這正是「驗證者身分、代表身分、目的」可直接呈現的證據，且可比對「本次請求的 claim 是否在登記範圍內」。
- 錢包端：`eudi-lib-jvm-openid4vp-kt 0.16.2` 對線上請求 GET 與 POST（request_uri_method）皆 `Resolution.Success`，**嚴格 PKIX 以 CA 02 為錨也通過**（本地範例憑證因中繼 CA:FALSE 失敗，線上正式鏈沒有此問題）。記錄 `wallet-probe-online.txt`。
- `dev.issuer.eudiw.dev` 回 502；`certification.openid.net` 仍被代理擋，OIDF 線上一致性測試未能執行（本地自建版本已在前次驗證可用）。

## 四、Android APK 建置（`validation/android-smoke/`）

- 工具鏈：Android cmdline-tools 13114758、platform 36、build-tools 36.0.0（從 dl.google.com 下載成功）、AGP 8.13.0、Gradle 8.14.3、Kotlin 2.2.21、Compose Multiplatform 1.9.0、JDK 21、minSdk 28、targetSdk 36。
- 結構：單一 KMP 模組 `composeApp`，`commonMain`（CMP UI）→ `jvmCommonMain`（Multipaz 與 BC 共用檢查，Android 與桌面共用）→ `androidMain`、`desktopMain`。
- 產物：`apk/diw-smoke-0.1.0-debug.apk`（67.7 MB）、`apk/diw-smoke-0.1.0-release.apk`（25.9 MB，R8 縮減，以 debug key 簽章供側載），雜湊見 `apk/SHA256SUMS.txt`。
- 發現：
  1. Multipaz 0.101.0 的 `multipaz`、`multipaz-longfellow`、`multipaz-compose`、`multipaz-dcapi` 都有 android 版；`multipaz-doctypes` 沒有 android 版，Android 編譯取用其 JVM 版成功。
  2. Longfellow 的 `libzkp.so` 只有 arm64-v8a 與 x86_64，**32 位元 ARM 裝置無法使用 ZK**，需降級處理。
  3. ofdrw 經 dom4j 帶入 `xpp3`、`pull-parser`，其 `org.xmlpull` 與 Android 框架衝突，R8 直接失敗；排除這兩個依賴後通過。
  4. R8 缺類別報告（`logs/r8-missing-classes.txt`，33 筆）：
     - ofdrw-reader 的 `ImageUtils`、`KeywordExtractor`、`ResourceManage.getImage` 與 pdfbox-jbig2 依賴 `java.awt`、`javax.imageio`；簽章與驗章路徑不經過這些類別。
     - dss-cades 的驗證端需要 `dss-validation` 與 JAXB 診斷資料（未納入，符合前次結論：Android 端只用 DSS 的 CMS/CAdES 簽章模組）。
     - commons-compress 的 zstd 為可選。
  5. 執行期是否真的可用（DSS CAdESService 實例化、GB/T 38540 印章解析、Keystore、生物辨識、NFC、網路）由 APK 內的 A1 至 A4、M1、M2 在實機判定。
- 桌面兜底：同一份程式碼打包為 Linux 桌面程式，`--headless` 執行 C1 至 C6 全過（`logs/desktop-headless-linux.log`）。Longfellow 證明約 1.4 至 1.5 秒、驗證約 0.7 秒、證明約 360 KB；完整樣本 mDL 仍因 MSO 過大失敗，與前次一致。

## 五、仍未完成的項目

| 項目 | 原因 | 下一步 |
|---|---|---|
| TWDIW 沙盒端到端 | 需要沙盒帳號與 Access-Token | 使用者註冊後提供 token（清單 N1） |
| Cloudflare TLS 指紋、台灣網路 | 雲端出口與代理不具代表性 | 實機 A3 |
| wallet.gov.tw 官網、demo 反向 QR 站 | 雲端 IP 被 WAF 擋 | 實機或台灣網路瀏覽器測試 |
| 台灣 TSA | 無公開端點 | 取得 TWCA 等簽約帳號後再測 |
| OIDF 線上一致性測試 | certification.openid.net 仍被擋 | 放行該網域，或沿用本地自建版本 |
| Android 執行期、NFC、生物辨識、近場出示、DC API | 無 KVM、無硬體 | `device-test-checklist.md` |

## 六、建議納入規劃文件的變更（由規劃串決定是否採納）

1. 風險「Cloudflare UA 阻擋」改為「TLS 指紋或 IP 信譽阻擋，UA 層未重現」，仍列為 Android 首要實機驗證。
2. TWDIW profile 補充：metadata `credential_issuer` 無結尾斜線已確認；well-known 只支援附加式路徑。
3. 新增「驗證者身分證據」來源：EUDI registration certificate（`rc-wrp+jwt`，含 purpose 與允許 claim 清單）與 TWDIW DID 註冊的 x509 序號；UI 應比對請求 claim 是否超出登記範圍。
4. 新增風險：EUDI 發行端要求錢包提供者簽發的 key attestation，需規劃錢包提供者後端（Android Key Attestation 與 Play Integrity 作為輸入）。
5. 新增限制：Longfellow ZK 不支援 32 位元 ARM，該類裝置的 ZK 功能需標示降級。
6. 建置規則：ofdrw 在 Android 須排除 xpp3 與 pull-parser；Android 端不引入 ofdrw-reader 的影像與關鍵字功能。
7. TSA 信任需獨立分區並可加入 Apple、Microsoft 等不在系統庫的根憑證。
8. 實機測試以 `validation/android-smoke` 測試 APK 為基準，正式 App 的同類測試可沿用其檢查項。

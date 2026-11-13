# TWDIW 裝置金鑰註冊查證（2026-11-02）

## 範圍與結論

最新結論（附件 AOT 查證）：已還原並實測成功的生態系 nonce URL 為 `https://moda.wallet.gov.tw/oid4vci/api/ext/nonce/generate?type=ecosyst`。現行 `defaultEcosystemBase` 丟掉 `/oid4vci`，因此 nonce URL 的主機正確、服務前綴錯誤。附件 Dart 中 `api/did` 與 `api/did/` 的引用分別是發行者清單及單一發行者狀態查詢，未支持目前的裝置註冊 POST。生態系簽章經 `did_sdk_channel` 的原生方法 `dwapp-201i` 取得；獨立手機註冊契約仍未知。以下早期唯讀量測與假說保留作對照，以本段及「商店版 AOT 呼叫鏈」為最新結論。

APK 最新結論：已離線還原 `a-`、`b-` 兩層封裝，找到 Android SDK 實作 `o.N3Kf59pP`。`dwapp-201i` 簽章路徑呼叫的 PrivateKey getter 會讀取 `assets/dwapp201i_private.txt`，經串流解碼、Base64 與 PKCS#8 匯入 EC 私鑰，再以 `SHA256withECDSA` 簽署。這是實際呼叫鏈證據，不支持將這條路徑描述為「先產生手機硬體金鑰，再向 `/api/did/` 註冊」。後續符號模型已追到成功路徑：appHash 是 Context.getPackageName 的原始字串，keyId 是公鑰資產通過兩層 reader 後之正規化 UTF-8 文字的 SHA-256 小寫 hex；具體值見下述附件追加核對。appPlatform 明文、其他保護分支與第三方應用准入仍未驗收。

native 模擬最新進度：本輪經使用者要求於雲端執行，unidbg 已成功執行 `libd186.so` 的 `JNI_OnLoad`，取得 98 筆註冊，並核對四個 helper 的方法、位址及回傳值；依實際 native 回傳值還原 appPlatform 為 **`Android`**。這項常數由候選升為 native_emulation_verified；其他保護分支、完整 App 執行與官方第三方准入沒有因此獲得驗收。詳細紀錄與精簡重現包見 [native helper 雲端模擬驗證](twdiw-native-helper-emulation.md)。

同一份還原 DEX 的 `o.G91c5eRH` 明列 `https://frontend.wallet.gov.tw/api/moda/dwapp/` 下的 `apply/vcList`、`offline/vpList`、`serviceUrl/`、`vc/realNameVerification/`。frontend 確實承載 App 的部分 API，但這些不是已確認的手機註冊端點。後續取得 27 個分割 APK，全部通過 v3 簽章驗證，其簽章指紋與官方 frontend 的 assetlinks 公布值一致；分析涉及的 DEX、Dart、SDK 封裝與資產和先前合併包相同，已將上述靜態證據核對到官方簽署的檔案。先前合併包的執行時完整性限制仍須與這份分割包區分。分析未執行 APK、未取出或重用官方私鑰、未發出註冊 POST。

本次在 `claude/p4-zkp-design-fmkasd`（起點 `3bdaf15`）查閱現有實作、官方公開原始碼與公開端點。官方來源固定在 `moda-gov-tw/TWDIW-official-app` 的 `99e9deb105b6bbd7d3bc103ab68d0417eb7e5767`，其 Android `app/build.gradle.kts` 的公開版本為 `1.0.0+20251117_01`；不能視為上架 1.0.14 的完整來源。

**尚未確認官方手機裝置金鑰的註冊 URL、HTTP 方法、請求欄位、金鑰證明要求與回應契約。現有 `TwdiwDeviceKeys` 是推斷格式的實作，不能視為已完成官方註冊互通。**

來源補充（使用者 2026-11-02 澄清）：生態系相關發現來自 Play 商店版的 Dart 層，並非舊公開 SDK；目前仍找不到 endpoints。本工作環境未找到該商店版 APK、libapp.so 或 Dart 分析輸出，只有本次從舊公開 repo 提取的 libapp.so。因此，下文公開碼的查證只用於描述舊版、辨識機構 API 與提供對照，不能否定商店版的新機制，也不能用舊版預設 HTTP 行為解釋商店版實測。

後續附件：使用者已提供商店版 `libapp.so`，取代上段「未取得商店版產物」的工作環境狀態。檔案為 Android arm64 ELF，SHA-256 為 `abd024e694bcdcd52a685e2e00a72a890af583c46785b4b89c1da128d3af3efa`，Dart snapshot hash 為 `78da37fed6bf1489361a312568249f3f`。已確認內含 `Twdiw-Signature`、`api/ext/nonce/generate?type=ecosyst`、`api/did`、`api/did/`、`getNonce` 與 `frontUrl`。這些字串的存在不等於已確認註冊呼叫鏈或正式主機；需進一步檢查 AOT 方法與常數引用。附件與完整分析輸出保留在工作環境，不提交進 repo。

後續應以商店版簽章函式與 keyId 來源的資料流為主：先確認是否確實存在 HTTP 註冊呼叫，再追 URL 的 base/path 組合、設定或先前回應的來源；若 Dart 交給 MethodChannel，則追原生端的實際處理。僅有 keyId、金鑰前綴或簽章 payload，不能證明 keyId 必由註冊伺服器核發；`api/did` 字串也需呼叫鏈證明與裝置註冊相關，不能因名稱而串接成同一流程。

本次未變更領卡、金鑰或 UI 行為，也未向官方送出註冊 POST。下列證據修正 `review-followups.md` 中「500/11021 可能是未註冊金鑰」及直接套用 `api/did` 的舊推論。

## 使用者實機線索

| 觀察 | 證據等級與限制 |
|---|---|
| 本錢包的 StrongBox 金鑰已建立，註冊顯示 HTTP 404 | 使用者截圖；證明本機建立成功與某次請求收到 404，截圖未包含完整請求 URL、方法與回應原文 |
| 官方 App 無法透過目前抓包方式解密，懷疑內建 root CA | 使用者實測與假說；尚未確認其 TLS 信任庫或憑證釘選機制 |
| 官方 App 有反逆向 | 使用者實測回報；未取得版本、觸發條件與診斷紀錄，本次未重現或繞過 |
| 官方 App 啟動時會嘗試連線電信卡的 OID4VCI service | 使用者實測回報；完整主機、路徑、方法與當時是否已有卡片待補。不能直接推定是裝置註冊 |

## 公開來源能確認的規則

### 1. 機構 DID 註冊與手機裝置註冊不能混用

官方 `twdiw-vc-handler` 的 `IssuerDidResource.register` 提供 `POST /api/did`，請求 DTO 是 `IssuerDidRequestDTO`，欄位為 `org` 與 `p7data`；驗證至少要求非空的 `org`。

`IssuerDidService.register` 在伺服器產生 P-256 金鑰（`kid = key-1`），取得設定中的 frontend access token，再呼叫 frontend 產生 DID、簽署 DID 文件並建立機構資料。這不是接收手機提供的 JWK、Android attestation、nonce 後回傳手機 keyId 的流程。另一個 `DidRegisterRequestDTO` 也使用 `did`、`org`、`orgType`，屬機構登錄資料。

因此，公開來源中出現 `api/did` 字串，不能支持「向每個發證端 origin 的 `/api/did/` 註冊手機金鑰」。不同服務的同名路徑也不代表相同契約。

來源：

- [IssuerDidResource.java](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/core-system/twdiw-vc-handler/src/main/java/gov/moda/dw/issuer/vc/web/rest/IssuerDidResource.java)
- [IssuerDidRequestDTO.java](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/core-system/twdiw-vc-handler/src/main/java/gov/moda/dw/issuer/vc/service/dto/IssuerDidRequestDTO.java)
- [IssuerDidService.java](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/core-system/twdiw-vc-handler/src/main/java/gov/moda/dw/issuer/vc/service/IssuerDidService.java)

### 2. 持有者 did:key 可在本機產生

官方公開 `APP/APPSDK/lib/did_key_gen.dart` 的 `generateDID` 以輸入的公鑰 JWK 在本機產生 did:key 與 DID document，函式沒有 HTTP 註冊。這只說明公開版持有者 DID 的建立方式，不能排除上架新版另外存在生態系裝置註冊。

來源：[did_key_gen.dart](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/APP/APPSDK/lib/did_key_gen.dart)

### 3. 抓包失敗不足以證明內建 root CA

公開 Android `network_security_config.xml` 的 base trust anchors 只有 `src="system"`，沒有 `src="user"` 或自訂 raw 憑證，也沒有 XML pin-set。Manifest 指向此設定。因此，只把抓包 CA 安裝到使用者憑證庫，仍可能被拒，無須存在內建私有 root CA 或憑證釘選。

`VerifiableManagerImpl.getImageBase64` 另外使用 AndroidCAStore 與 TrustManagerFactory；它是圖片下載路徑，不代表 Flutter SDK 的領卡 HTTP 用相同 TLS 實作。本次在公開 Android Kotlin/Java/XML 未找到 CertificatePinner、checkServerTrusted 或 isDebuggerConnected 等相關名稱，搜尋未命中不能排除原生二進位、保護層或上架新版的實作。

公開 `ModaKeyStoreManagerImpl` 的 StrongBox 邏輯管理 AES-256-GCM 本機祕密金鑰，不能用它證明生態系簽章金鑰必定採 StrongBox、TEE、軟體的相同順序。

來源：

- [network_security_config.xml](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/APP/moda-digitalwallet-holder-androidapp/app/src/main/res/xml/network_security_config.xml)
- [VerifiableManagerImpl.kt](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/APP/moda-digitalwallet-holder-androidapp/app/src/main/java/tw/gov/moda/digitalwallet/core/verifiable/VerifiableManagerImpl.kt)
- [ModaKeyStoreManagerImpl.kt](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/APP/moda-digitalwallet-holder-androidapp/app/src/main/java/tw/gov/moda/digitalwallet/core/keystore/ModaKeyStoreManagerImpl.kt)

### 4. 11021 不是裝置註冊專用錯誤碼

公開 `twdiw-oid4vci-handler` 的 `ErrorCodeConfiguration` 將 11021 定義為 `VC Server error`；`HTTPService` 呼叫上游 VC 服務時，捕捉到 HTTP 500 或其他 5xx 都可能轉成 11021。未註冊金鑰只是許多可能原因之一，需上游錯誤或官方契約才能定因。

來源：

- [ErrorCodeConfiguration.java](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/core-system/twdiw-oid4vci-handler/src/main/java/gov/moda/dw/issuer/oidvci/config/ErrorCodeConfiguration.java)
- [HTTPService.java](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/core-system/twdiw-oid4vci-handler/src/main/java/gov/moda/dw/issuer/oidvci/service/HTTPService.java)

### 5. 公開碼與二進位的查證邊界

本次搜尋公開 Android/iOS App 原始碼、APPSDK Dart、core-system Java 與設定，未找到 `Twdiw-Signature`、`ecosyst`、`appHash`、`keyPrefix` 的生態系實作。另檢查官方 repo 內公開 `flutter_release-1.0.aar` 的 arm64 `libapp.so` ASCII 字串，只命中 `/api/did/` 與 `/api/did?size=`，未命中其餘生態系名稱。字串檢查不等於完整控制流程分析；這個公開 AAR 也不能代表實測的上架 App。

## 公開端點唯讀量測

時間：2026-11-02 12:42 UTC，使用工作環境的 HTTPS 代理、保持 TLS 驗證，`User-Agent: Mozilla/5.0`、`Accept: application/json`。以下全部是 GET，未傳入權杖、持有者資料或裝置證明。

| URL | 結果 |
|---|---|
| `https://moda.wallet.gov.tw/api/did/` | 404，text/plain，`404 page not found` |
| `https://moda.wallet.gov.tw/api/did` | 同上 |
| `https://moda.wallet.gov.tw/api/ext/nonce/generate?type=ecosyst` | 同上 |
| `https://frontend-uat.wallet.gov.tw/api/did?size=1&page=0&orgType=1&status=1` | 200 JSON，`code="0"`，data 有 count、dids |
| `https://97179430.wallet.gov.tw/oid4vci/api/issuer/97179430/.well-known/openid-credential-issuer` | 200 JSON，有 credential_issuer、credential_endpoint、credential_configurations_supported；未列 nonce_endpoint |

這裡選遠傳為已知、可公開讀取的對照發證端，**不是認定使用者觀察到的主機就是遠傳**。GET 404 不能證明同路徑 POST 不存在，也不能判斷是路由、環境、來源條件或授權遮蔽；本次沒有重現截圖的註冊 POST。UAT 清單可讀取不代表 moda 的註冊也應改送 UAT frontend。

精簡量測 JSON 在本次工作環境 `/workspace/scratch/twdiw-registration-probes.json`，不包含完整機構資料、nonce 或憑證內容。另讀取 UAT frontend 根頁 `/` 得到 404，因此未能沿該頁取得 JavaScript 資產或註冊契約。

## 追加查證：是否位於 frontend（2026-11-02）

依使用者提出的主機假說，於 12:55 UTC 對正式 frontend 與 UAT frontend 比對已知路徑。保留 TLS 驗證，未送註冊 POST。

| 路徑與方法 | frontend.wallet.gov.tw | frontend-uat.wallet.gov.tw |
|---|---|---|
| GET `/api/did` | 200，`code="0"`，data 含 count、dids | 相同 |
| OPTIONS `/api/did` | 200，`Allow: GET,HEAD,OPTIONS` | 相同 |
| GET、OPTIONS `/api/did/` | 404，application/problem+json | 相同 |
| GET `/api/did/register` | 401，空回應 | 相同 |
| GET `/api/ext/nonce/generate?type=ecosyst` | 404，text/plain | 相同 |

OPTIONS `/api/did/` 的 detail 為 `No static resource api/did.`。這說明尾斜線在這些實測路由上有差異，但不能據此把現行 POST 改為 GET。

官方 [setting_release.csv](https://github.com/moda-gov-tw/TWDIW-official-app/blob/99e9deb105b6bbd7d3bc103ab68d0417eb7e5767/core-system/twdiw-vc-handler/src/main/resources/config/liquibase/data/setting_release.csv) 第 20–24 行設定 frontend 的 `/api/did/generate`、`/api/did/register`、`/api/did/review`、`/api/did/`（查詢前綴）與 `/api/did/create`。`IssuerDidService.callFrontendToRegisterDid` 以 `Access-Token` 標頭送出機構 DTO；這是機構服務端的註冊流程，不能將其權杖或契約移用到手機。GET 401 本身也不能證明特定 controller 存在，因為授權層可先攔截。

結論：frontend 確實承載公開 DID 查詢及官方設定中的機構登錄服務，因此是合理的調查方向；目前尚無證據確認手機裝置註冊也在此。僅將 `registrationBase` 改成 frontend，仍會 POST 到尾斜線路徑，且 nonce URL 仍回 404，不能當成已驗證的修正。GET 精簡紀錄在 `/workspace/scratch/twdiw-frontend-probes.json`；OPTIONS 與 register GET 的結果如上表。

## 追加線索：目的 IP 104.18.10.20（2026-11-02）

使用者補充 `104.18.10.20`，本次暫按觀察到的目的 IP 處理。12:59 UTC 經 Cloudflare DNS-over-HTTPS 查詢 A 紀錄，`frontend.wallet.gov.tw`、`frontend-uat.wallet.gov.tw`、`moda.wallet.gov.tw`、`97179430.wallet.gov.tw` 與 `issuer-vc.wallet.gov.tw` 五個主機都同時回傳 `104.18.10.20`、`104.18.11.20`（TTL 300 秒）。這是當次解析快照，不保證其他時間或解析位置相同。

[ARIN RDAP](https://rdap.arin.net/registry/ip/104.18.10.20) 回報 `CLOUDFLARENET`，配置範圍 `104.16.0.0` 至 `104.31.255.255`。這個 IP 是 Cloudflare 共用入口，不能單獨辨識實際 origin，也不能區分上述 frontend、電信與憑證服務。若「連到電信服務」原本僅根據這個 IP 判斷，該主機歸屬仍待確認；不能據此排除 frontend。

下一步應取同一條連線的 TLS ClientHello SNI、代理 CONNECT 目的主機或可關聯的 DNS 查詢；這些資訊不需要先解密 HTTP 內容。若使用 ECH 或 DNS 快取使其不可見，目的 IP 本身仍不足以判定。量測精簡 JSON：`/workspace/scratch/twdiw-ip-104.18.10.20.json`。

## 追加線索：官方 App 似乎不接受 Proxy（2026-11-02）

使用者回報官方 App 似乎不接受 Proxy，目前尚未區分「未使用系統代理」、「經代理但 TLS 驗證失敗」與「偵測代理後拒絕運作」。

公開 `APP/APPSDK/lib/http_service.dart` 以 `package:http/http.dart` 的頂層 get/post 執行領卡 HTTP；本次搜尋公開 Dart 與 Android/iOS App 原始碼，未找到 findProxy、HttpOverrides 或明確 Proxy 設定。Dart [HttpClient.findProxy](https://api.dart.dev/dart-io/HttpClient/findProxy.html) 文件說明未設定時直接連線；[findProxyFromEnvironment](https://api.dart.dev/dart-io/HttpClient/findProxyFromEnvironment.html) 需明確指定才會依環境變數解析代理。因此「Flutter/Dart 網路層沒有套用 Android Wi-Fi Proxy」是有依據的候選原因，尚不能直接認定上架版存在反代理偵測。公開版與上架版仍可能不同。

先以不解密 TLS 的方式觀察：代理有無收到 CONNECT、手機是否直接對目的 IP 的 443 連線、App 是否仍能正常連網。代理完全沒有連線且手機仍直連，比較符合未套用代理；收到 CONNECT 後才在 TLS 階段失敗，才進一步查 CA 信任或釘選。若只需辨識目的網域，可用能觀察直連流量的路由器或 VPN 型封包擷取查看 DNS 與 TLS SNI，不依賴 App 遵守 HTTP Proxy；SNI 受 ECH 限制，HTTP 路徑與註冊內容仍不可由此取得。

## 商店版 AOT 呼叫鏈（2026-11-02）

### 分析方式與限制

使用前述 SHA-256 的附件，未執行官方 App 或修改其保護機制。以 blutter 的 Dart 3.11.1 相容 runtime 載入 snapshot；snapshot hash 與該系列相符，但不能僅據此確認 App 使用的精確 Dart patch 版本或 App 版本。

原工具在 heap walk 及高階指令辨識遇到相容性問題；本次工具改從 `object_store.instructions_tables` 的 code_objects 收集 Code，使用 Capstone 原始反組譯，停用高階 pattern analyzer 與不需要的 IDA/Frida 匯出。常數池完整保留相鄰的 tagged entries，避免 UnlinkedCall 後的字串被略過。調整後靜態匯出程序退出碼為 0；下列結論依原始指令、常數與 HTTP 實測交叉核對，不依賴失敗的高階還原。

分析產物在 `/workspace/scratch/twdiw-play-blutter/`：`pp.txt`、`objs.txt`、`asm/did_sdk_module/`、`annotated/`、`functions.json`。輔助標註腳本在 `/workspace/scratch/annotate_twdiw.py`。附件與完整反組譯不收入 repo。

### 1. nonce 端點保留發證服務前綴

`VcOperations.applyVCKx`（入口 `0x2ea564`）在 `0x2eb8cc` 讀取 `applyVCUrl`，將其字串以 `/api/` 分割，取第一段後，在 `0x2eb960` 呼叫 `HttpService.getNonce`（入口 `0x2c16f0`）。`getNonce` 在 `0x2c1724` 載入相對路徑 `api/ext/nonce/generate?type=ecosyst`，經 `_buildApiUri`（`0x2bb2a4`）建構 URI，再於 `0x2c1768` 呼叫 HTTP GET。

`_buildApiUri` 會確保 base 有尾斜線、移除相對路徑開頭的斜線，並解析相對 URI；不會把 base 截成只有 origin。可將已觀察到的行為概括為：

```text
issuer:     https://moda.wallet.gov.tw/oid4vci/api/issuer/<id>/
base:       https://moda.wallet.gov.tw/oid4vci
nonce URL:  https://moda.wallet.gov.tw/oid4vci/api/ext/nonce/generate?type=ecosyst
```

上例 `<id>` 是路徑佔位，沒有使用真實領卡 offer 或 pre-authorized code。

唯讀實測（本次工作環境，TLS 驗證開啟，不保存 nonce 值）：

| URL | 結果 |
|---|---|
| `https://moda.wallet.gov.tw/oid4vci/api/ext/nonce/generate?type=ecosyst` | HTTP 200 JSON，`code="0"`，data 有 nonce 字串 |
| `https://97179430.wallet.gov.tw/oid4vci/api/ext/nonce/generate?type=ecosyst` | HTTP 404，application/problem+json |

正式 moda 的 200 證實服務前綴的重要性；不代表所有發證端都支援同一擴充。精簡量測在 `/workspace/scratch/twdiw-prefixed-nonce-probes.json`。現行 `TwdiwDialect.defaultEcosystemBase` 只保留 scheme/authority，與此附件的領卡流程不同；先前的 origin 路徑 404 不能解讀為整個 nonce 服務不存在，也無須因此改送 frontend。

### 2. `api/did` 的 Dart 引用是發行者查詢

| 常數 | 方法及引用位址 | 行為 |
|---|---|---|
| `api/did` | `HttpService.getVCIssList`（`0x2be640`），常數引用 `0x2be6ec` | 組 size、page、orgType、status 查詢參數後 GET 發行者清單 |
| `api/did/` | `HttpService.getVCIssStatus`（`0x2de338`），常數引用 `0x2de374` | 附加傳入 DID，於 `0x2de3d8` 呼叫 HTTP GET |

因此，這兩個字串在此附件中的已追蹤呼叫鏈不是手機裝置註冊。這比舊公開碼的對照更直接；仍不能排除原生端有另一個未出現在 Dart 的註冊流程。

### 3. 簽章是原生 MethodChannel 回傳值

領卡流程先組 credential request body，在 `0x2eb9b8` JSON encode、`0x2eb9c8` 做 UTF-8 SHA-256 雜湊。接著組包含 `body`（該雜湊）、`timestamp`、`nonce` 的物件，再 JSON encode，於 `0x2ebba4` 呼叫 `Utils.callDwapp201i`（`0x2c143c`）。timestamp 路徑讀取 `_getCurrentMicros` 後除以 1000，再轉字串，對應毫秒時間。

`callDwapp201i` 在 `0x2c149c` 載入 MethodChannel 物件；`objs.txt` 將其辨識為 `did_sdk_channel`。`0x2c14a4` 載入 `dwapp-201i` 方法名稱，`0x2c14b4` 呼叫 `invokeMethod`，參數是前述 JSON 字串。它解析原生回應的 code/data，成功時取非空 data 字串。

`HttpService.getVC`（`0x2ec368`）在 `0x2ec45c` 放入 `Twdiw-Signature` 標頭，其值來自傳入的簽章字串。這條 Dart 路徑沒有自行組出現行 Kotlin 猜測的七欄 JWT，也沒有證明 `keyId` 由 `POST /api/did/` 核發。實際 JWT 結構、金鑰選擇、App 身分與可能的裝置註冊需追原生 `dwapp-201i` 實作。

### 4. 下一份產物應是同版本 APK 的原生端

優先在 `classes*.dex` 搜尋 `did_sdk_channel`、`dwapp-201i` 與 MethodCallHandler 註冊處，再追它呼叫的 SDK/JNI。若處理者交給原生程式庫，需同版 APK 內對應的 `.so`；`libapp.so` 是 Dart AOT 程式，不能單獨提供其他檔案裡的註冊 URL。此處是在辨識靜態呼叫邊界，沒有要求先繞過抓包或反逆向保護。

本輪只更新研究結果，未修改領卡程式或將原先猜測的裝置註冊 POST 改送其他端點。修正 nonce 的服務前綴可以解決此項 404，但不能保證官方接受本錢包目前產生的簽章；兩者需分開驗證。

## APK 1.0.14 追加查證（2026-11-02）

### 產物來源與完整性

來源為使用者提供的 [Drive 檔案](https://drive.google.com/file/d/1i5q12fgokn0HEWhUP-S5Lr-OrAtZWdtC/view)，檔名 `數位憑證皮夾_1.0.14_apks.apk`，大小 83,437,476 bytes。

- APK SHA-256：`860c204751b7c7e4f0609445bacc93aba3b31f204474b80ce1a7f1aad09ed737`。
- Manifest：`versionName=1.0.14`，package `tw.gov.moda.diw`。
- APK 內 arm64 `libapp.so` SHA-256 與先前附件完全相同。
- `apksigner verify` 通過 v3 簽章；簽署憑證 SHA-256 為 `dd7eab62593edb252a942e5898dfcf9104969e8970f66e59d920383e8be9bfb3`。不記錄憑證主體的個人姓名。
- 使用者確認曾合併或重新簽章，工具與具體操作未提供。因此這不是已驗證的 Play 原始簽署產物；版本與 Dart 一致不代表保護層、原簽章檢查或動態載入在原包與此樣本必然相同。

本次用 apkanalyzer、aapt2、dexdump 與 JADX 做靜態分析，未安裝或執行此 APK。未將檔案上傳第三方分析平台，也未修改 Drive 檔案或分享狀態。原始 APK 在 `/workspace/scratch/twdiw-play-1.0.14.apk`；解出的檔案與分析結果都只放 scratch。

### 七欄 JWT 模型有原生證據，註冊模型仍無

主 DEX 的 `o.IeeqwtWx` 包含 `dwapp-201i` 名稱與 Header/Payload/回應模型。其 `ebZ5jVfe` 類別有 `bodyHash`、`nonce`、`appHash`、`appVersion`、`appPlatform`、`timestamp`、`keyId` 七個字串欄位。這支持簽章 payload 的欄位結構，不足以確認 appHash 的計算方式、keyId 來源、金鑰生命週期或手機註冊協議。

特別需要修正的是 `o.mNiI8S`：它保存 annotations、entries、primaryKeyId，內部 entry 的 toString 為 `(status=%s, keyId=%s, keyType='%s', keyPrefix='%s')`，keyId 為整數。此結構、建構參數與字串格式可與 Tink 1.9.0 的 `com.google.crypto.tink.monitoring.MonitoringKeysetInfo` 來源逐項對照。這是通用密碼學程式庫的監控資訊，不能用來推導 TWDIW 的手機註冊欄位，更不能因 APK 同時出現 `android-keystore://` 就把它當成生態系註冊 keyPrefix。

對照來源：[Tink Android 1.9.0 sources JAR](https://repo.maven.apache.org/maven2/com/google/crypto/tink/tink-android/1.9.0/tink-android-1.9.0-sources.jar) 中的 `com/google/crypto/tink/monitoring/MonitoringKeysetInfo.java`；[Builder API](https://javadoc.io/static/com.google.crypto.tink/tink-android/1.9.0/com/google/crypto/tink/monitoring/MonitoringKeysetInfo.Builder.html)。此對照用於辨識結構來源，不宣稱已精確辨識 APK 內所有 Tink 元件的版本。

### 金鑰資產與硬體簽章須分開追蹤

APK 有以下資產名稱與長度：

| 資產 | bytes |
|---|---:|
| `assets/dwapp201i_private` | 96 |
| `assets/dwapp201i_private.txt` | 192 |
| `assets/dwapp201i_public` | 128 |
| `assets/dwapp201i_public.txt` | 128 |

它們是二進位內容，並非依檔名即可解讀的文字金鑰。本次未證實格式、是否加密、讀取者或是否用於實際生態系簽章；沒有輸出其內容，也沒有取出或重用其中的金鑰。這些名稱是靜態線索，不能直接宣布「官方以內建共用私鑰簽章」。

另一方面，`o.a9rRVSe7` 的建構流程明確建立 `com.flutter_method_channel/gov.moda.dw` Channel，交由 `o.BV9TyT73.onMethodCall` 轉入處理，並依賴 `o.uiW5atgU`；後者能以 Android Keystore 的 PrivateKeyEntry 做 SHA256withECDSA。這是另一個已可見的簽章路徑，不能在未追到呼叫鏈前，當成 Dart `did_sdk_channel / dwapp-201i` 的實作或其註冊方式。

### 原生呼叫邊界：還原前的定位

`ApplicationModule.Qv6H7VWA(Context, skxIpHfX, MethodChannel, QApoG8vD, gW0nMvAr)` 透過 `iA8xfKSu` 解析反射建構子，建立回傳型別 `IRLfSEKL` 的橋接服務。`iA8xfKSu` 保存獨立 ClassLoader 物件 `CZJ2BzPW` 與分派物件 `dDAKKSRt`，其解析方法使用該 ClassLoader 做 Class.forName、取得 Method/Constructor 並呼叫。主 DEX 未找到直接宣告 implements IRLfSEKL 的類別。

APK 另有 `a-`（18,849 bytes）、`b-`（1,238,093 bytes）及多個非語意命名的原生程式庫。在還原載入器前，僅靠檔名不能確認其格式。主 DEX 的 JADX simple 匯出有 160 個還原錯誤；涉及重要方法時需以原始 DEX 指令交叉核對，不能把未輸出的類別或失敗的方法當成不存在。

下節以純離線還原進一步跨過此 ClassLoader 邊界。樣本的重簽狀態會影響執行時完整性檢查，但不需要先讓使用者抓包或成功啟動修改包，才能分析其中的程式。

### 離線解開封裝後的簽章與服務網址

載入器分析及還原腳本保留於 scratch：`twdiw_decode_loader.py`、`twdiw_unpack_loader.py`、`twdiw_unpack_b.py`。未呼叫 APK 的 Application、ClassLoader 或 JNI 執行程式碼；由 Python 依檔案格式還原封裝，辨識 20-byte 前綴後的 ZIP，解出 DEX。

| 來源 | 還原結果 | DEX bytes | DEX SHA-256 |
|---|---|---:|---|
| `a-` | `o.mUHNhY6P` ClassLoader／反射橋接 | 29,472 | `8396559fb6a2fec5d98c23f23c14cd4959e3fd8f562fdb4e2329c52580249c77` |
| `b-` | 包含 `o.N3Kf59pP`、`o.G91c5eRH` 的 SDK | 2,263,872 | `4bac5eefe40ec027a39b9f8e38261d1cec34edd41c110fda1815c84538ed0e2d` |

`b-` 的 JADX simple 匯出完成，有 18 個還原錯誤，另產生原始 DEX 反組譯交叉核對。產物為 `/workspace/scratch/twdiw-b-stage/classes.dex`、`/workspace/scratch/twdiw-b-jadx/sources`、`/workspace/scratch/twdiw-b-dexdump.txt`。混淆程式仍有控制流程平坦化、反射與虛擬指令分派；可辨識個別呼叫不代表已還原所有分支。

簽章呼叫鏈：

1. `N3Kf59pP implements IRLfSEKL`，MethodChannel 接收者 `o.cjG00Evx` 保存該服務。`N3Kf59pP.YdPt6BuV` 比對 MethodCall 名稱與 `IeeqwtWx` 的 `dwapp-201i` 名稱，轉入對應處理。
2. `N3Kf59pP.mbkki7b3` 的簽章處理反序列化 `IeeqwtWx.mbkki7b3` 請求，讀取 body、nonce、timestamp，建立 ES256/JWT Header 與七欄 Payload；版本字串為 `1.0.14`。
3. 處理方法呼叫 `N3Kf59pP.ISyARpnL(service)` 取得 PrivateKey。還原 DEX 的呼叫指令位於 file offset `0x0b2a5c`；其 getter 進一步呼叫 `QB1mryx(): PrivateKey`，指令位於 `0x0e0e40`。分派器對應 `wUkgW2wl(Object[])` 與 `zAKsgAGv(Object[])`。
4. `zAKsgAGv` 使用 Context.getAssets；檔名字串解碼器的有效參數為 `(17, 3, -1)`，結果是 `dwapp201i_private.txt`。接著以串流解碼、移除空白及 Base64 解碼建立 `PKCS8EncodedKeySpec`，由 `KeyFactory("EC").generatePrivate` 匯入。沒有執行這個私鑰解碼流程或輸出私鑰內容。
5. 簽章處理中的反射字串已獨立靜態解碼為 `java.security.Signature`、`getInstance`、`initSign`、`java.security.PrivateKey`、`update`、`sign`；演算法字串為 `SHA256withECDSA`。這與前述 PrivateKey getter 位於同一處理方法。

另有 `Qv6H7VWA(): String` 讀取 `dwapp201i_public.txt`、移除空白，再經字串 UTF-8 SHA 雜湊 helper；簽章處理也引用該 helper 與 Context.getPackageName。這些值如何各自填入 appHash／keyId，仍需還原虛擬分派中的完整值流，不能僅按名稱猜測。此輪沒有取出公私鑰資產的解碼內容。

可核對的 Android SDK 匯出位置：`N3Kf59pP.java` 約 21,466 行（方法名稱比對）、25,308–25,469 行（請求與 Payload）、25,513–25,618 行（PrivateKey 與簽章）、45,273 行（分派器）、47,717 行（PrivateKey getter 呼叫）、49,803–50,113 行（資產與 PKCS#8）、50,116 行（另一資產 reader）。行號是本次 scratch 匯出，重新使用不同 JADX 設定會變動。

`G91c5eRH.java` 可見的 frontend URL：

| URL／前綴 | 靜態出現位置 | 能確認的範圍 |
|---|---:|---|
| `https://frontend.wallet.gov.tw/api/moda/dwapp/apply/vcList` | 8606 | 領卡清單呼叫中的完整字串 |
| `https://frontend.wallet.gov.tw/api/moda/dwapp/offline/vpList` | 19538 | 離線出示清單呼叫中的完整字串 |
| `https://frontend.wallet.gov.tw/api/moda/dwapp/serviceUrl/` | 24741、27238 | 服務 URL 呼叫前綴；不能把前綴當完整資源 |
| `https://frontend.wallet.gov.tw/api/moda/dwapp/vc/realNameVerification/` | 28055 | 實名驗證呼叫前綴；未實際呼叫 |

唯讀量測：對不帶額外 suffix 的 `GET https://frontend.wallet.gov.tw/api/moda/dwapp/serviceUrl/` 收到 HTTP 404，JSON detail 為 `No static resource api/moda/dwapp/serviceUrl.`。此結果只證明裸前綴不是可直接取用的資源，不否定帶參數／後綴的 SDK 呼叫，也不能因此改用猜測的 POST。其餘新發現的 URL 本次未呼叫。

因此，找不到明文 endpoints 的一個具體原因已確認：相關 SDK 位於兩層封裝內，僅搜尋 Dart AOT 或主 DEX 不完整。簽章路徑有 APK 資產匯入私鑰的實證；目前並無證據可將它改寫成現行 `TwdiwDeviceKeys` 假設的裝置註冊規則。這不等於已證明整個 App 永遠沒有其他裝置註冊機制，或第三方應用必然會被拒絕。

### 商店版樣本的 TLS 設定

Manifest 的 `android:networkSecurityConfig` 指向資源 `0x7f140001`；aapt2 將其解析為 `res/raw/xc.xml`。該 XML 的 base trust-anchors 只有 `certificates src="system"`，未列 user CA、自訂 raw CA 或 XML pin-set。這次是直接檢查使用者提供的 1.0.14 樣本，而非沿用舊公開碼。

此結果仍只涵蓋 Android XML 設定，不排除 Flutter 引擎、其他 TLS 程式碼或保護層另有信任與代理策略；也不能僅由抓包失敗認定內建 root CA。與舊公開碼的對照、樣本重簽限制及使用者觀察須分別保留。

### 對目前實作的判斷

1. nonce URL 丟失 `/oid4vci` 是已實測的程式差異，可獨立修正並以回歸測試驗證。
2. 七欄 JWT、資產匯入 EC 私鑰與 ECDSA 簽章已有呼叫鏈證據；App 身分與 keyId 值流仍未完整還原，不能保證現行自行簽出的 header 被接受。
3. `TwdiwDeviceKeys` 對 `/api/did/` 的 POST、所猜的欄位與回應解析仍無官方契約支持；Tink 監控資訊不能補足此證據。此次未擅自把註冊請求改送 frontend 或其他猜測端點。
4. 本輪完成的是靜態查證與對既有推論的校正，沒有確認一條可實際完成的官方手機註冊流程。

## 官方簽章分割 APK 追加核對（2026-11-02）

使用者另提供 [TWDIW_1.0.14_apkcube.apks](https://drive.google.com/file/d/1Es6JQBy1zbLJz6Vb6NKG_FGnFxSd1B4P/view)，大小 69,925,703 bytes，SHA-256 為 `618fc74351c936d716e7e3b3a5981124e1e12c6abb4af7b9b574f62c7aac3a8c`。Drive metadata 已確認類型為 ZIP；連接器 raw fetch 兩次因 transport closed 失敗，改從使用者提供的公開檔案連結下載。未修改 Drive 檔案或權限。

### 簽章與官方公布值交叉驗證

- ZIP 包含 27 個 APK：base、arm64-v8a、xxxhdpi 與 24 個語言分包；沒有執行或安裝這些檔案。
- `base.apk` 的 package 為 `tw.gov.moda.diw`，versionName `1.0.14`，versionCode `62`，minSdk `28`，targetSdk `36`。
- 逐一以 Android build-tools 35.0.0 的 `apksigner verify --verbose --print-certs` 檢查，27 個 APK 全部成功，均由同一張憑證以 v3 簽署。
- 簽署憑證 SHA-256：`0ff666ffa74618629e859cc6cd2a51ade91cd716d09f83ddd4dcb863313c2930`。
- 唯讀取得 [官方 frontend assetlinks](https://frontend.wallet.gov.tw/.well-known/assetlinks.json)，HTTP 200；`target.package_name = tw.gov.moda.diw` 的公布指紋包含上述值，relation 為 `delegate_permission/common.handle_all_urls`。這是網站公開的 App Links 信任資料，沒有使用 APK 自述的憑證名稱來判斷來源。
- 此結果支持這批檔案保留官方公布憑證的有效簽章；不另宣稱已驗證使用者手機上的安裝來源、全部執行時行為或 Google Play 裝置完整性判定。

主要分包 SHA-256：

| 分包 | SHA-256 |
|---|---|
| `base.apk` | `0df9fb52206747cb2e4df2985c34e91f7203390c7d31ccd3b6b62c99ae4d383d` |
| `split_config.arm64_v8a.apk` | `30146156a091d64938e33e8582adbda3bf721fa06ad4c4472c82e90e1ec81a43` |
| `split_config.xxxhdpi.apk` | `d21b0afcb30a95d298a9b0e0497bce710f12d77760325cd182b13fe8eb01b7ad` |

### 與先前合併包的內容比較

下列 16 個檔案逐一比對內容 SHA-256，全部與先前 `860c2047...09ed737` 合併包相同：

| 範圍 | 核對結果與意義 |
|---|---|
| `classes.dex` | 14,501,968 bytes；主 DEX 與載入器分析可沿用 |
| `a-`、`b-` | 封裝本身完全相同；先前還原出的兩份 DEX 不需重做解碼 |
| 四個 `assets/dwapp201i_*` | 加密／編碼資產內容相同；未輸出或解出其金鑰內容 |
| arm64 分包內全部 9 個 `.so` | 包含 `libapp.so`、`libflutter.so` 與保護層程式庫，全部相同 |

base APK 排除 `META-INF/` 與目錄項目後，549 個檔案與合併包相同，差異只有 `AndroidManifest.xml`、`resources.arsc`。先前合併包的簽署憑證為 `dd7eab62...e9bfb3`，與這批官方公布指紋不同；不能把它視為保留原簽章的原包。

新 base 的 `res/raw/xc.xml` 仍只有 `certificates src="system"`，其內容與合併包相同，SHA-256 為 `40662bd671fe6dab4f6ea53bbaf400a9a20dad089511bfb0da279777fcaa083e`。因此「Android XML 未納入 user CA」也已核對到官方簽署的檔案；仍不據此判定 Flutter／保護層是否另有 pinning、內建 CA 或代理策略。

本輪新增的是簽章與來源證據，沒有新增裝置註冊 URL。先前 APK 內建資產匯入私鑰的呼叫鏈及 frontend API 字串均獲保留；appHash／keyId 值流與第三方應用准入的未知部分仍在。合併重簽可能影響執行時完整性檢查，但沒有實機診斷就不能宣稱它是使用者抓包失敗的唯一原因。

本機產物：`/workspace/scratch/twdiw-apkcube-1.0.14.apks`、`twdiw-apkcube-splits/`、`twdiw-apkcube-signature-report.json`、`twdiw-apkcube-comparison.json`、`twdiw-apkcube-verification-summary.json`、`twdiw-official-assetlinks.json`。不將 APK、個人憑證主體資料或金鑰資產提交 repo。本輪只更新研究文件，未改領卡程式，因此沒有重跑建置或功能測試。

## 分析附件追加核對

使用者後續提供 `TWDIW_1.0.14_領卡與簽章逆向分析.md`。該文件所需的解封 b- DEX 仍在本環境，雜湊相符；已打包為 `/workspace/scratch/twdiw-analysis-handoff-1.0.14.zip` 供跨環境接續。另在 dwapp 處理方法內確認 `r3OTB7M.ISyARpnL`（DER→64-byte R||S）與 `lJGlmuQP.mbkki7b3`（Base64 flag 11）的直接呼叫；holder 的 `hs415h1b` 做等價轉換但不是同一個 helper。appHash／keyId 值流仍未還原完成。

附件的 nonce 來源、grant_type 縮寫及若干證據等級需校正，詳見 [領卡與簽章分析附件核對](twdiw-1.0.14-issuance-review.md)。此輪沒有重做已完成的解封，也沒有修改領卡程式。

第二份修訂附件追加：已還原簽章 VM 的 1,171 個 opcode，追蹤成功路徑至六參數 Payload 建構子，確認 appHash 對應原始 package 名 `tw.gov.moda.diw`，keyId 對應公鑰 reader 的輸出。公鑰資產需依序通過 `VVcmSog7` 與 `ua7zwMYm`（8-round、CBC mode 2），並非僅一層處理；正規化後的 124-byte 文字可解析為 P-256 公鑰，其 SHA-256 為 `dfbbc7e88f69844fe449aca4f02ce1d719ddaaad9e3fd9dc25f1934869bc5a82`。本輪只讀 public 資產，未讀取或重用 private 資產。這是靜態模型的成功路徑核對，尚無實際 JWS 或伺服器接受證據。

附件所稱缺少 `libd186.so` 不符已驗簽分包的內容；arm64 分包含該檔，大小 1,612,328 bytes。`System.load` 的實參是 `ClassLoader.findLibrary("d186")` 的回傳路徑。完整值流、重現方法與 v2 交接包見前述核對文件；早期「appHash／keyId 尚未追到」的段落保留作研究進度紀錄，以本段與文件開頭為最新狀態。

第三份修訂附件已對齊上述結果。本輪進一步依 appPlatform 的四槽 Java helper 做有限算式搜尋，得到唯一可列印候選 `Android`，但兩個索引與 native 餘數／商數的綁定尚未完整核對，因此不升為確定值。候選、假設與原生反組譯觀察另列於 [附件核對文件](twdiw-1.0.14-issuance-review.md)；appPlatform、應用准入與實際伺服器接受仍未驗收。

## 現有實作與測試的限制

- `TwdiwDeviceKeys.REGISTRATION_PATH = "/api/did/"`，且預設用發證端 origin。did、keyType、keyPrefix、publicKey、attestation、nonce、proof、appHash、appPlatform、appVersion 均不能由本次官方來源確認為手機註冊契約。
- nonce 取得失敗仍會產生隨機 challenge 並嘗試註冊；不能宣稱每次證明都綁到伺服器核發的 nonce。
- 註冊失敗後重試會沿用既有金鑰，證明鏈仍綁首次建立時的 challenge，卻可能帶新的 nonce；若官方要求兩者一致，現行流程可能不符。是否需要重新證明或重新建立金鑰取決於尚未取得的契約。
- `appHash = SHA-256(appId)`、`android-keystore://` 等值是目前實作的假設，本次沒有官方證據確認其語意；不能把應用程式識別字串雜湊視為已驗證的 App 身分。
- 註冊拒絕時改用持有者金鑰簽章，只保證仍會嘗試送出領卡請求，不能保證官方接受或「不影響領卡」。nonce 404 時，`TwdiwDialect` 目前直接不附生態系標頭。
- `TwdiwEcosystemSignatureTest` 驗證自己產生的 JWT、假造 nonce、假造註冊回應、持有者金鑰 fallback 與本機保存。它是本機回歸測試，不是官方互通驗收；本次未改程式，因此未重跑建置或測試。

## 後續查證方向

1. 使用者無法抓包或操作官方 App 不構成靜態分析的前置阻礙。可繼續沿還原 SDK 分派追 appHash、keyId、Header 序列化及 frontend 前綴的後綴組合；不要求使用者先繞過代理或反逆向。
2. 啟動時連到電信發證端，也可能是中繼資料或既有卡片更新，不能直接移用為註冊 base URL。若之後另有實機紀錄，再比較操作與連線順序；此輪沒有此動態證據。
3. 第三方皮夾如何取得平台接受的應用身分，仍需官方契約或明確的 SDK 呼叫鏈。不能以重用官方 App 的內建私鑰冒充該應用來驗收；也不能假定修正 nonce 前綴就能解決平台的應用准入。
4. 修改路由或欄位應依相應證據與回歸測試。OID4VCI proof nonce 與生態系 nonce 分開處理；不以機構註冊 DTO 代替手機註冊，也不以關閉 TLS 驗證作為正式修正。

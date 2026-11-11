# 發佈建置

CI 在 push 到 main 時重建「nightly」預先發行版，檔案不經壓縮：

| 檔案 | 說明 |
|---|---|
| `DIW-MY-WALLET-<版本>.apk` | Android release 版：R8 縮減與最佳化，網路安全設定只允許本機與模擬器主機的 HTTP；兩個 ABI 與所有選用元件都在裡面 |
| `DIW-MY-WALLET-<版本>-arm64-v8a.apk`、`-x86_64.apk` | 同上，只含一個 ABI，檔案較小（一般手機用 arm64-v8a） |
| `DIW-MY-WALLET-<版本>.apks` | 同一版的分割 APK 組，與 Google Play 的分割相同，選用元件是獨立分割；用 `bundletool install-apks` 或 SAI 等分割安裝程式安裝，可以只裝需要的部分 |
| `DIW-MY-WALLET-<版本>-debug.apk` | Android debug 版：未最佳化，允許區網測試伺服器的 HTTP；含所有選用元件 |
| `DIW-MY-WALLET-<版本>.aab`、`DIW-MY-WALLET-<版本>-debug.aab` | release／debug App Bundle，供 Google Play 或 bundletool 使用，不能直接安裝 |
| `DIW-MY-WALLET-<版本>-mapping.txt` | release 版的 R8 mapping，與 AAB 一起上傳 Google Play 以還原當機記錄（套用 `diw-wallet/play/` 的 CI 修改後才有） |
| `DIW-MY-WALLET-<版本>.msi` | Windows 安裝檔（ProGuard 最佳化，內含 Java 執行環境，不需系統管理員權限） |
| `diw-my-wallet_<版本>_amd64.deb` | Linux 安裝檔（同上） |
| `DIW-MY-WALLET-<平台>-<版本>-release.jar` | 需自行安裝 Java 21，以 `java -jar` 執行；macOS（Apple 晶片）只提供這個檔案 |
| `zk-templates.jwt` | 零知識證明版型包（zkTLS 查驗頁與 zkPDF 版型），以 `ZK_TEMPLATES_KEY` 簽章；沒有設定這個 secret 時不附上。格式與手動發佈見 [templates/README.md](../templates/README.md) |

Google Play 的上架步驟、自動提交 workflow（`google-play.yml`，從 nightly 取 AAB 上傳）、商店資訊與資料安全表單見 [google-play.md](google-play.md)。

每個平台都連結零知識證明的 OpenAC 年齡證明與 TLSNotary（zkTLS）後端（Android、Windows、Linux、macOS，CI 以 `DIW_ZK_FEATURES=openac,tlsn` 建置）；Android 與 Linux 另連結 zkPDF（Barretenberg 6.0.0，`openac,tlsn,zkpdf`），Windows 暫不支援、macOS 尚未建置。zkPDF 的電路資產在 `zkpdf-v1-bb6` release，由手動執行的 `zkPDF assets` workflow 從原始碼建置並核對雜湊後發佈，App 依 `native/assets.json` 下載並核對；CI 的測試也從這裡取得資產（`native/circuits/tools/fetch_assets.py`），尚未發佈時略過 zkPDF 證明測試並警告。mdoc 的 Longfellow 由 Multipaz 提供，沒有 Windows 版。

零知識原生函式庫在 CI 由獨立工作建置：`native-android`（Linux，每個 ABI 一個工作）、`native-linux`（Linux 桌面，也供測試使用）、`native-desktop`（Windows、macOS）。它們只上傳最終函式庫（`zk-native-android-<abi>`、`zk-native-<os>` Artifacts，保留 3 天），`test`、`build`、`desktop` 下載回 `native/dist` 並以 `DIW_ZK_NATIVE=prebuilt` 執行 Gradle，不再安裝 Rust、NDK 編譯工具或建置 Barretenberg。發佈只收 `android`、`windows`、`linux`、`macos`、`zk-templates` 這幾個 Artifacts，原生函式庫不會出現在 nightly。

## 版本號

版本號只記在 repo 根目錄的 `version.properties`（`version=主版號.次版號`，進入新階段或正式發佈時手動修改），建置時補上修訂號：從最後一次修改 `version=` 那一行的 commit 起算的 commit 數。同一個 commit 在任何機器算出的版本都相同，換新的主版號或次版號時修訂號從 0 重新開始，之後每合併一次到 main 加 1。不再使用 CI 執行次數。

| 建置 | 版本 | Android versionCode |
|---|---|---|
| push 到 main（nightly） | `0.4.<修訂號>` | 主版號 × 1,000,000 + 次版號 × 10,000 + 修訂號（0.4.3 為 40003） |
| pull request | `0.4.<修訂號>-pr<PR 編號>` | 同上 |
| 本機 | `0.4.<修訂號>-dev` | 同上 |

修訂號需要完整的 git 歷史：CI 的 checkout 使用 `fetch-depth: 0`，`tools/app-version.sh` 在歷史不完整時讓發佈檔案的工作失敗；只跑測試的工作只警告並以修訂號 0 繼續。修訂號達 10,000 時建置要求換新的版本線。

versionCode 由版本算出，換新版本線時一定變大（0.4 起為 40000 以上，大於舊規則的 CI 執行次數），所以新建置能覆蓋安裝舊版（同一把簽章金鑰時）；同一版本線內只要從 main 依序建置，也一定變大。Windows 安裝檔與 Linux 套件使用不含字尾的數字版本（`0.4.<修訂號>`）。`-Pdiw.versionName`、`-Pdiw.versionCode`、`-Pdiw.desktopVersion` 仍可覆寫。CI 以 `tools/app-version.sh`（與 Gradle 同一規則）算出 `APP_VERSION` 為檔名，`./gradlew -q :app:printVersion` 可查看 Gradle 算出的版本。關於頁顯示版本與 commit。

## Android 選用元件與 APK

少數人需要、體積又大的原生元件放在隨選動態功能模組（`features/`），目前只有 `features/bb5`：Barretenberg 5（`native/zkpassport-bb5`），用來驗證 zkPassport 0.22.0 以前電路的證明。Google Play 版在用到時由 App 向 Play 要求安裝（設定的 zkPassport 區段或查驗結果頁的按鈕）；Play 政策不允許從 Play 以外下載可執行程式碼，所以不另外提供下載。

GitHub 的 APK 與 `.apks` 由 CI 用 `tools/bundle-apks.sh` 從 Google Play 收到的同一個 AAB 產生（bundletool，版本與 SHA-256 釘選在腳本裡），所以程式碼、版本號與簽章都和 Play 版相同：`.apk` 已含所有模組，`.apks` 的模組是獨立分割。電腦版把同一個函式庫放在 JAR 的資源裡，所以每個版本的功能一致。新增這類元件時照同樣方式：加一個 `features/` 模組並列入 `app` 的 `dynamicFeatures`，在 `ZkComponent` 的實作裡載入，桌面版放進資源。

本機建置 Android 時要在 `DIW_ZK_FEATURES` 加上 `bb5`（需要 `zkpdf`），`native/build.sh` 才會建置 `native/dist/android-bb5`；沒有時模組是空的，App 會顯示元件不可用。bundletool 要求有原生程式碼的模組都支援和 base 相同的 ABI，而 base 含相依套件（JNA、Tesseract、CameraX 等）的 32 位元函式庫；32 位元沒有 Barretenberg（也沒有 `diw_zk`），所以 `build.sh` 在 `armeabi-v7a` 與 `x86` 放一個空的 `libdiw_bb5_none.so`，App 不會載入它。

## Android 簽章

release APK 以 repo secrets 的金鑰簽章；沒有設定時改用 debug 金鑰。debug APK 以 `DEBUG_KEYSTORE_BASE64` 的金鑰簽章，沒有設定時每次 CI 用新產生的金鑰，無法覆蓋安裝舊版。CI 記錄會印出兩把金鑰的 SHA-256 指紋（`Debug APK signed with key ...`、`Release APK signed with key ...`），每次相同才代表簽章固定。

AAB 使用相同 build type 的 signingConfig。AAB 是分發格式，不能直接當 APK 安裝；由 Google Play 或 bundletool 產生適合裝置的 APK。要上架時必須提供正式 upload key，debug 金鑰的 fallback 僅供測試。

建立金鑰（PowerShell，金鑰請自行保管，遺失後無法再更新已安裝的 App）：

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
keytool -genkeypair -v -keystore diw-release.jks -alias diw -keyalg RSA -keysize 4096 -validity 10000
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path "diw-release.jks"))) | Set-Clipboard
```

JDK 9 以後 keytool 預設建立 PKCS12 keystore，金鑰密碼固定等於 keystore 密碼（指定不同的 `-keypass` 會被忽略）。

到 GitHub repo 的 Settings、Secrets and variables、Actions 新增：

| Secret | 內容 |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | 上面複製的 base64（換行與空白會自動去除） |
| `ANDROID_KEYSTORE_PASSWORD` | keystore 密碼 |
| `ANDROID_KEY_ALIAS` | `diw` |
| `ANDROID_KEY_PASSWORD` | 只有舊式 JKS 且金鑰密碼不同時才設；PKCS12 請不要設 |
| `DEBUG_KEYSTORE_BASE64` | debug keystore 的 base64，固定 debug APK 的簽章 |
| `DEBUG_KEYSTORE_PASSWORD` | 只有 debug keystore 密碼不是 `android` 時才設 |
| `DEBUG_KEY_ALIAS` | 只有 debug keystore 內有多把金鑰時才設 |
| `ZK_TEMPLATES_KEY` | 版型包的發布私鑰（P-256 PEM），公鑰釘選在 App；見 templates/README.md |

建立 debug keystore（PowerShell，與 release 金鑰分開保管）：

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
keytool -genkeypair -v -keystore diw-debug.p12 -storetype PKCS12 -storepass android -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=DIW MY WALLET Debug"
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path "diw-debug.p12"))) | Set-Clipboard
```

本機建置要用同一把金鑰時，設定環境變數 `DIW_DEBUG_KEYSTORE_FILE` 指向這個檔案（密碼不是 `android` 時另設 `DIW_DEBUG_KEYSTORE_PASSWORD`）。

CI 的 Signing keys 步驟會先檢查 base64、keystore 密碼與別名，並印出憑證 SHA256 指紋；Gradle 在 release 建置開始前開啟金鑰，`ANDROID_KEY_PASSWORD` 打不開時改用 keystore 密碼，兩者都不行就以明確訊息停止，不會改用 debug 金鑰。

### 簽章失敗排查

| CI 訊息 | 原因與處理 |
|---|---|
| `ANDROID_KEYSTORE_BASE64 is not valid base64` | base64 不完整，重新複製整段 |
| `ANDROID_KEYSTORE_PASSWORD does not open the keystore` | keystore 密碼錯，或 base64 不是整個 .jks 檔 |
| `ANDROID_KEY_ALIAS is not a key in the keystore` | 別名錯，上一行會列出 keystore 內的別名 |
| `Key "..." opens with neither ANDROID_KEY_PASSWORD nor ANDROID_KEYSTORE_PASSWORD` | JKS 的金鑰密碼錯 |
| `Given final block not properly padded` | 舊版建置腳本把空的 `ANDROID_KEY_PASSWORD` 當成密碼，更新後即可 |

在自己電腦確認金鑰（PowerShell）：

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
keytool -list -v -keystore diw-release.jks -alias diw
Get-FileHash diw-release.jks -Algorithm SHA256
```

`Keystore type` 為 `PKCS12` 時刪除 `ANDROID_KEY_PASSWORD`；`SHA256` 指紋要與 CI 印出的相同，不同代表 secret 存的是另一個檔案。

本機建置 release：設定環境變數 `DIW_KEYSTORE_FILE`、`DIW_KEYSTORE_PASSWORD`、`DIW_KEY_ALIAS`（金鑰密碼不同時再設 `DIW_KEY_PASSWORD`）後執行 `./gradlew :app:assembleRelease`。

APK 與 AAB 一起建置：

```bash
./gradlew :app:assembleDebug :app:bundleDebug
./gradlew :app:assembleRelease :app:bundleRelease
```

本機驗證使用 `--max-workers=1 -Dorg.gradle.jvmargs='-Xmx4g -Dfile.encoding=UTF-8' -Pkotlin.compiler.execution.strategy=in-process`，讓 Kotlin 與 R8 共用受限的 JVM heap，避免另外保留大型 Kotlin daemon 後在 R8 階段達到記憶體上限。手動更新 CI Android 建置命令時也建議加入相同參數。

## TWDIW 應用簽章金鑰

這組金鑰用於新版 TWDIW `dwapp-201i` 格式的 `Twdiw-Signature`，獨立於 holder／Android APK 簽章金鑰。尚未找到 `diwapp-200i` 的另一份契約，因此設定不以該未確認名稱命名。只匯入自行產生或合法取得的應用金鑰，不讀取官方 APK 的私鑰資產。

| GitHub Actions secret | Gradle／本機環境變數 | 格式 |
|---|---|---|
| `TWDIW_APP_PRIVATE_KEY` | `DIW_TWDIW_APP_PRIVATE_KEY` | 未加密 P-256 PKCS#8 PEM（`BEGIN PRIVATE KEY`），或其 DER 的標準 Base64 |
| `TWDIW_APP_PUBLIC_KEY` | `DIW_TWDIW_APP_PUBLIC_KEY` | P-256 SPKI PEM（`BEGIN PUBLIC KEY`），或其 DER 的標準 Base64 |

兩個值都空白或未設時，`:app:generateTwdiwApplicationKey` 以 JDK 產生新的 P-256 配對。它在 `app/build/twdiwApplicationKeyState/` 保留本機配對，讓同一工作目錄的 APK、AAB、桌面產物及後續增量建置使用相同應用 keyId；`clean` 或新 CI runner 會產生另一組。要跨 CI 發行保持 keyId，必須提供固定配對。

兩值須同時提供；只填一個、格式錯誤、曲線不是 P-256，或簽署／驗簽證明不匹配時，建置失敗，不會悄悄改用隨機金鑰。建置只記錄來源及公鑰文字指紋，不輸出私鑰。產生的 Kotlin source 位於 `app/build/generated/twdiwApplicationKey/kotlin/`；POSIX 系統下 state 與 source 權限為 0600，不作此任務的 build-cache artifact，也不提交或額外上傳 state/source。

CI 的 `build` 與 `desktop` job 只在 push 建置注入這兩個 secrets；PR 建置使用自己的生成測試配對。Android debug／release 的 APK／AAB 及桌面包都支援相同環境輸入。沒有設定這兩個 GitHub secrets 時 push 建置也產生測試配對，不必手動填空字串。兩個 job 的 `env` 為：

```yaml
DIW_TWDIW_APP_PRIVATE_KEY: ${{ github.event_name == 'push' && secrets.TWDIW_APP_PRIVATE_KEY || '' }}
DIW_TWDIW_APP_PUBLIC_KEY: ${{ github.event_name == 'push' && secrets.TWDIW_APP_PUBLIC_KEY || '' }}
```

Android 建置以 `:app:bundleDebug`／`:app:bundleRelease` 一併產生 AAB 並收進 `android` Artifact。金鑰建置測試可透過 `python3 tools/twdiw/test_generate_application_key.py` 執行。

本機 PowerShell 匯入合法金鑰：

```powershell
$env:DIW_TWDIW_APP_PRIVATE_KEY = [IO.File]::ReadAllText((Resolve-Path "my-application-private.pem"))
$env:DIW_TWDIW_APP_PUBLIC_KEY = [IO.File]::ReadAllText((Resolve-Path "my-application-public.pem"))
./gradlew :app:assembleRelease :app:bundleRelease
```

Secrets 保護的是 repo 與建置輸入；這項設計會把應用簽章能力放進發行產物，不能把客戶端內嵌私鑰視為無法擷取的機密。不得提供不允許散布在客戶端的金鑰；未來平台若要求非匯出金鑰或後端簽署，需依正式契約另接 signer。

應用身分使用本專案 `diw.wallet.app`、本次版本與平台，keyId 是該配對 Base64 SPKI 文字的 SHA-256。自動生成或合法匯入不代表官方平台已准入；正式受理仍須官方授權與端到端驗收。新版／舊版流程與驗證紀錄見 [TWDIW 新版領卡實作](acceptance/twdiw-application-signature.md)。

## 行動自然人憑證 SP 帳號

SP 帳號在建置時由 `DIW_MOICA_SP_SERVICE_ID`、`DIW_MOICA_SP_AES_KEY`、`DIW_MOICA_SP_ENV`（`UAT` 或 `PRODUCTION`）產生 `BuiltInSp`，不提交進 repo。目前的 CI workflow 沒有傳入這三個值，所以 nightly 沒有內建 SP 帳號；可改用正式服務端的 SP（服務端啟用 `twfido`，App 設定正式服務端與存取權杖），或在「設定 > 開發者與測試」手動輸入（只存在記憶體）。持有 SP 許可的開發者可在本機設定環境變數後建置；要讓 CI 內建，需新增同名 secrets 並在 workflow 的 build 與 desktop job 的 `env` 加入這三行（workflow 由使用者手動修改）。

## 縮減規則

- Android：`app/proguard-rules.pro`。Bouncy Castle 與 Multipaz 以類別名稱載入演算法與格式，整包保留。
- 桌面版：`app/compose-desktop.pro`，另保留 SQLite JDBC 與 Ktor Java 引擎；不做名稱混淆。

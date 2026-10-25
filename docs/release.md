# 發佈建置

CI 在 push 到 main 時重建「nightly」預先發行版，檔案不經壓縮：

| 檔案 | 說明 |
|---|---|
| `DIW-MY-WALLET-<版本>.apk` | Android release 版：R8 縮減與最佳化，網路安全設定只允許本機與模擬器主機的 HTTP |
| `DIW-MY-WALLET-<版本>-debug.apk` | Android debug 版：未最佳化，允許區網測試伺服器的 HTTP |
| `DIW-MY-WALLET-<版本>.msi` | Windows 安裝檔（ProGuard 最佳化，內含 Java 執行環境，不需系統管理員權限） |
| `diw-my-wallet_<版本>_amd64.deb` | Linux 安裝檔（同上） |
| `DIW-MY-WALLET-<平台>-<版本>-release.jar` | 需自行安裝 Java 21，以 `java -jar` 執行；macOS（Apple 晶片）只提供這個檔案 |
| `zk-templates.jwt` | 零知識證明版型包（zkTLS 查驗頁與 zkPDF 版型），以 `ZK_TEMPLATES_KEY` 簽章；沒有設定這個 secret 時不附上。格式與手動發佈見 [templates/README.md](../templates/README.md) |

每個平台都連結零知識證明的 OpenAC 年齡證明與 TLSNotary（zkTLS）後端（Android、Windows、Linux、macOS，CI 以 `DIW_ZK_FEATURES=openac,tlsn` 建置）。mdoc 的 Longfellow 由 Multipaz 提供，沒有 Windows 版。

## 版本號

版本號只記在 repo 根目錄的 `version.properties`（`version=主版號.次版號`），建置時補上修訂號：

| 建置 | 版本 | Android versionCode |
|---|---|---|
| push 到 main（nightly） | `0.4.<CI 執行次數>` | CI 執行次數 |
| pull request | `0.4.<CI 執行次數>-pr<PR 編號>` | CI 執行次數 |
| 本機 | `0.4.0-dev` | 1 |

CI 執行次數在 PR 與 main 之間共用且只會增加，所以新建置一定能覆蓋安裝舊版（同一把簽章金鑰時）。進入新階段或正式發佈時只改 `version.properties`。Windows 安裝檔與 Linux 套件使用不含字尾的數字版本。`-Pdiw.versionName`、`-Pdiw.versionCode`、`-Pdiw.desktopVersion` 仍可覆寫。CI 以同一規則算出 `APP_VERSION` 為檔名，`./gradlew -q :app:printVersion` 可查看 Gradle 算出的版本。關於頁顯示版本與 commit。

## Android 簽章

release APK 以 repo secrets 的金鑰簽章；沒有設定時改用 debug 金鑰。debug APK 以 `DEBUG_KEYSTORE_BASE64` 的金鑰簽章，沒有設定時每次 CI 用新產生的金鑰，無法覆蓋安裝舊版。CI 記錄會印出兩把金鑰的 SHA-256 指紋（`Debug APK signed with key ...`、`Release APK signed with key ...`），每次相同才代表簽章固定。

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

## 行動自然人憑證 SP 帳號

SP 帳號在建置時由 `DIW_MOICA_SP_SERVICE_ID`、`DIW_MOICA_SP_AES_KEY`、`DIW_MOICA_SP_ENV`（`UAT` 或 `PRODUCTION`）產生 `BuiltInSp`，不提交進 repo。目前的 CI workflow 沒有傳入這三個值，所以 nightly 沒有內建 SP 帳號，只能在「設定 > 開發者與測試」手動輸入（只存在記憶體）。持有 SP 許可的開發者可在本機設定環境變數後建置；要讓 CI 內建，需新增同名 secrets 並在 workflow 的 build 與 desktop job 的 `env` 加入這三行（workflow 由使用者手動修改）。

## 縮減規則

- Android：`app/proguard-rules.pro`。Bouncy Castle 與 Multipaz 以類別名稱載入演算法與格式，整包保留。
- 桌面版：`app/compose-desktop.pro`，另保留 SQLite JDBC 與 Ktor Java 引擎；不做名稱混淆。

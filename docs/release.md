# 發佈建置

CI 在 push 到 main 時重建「nightly」預先發行版，檔案不經壓縮：

| 檔案 | 說明 |
|---|---|
| `DIW-MY-WALLET-<版本>.apk` | Android release 版：R8 縮減與最佳化，網路安全設定只允許本機與模擬器主機的 HTTP |
| `DIW-MY-WALLET-<版本>-debug.apk` | Android debug 版：未最佳化，允許區網測試伺服器的 HTTP |
| `DIW-MY-WALLET-<版本>.msi` | Windows 安裝檔（ProGuard 最佳化，內含 Java 執行環境，不需系統管理員權限） |
| `diw-my-wallet_<版本>_amd64.deb` | Linux 安裝檔（同上） |
| `DIW-MY-WALLET-<平台>-<版本>-release.jar` | 需自行安裝 Java 21，以 `java -jar` 執行 |

版本號為 `0.1.<CI 執行次數>`，Android versionCode 為 CI 執行次數，新版可直接覆蓋安裝舊版。

## Android 簽章

release APK 以 repo secrets 的金鑰簽章；沒有設定時改用 debug 金鑰，仍可安裝測試，但每次 CI 的 debug 金鑰不同，需先解除安裝舊版。

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
| `DEBUG_KEYSTORE_BASE64` | 選用，固定 debug APK 的簽章 |

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

## 縮減規則

- Android：`app/proguard-rules.pro`。Bouncy Castle 與 Multipaz 以類別名稱載入演算法與格式，整包保留。
- 桌面版：`app/compose-desktop.pro`，另保留 SQLite JDBC 與 Ktor Java 引擎；不做名稱混淆。

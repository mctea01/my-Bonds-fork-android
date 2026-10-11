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
keytool -genkeypair -v -keystore diw-release.jks -alias diw -keyalg RSA -keysize 4096 -validity 10000
[Convert]::ToBase64String([IO.File]::ReadAllBytes("diw-release.jks")) | Set-Clipboard
```

到 GitHub repo 的 Settings、Secrets and variables、Actions 新增：

| Secret | 內容 |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | 上面複製的 base64 |
| `ANDROID_KEYSTORE_PASSWORD` | keystore 密碼 |
| `ANDROID_KEY_ALIAS` | `diw` |
| `ANDROID_KEY_PASSWORD` | 金鑰密碼（與 keystore 相同可不設） |
| `DEBUG_KEYSTORE_BASE64` | 選用，固定 debug APK 的簽章 |

本機建置 release：設定環境變數 `DIW_KEYSTORE_FILE`、`DIW_KEYSTORE_PASSWORD`、`DIW_KEY_ALIAS`、`DIW_KEY_PASSWORD` 後執行 `./gradlew :app:assembleRelease`。

## 縮減規則

- Android：`app/proguard-rules.pro`。Bouncy Castle 與 Multipaz 以類別名稱載入演算法與格式，整包保留。
- 桌面版：`app/compose-desktop.pro`，另保留 SQLite JDBC 與 Ktor Java 引擎；不做名稱混淆。

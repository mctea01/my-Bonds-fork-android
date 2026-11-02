# TWDIW 應用簽章金鑰的建置工具

`GenerateApplicationKey.java` 使用 JDK 21 的 EC／ECDSA 實作，供 Gradle 的 `:app:generateTwdiwApplicationKey` 呼叫，不依賴 Python 套件或官方 SDK。

- `DIW_TWDIW_APP_PRIVATE_KEY`、`DIW_TWDIW_APP_PUBLIC_KEY` 同時提供：匯入合法自有 P-256 配對，支援 PKCS#8／SPKI PEM 或 Base64 DER。
- 兩者皆空：產生配對，在 ignored build 目錄保留至 clean，避免同一工作目錄的 APK／AAB 使用不同 keyId。
- 只給一個、曲線／格式錯或配對不符：停止建置，不產生替代配對。
- Generated Kotlin source 使用經 JDK 重新編碼的 Base64 DER，不插入原始環境字串；配對以實際 ECDSA 簽署／驗簽核對。
- log 只有來源與 public keyId，私鑰不放進命令列。POSIX 下 source／state 檔為 0600；state 有檔案鎖及原子寫入。

正常建置直接執行 Gradle，不需手動呼叫 Java 工具：

```bash
./gradlew :app:assembleDebug :app:bundleDebug
./gradlew :app:assembleRelease :app:bundleRelease
```

獨立測試：

```bash
python tools/twdiw/test_generate_application_key.py -v
```

測試只使用臨時生成的配對，明確移除繼承的兩個金鑰環境變數，再驗證空值重用、PEM／DER、配對與曲線、部分 secrets、毀損 state、檔案權限及錯誤訊息不含輸入私鑰。錯誤曲線測試需要 OpenSSL，其他測試只需 Python 標準函式庫及 JDK。

GitHub secret 名稱、PR 與 push 差異、內嵌客戶端金鑰的界線見 [發佈建置](../../docs/release.md)；驗證紀錄見 [新版領卡驗收](../../docs/acceptance/twdiw-application-signature.md)。

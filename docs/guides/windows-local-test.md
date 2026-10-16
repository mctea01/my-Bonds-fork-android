# 在 Windows 測試本地發行端

需要 JDK 21（Temurin）；用手機或模擬器測試時另需 Android SDK 的 `adb`。

## 1. PowerShell 統一 UTF-8

每開一個 PowerShell 視窗先執行：

```powershell
chcp 65001
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$env:JAVA_TOOL_OPTIONS = "-Dfile.encoding=UTF-8"
```

## 2. 啟動測試伺服器

伺服器的對外網址必須和錢包連線用的網址完全相同（metadata 的 credential_issuer 要一致），所以依錢包所在位置選一種：

| 錢包在哪裡 | 指令 | 錢包要填的網址 |
|---|---|---|
| Android 模擬器 | `.\gradlew.bat :test-servers:run --args="8080 http://10.0.2.2:8080"` | `http://10.0.2.2:8080` |
| USB 連接的實機 | 先 `adb reverse tcp:8080 tcp:8080`，再 `.\gradlew.bat :test-servers:run` | `http://localhost:8080` |
| 同一台電腦的桌面版 | `.\gradlew.bat :test-servers:run`，另開視窗 `.\gradlew.bat :app:run` | `http://localhost:8080` |
| 同一個 Wi-Fi 的實機（只限 debug APK） | `.\gradlew.bat :test-servers:run --args="8080 http://192.168.1.20:8080"`（換成電腦的 IP，`ipconfig` 查） | `http://192.168.1.20:8080` |

看到 `DIW test servers on ...` 就是啟動完成，Gradle 會一直停在執行中，按 Ctrl+C 結束。要同時給模擬器與桌面版用，可以用不同埠各開一個，例如 `--args="8081 http://localhost:8081"`。

走 Wi-Fi 時，Windows 防火牆要放行該埠（系統管理員 PowerShell）：

```powershell
New-NetFirewallRule -DisplayName "DIW test server" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Profile Private
```

網路要設為「私人」，公司或公共 Wi-Fi 若有用戶端隔離則連不到，改用 USB 的 adb reverse。區網 IP 只接受私有網段（10.x、172.16 至 172.31、192.168.x）；CI 產出的 debug APK 允許，正式版 APK 不允許。

## 3. 錢包設定

設定（右上齒輪）的「自訂測試伺服器」依序：開啟「使用自訂測試伺服器」與「允許本機與區網 HTTP」，「測試伺服器網址」填上表的網址並儲存，按「從測試伺服器匯入錨點」。需要金鑰證明的項目再開「使用測試錢包提供者」。

## 4. 領卡

方式 A，錢包自行發起：「使用」分頁的「貼上連結」填 `http://10.0.2.2:8080/issuer`（或 `http://localhost:8080/issuer`），勾選要領的憑證，瀏覽器會自動完成授權並回到錢包。

方式 B，預授權 offer（在電腦上產生）：

```powershell
$r = Invoke-RestMethod -Method Post -Uri http://localhost:8080/issuer/offers -ContentType "application/json" -Body '{"configuration_ids":["pid_sd_jwt","mdl_mdoc"]}'
$r.offer_uri
```

桌面版直接把 `offer_uri` 貼到「使用」分頁的「貼上連結」。手機或模擬器用：

```powershell
adb shell am start -a android.intent.action.VIEW -d ("'" + $r.offer_uri + "'")
```

加 `"tx_code":"1234"` 會要求輸入交易碼。可用的設定 ID：`pid_sd_jwt`、`pid_sd_jwt_attested`、`pid_sd_jwt_attestation_proof`、`pid_sd_jwt_deferred`、`pid_sd_jwt_keyless`、`mdl_mdoc`、`w3c_sd_jwt_legacy`（非標準的 W3C SD-JWT）、`w3c_ldp_vc`（不支援格式，用來測錯誤列表）。完整清單：

```powershell
(Invoke-RestMethod http://localhost:8080/.well-known/openid-credential-issuer/issuer).credential_configurations_supported | Get-Member -MemberType NoteProperty
```

## 5. 驗證（出示）

測試伺服器附有驗證測試頁 `<伺服器網址>/verifier`，例如 `http://192.168.1.20:8080/verifier`。選好要求的憑證後按「建立請求」，頁面會顯示 QR Code 與連結，並每 2 秒更新驗證結果。

- 跨裝置：電腦瀏覽器開測試頁，用錢包「使用」分頁的「掃描 QR Code」。
- 同裝置：手機瀏覽器開測試頁，點「在此裝置開啟」切到錢包；出示完成後瀏覽器會開啟結果。
- DC API（Android Credential Manager）：瀏覽器只在安全來源提供此功能。手機先 `adb reverse tcp:8080 tcp:8080`，用 Chrome 開 `http://localhost:8080/verifier`，按「以 DC API 出示」，系統會跳出憑證選擇。也可以在手機 Chrome 的 `chrome://flags/#unsafely-treat-insecure-origin-as-secure` 加入 `http://192.168.1.20:8080`，重啟 Chrome 後直接用區網網址。

看結果：
- 錢包同意畫面應顯示驗證端為測試環境的「DIW Test Verifier」，並列出要提供的欄位。
- 頁面顯示「驗證通過」，`credentials` 內每項的 `passed` 為 true；`test_environment` 為 true 表示只在測試環境有效。
- 「故意破壞請求」的選項（簽章錯誤、SAN 不符、回應位址指向他處、外層 client_id 不一致）錢包都應拒絕並說明原因。`redirect_uri` 前綴是未簽章請求，錢包會標示為最低信任等級 T4。
- 「任一即可」測試 credential_sets，只出示其中一張也應通過。

不用網頁時，也可以在 PowerShell 建立請求：

```powershell
$s = Invoke-RestMethod -Method Post -Uri http://localhost:8080/verifier/sessions -ContentType "application/json" -Body '{}'
$s.uri
Invoke-RestMethod http://localhost:8080/verifier/sessions/$($s.id)
```

第一行建立請求，`$s.uri` 貼到錢包，最後一行查結果。

## 6. 常見錯誤

- `is not an acceptable https endpoint`：沒開「允許本機與區網 HTTP」，或用了私有網段以外的位址。
- `CLEARTEXT communication ... not permitted`：App 版本太舊或是正式版 APK，請改用含區網支援的 debug APK，或改用 adb reverse。
- `credential_issuer in metadata does not match`：伺服器啟動時的網址和錢包用的不同，依第 2 節重開。
- 匯入錨點失敗或連不上：確認伺服器視窗仍在執行；實機每次重新插線後要再跑一次 `adb reverse`。
- 只想跑自動測試：`.\gradlew.bat :test-servers:test :app:desktopTest`。

## 錢包身分與用戶端驗證

「設定 > 互通 > OpenID4VCI 錢包身分」可填錢包的 `client_id` 與受信任錢包後端的 HTTPS 網址。錢包依發證端中繼資料的 `token_endpoint_auth_methods_supported` 選擇：

1. 列出 `attest_jwt_client_auth` 且後端能發 Wallet Attestation 時用它；
2. 列出 `private_key_jwt` 且後端能簽 Client Assertion 時用它；
3. 其餘情況以公開用戶端（只送 `client_id` 與 PKCE）嘗試。Keycloak 與 EUDI 發證端不會列出 `none` 但接受公開用戶端；發證端回 `invalid_client` 時，錯誤會寫明它要求哪些驗證方式。

本機測試伺服器的 Wallet Provider 在「設定 > 開發者與測試」設定，不要把發證端網址填成錢包後端。把 `client_id` 改成其他錢包的識別碼不會讓正式發證端信任這個錢包。

## mdoc 簽署清單（VICAL、RICAL）

1. 在「設定 > 信任 > 自訂信任」匯入簽署清單的根憑證，用途勾「VICAL／RICAL 清單發行者」。這只代表信任清單的簽署者，不是把清單內的憑證都當成根憑證。
2. 同一頁的「mdoc 簽署清單」選 VICAL（mdoc 發行端）或 RICAL（查驗方），填 HTTPS 網址後按「驗證簽章後匯入」。清單發行者的根憑證與清單要在同一個環境，測試根憑證簽的清單不會變成正式信任。
3. 匯入同一發行者的清單時版本必須遞增；RICAL 的項目必須標為信任錨點。過期的清單立即停止提供信任，但仍列在清單中，可按「更新到期的清單」重新下載或移除；其中一份下載失敗不影響其他清單。

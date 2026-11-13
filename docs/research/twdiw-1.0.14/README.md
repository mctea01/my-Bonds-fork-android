# TWDIW 官方 App 1.0.14 分析

性質：研究紀錄（2026-11-02 至 2026-11-03）。對象是官方「數位憑證皮夾」Android 1.0.14，用來確認新版夥伴卡平台在標準 OpenID4VCI 之外要求的應用簽章（`Twdiw-Signature`）。平台的一般協定行為見 [../twdiw.md](../twdiw.md)。

**只想知道現況：** 錢包的實作與驗證見 [驗收紀錄](../../acceptance/twdiw-application-signature.md)，規則見 [AGENTS.md](../../../AGENTS.md) 的「TWDIW 與 Bonds 要點」。

## 結論

- `Twdiw-Signature` 是應用層的 ES256 JWS，payload 七欄（appHash、appPlatform、appVersion、bodyHash、timestamp、keyId、nonce），綁定送出的請求位元組與 ecosystem nonce（`/oid4vci/api/ext/nonce/generate?type=ecosyst`）；與持有者 proof 無關。
- 官方 App 的簽章金鑰來自 APK 內的資產，不是裝置端產生後註冊；先前推測的手機 `api/did` 註冊流程沒有證據，已停用。`api/did` 是發行者查詢與機構 DID 註冊。
- appHash 是原始套件名稱，appPlatform 為 `Android`，keyId 是公鑰正規化 Base64 SPKI 文字的 SHA-256，Header 只有 alg 與 typ。
- 本錢包用自己的應用金鑰（建置時提供或產生）照這個格式簽章，不取出、不內建官方 App 的私鑰。官方平台是否接受第三方 App 沒有驗收，需要官方准入。
- 分析只做靜態解讀與 JNI helper 的模擬執行，沒有執行完整 APK；官方分割 APK 的簽章與 assetlinks 已核對。

## 文件

| 文件 | 內容 |
|---|---|
| [twdiw-1.0.14-signing-and-oid4vci.md](twdiw-1.0.14-signing-and-oid4vci.md) | 總覽：三種金鑰的來源、七欄 JWS、兩種 nonce、Token 與 Credential 請求、證據界線。先讀這一份 |
| [twdiw-1.0.14-issuance-review.md](twdiw-1.0.14-issuance-review.md) | 領卡與簽章的逐項核對：appHash 與 keyId 的映射、公鑰雙層 reader、nonce 與 grant_type 校正 |
| [twdiw-device-registration.md](twdiw-device-registration.md) | 裝置金鑰註冊的查證：APK 簽章與 assetlinks、SDK 呼叫鏈、frontend API、未確認的契約 |
| [twdiw-native-helper-emulation.md](twdiw-native-helper-emulation.md) | 以 unidbg 執行 JNI helper，確認 appPlatform 為 Android |
| [twdiw-jws-local-generation.md](twdiw-jws-local-generation.md) | 以自有測試金鑰建立相同格式的 JWS 並獨立驗簽（工具在 [tools/twdiw-jws](../../../tools/twdiw-jws/README.md)） |
| [twdiw-1.0.14-key-asset-usage.md](twdiw-1.0.14-key-asset-usage.md) | 四個金鑰資產的用途與尚未確定的部分 |
| [twdiw-1.0.14-assets.md](twdiw-1.0.14-assets.md)、[twdiw-1.0.14-asset-decoding-guide.md](twdiw-1.0.14-asset-decoding-guide.md) | 全部 19 個資產的盤點與逐層解碼（工具在 [tools/twdiw-assets](../../../tools/twdiw-assets/README.md)） |

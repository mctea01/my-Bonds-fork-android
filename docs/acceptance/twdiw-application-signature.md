# TWDIW 新版應用簽章與舊版領卡相容

日期：2026-11-03。使用者要求修正新版 TWDIW 領卡、保留舊版、支援合法應用金鑰 secrets／空值生成及 AAB。

> **後續（2026-11-13）：** 本文提到「待手動套用」的 CI 修改都已在 main：`build` 與 `desktop` 工作只在 push 時注入 `TWDIW_APP_PRIVATE_KEY`／`TWDIW_APP_PUBLIC_KEY`，nightly 附 release 與 debug 的 AAB。官方平台是否接受本錢包的應用簽章仍未驗收，見 [專案現況](../STATUS.md)。

## 問題與結果

原流程會丟掉 `/oid4vci` 前綴、對 appId 再做 SHA-256、使用小寫 android、增加 Header.kid，並嘗試未獲證實的 `/api/did/` 手機註冊與 holder-key fallback。即使本機驗簽成功，也不能據此符合 1.0.14 的應用簽章格式。

現在 `TwdiwApplicationKey` 提供獨立 P-256 應用 signer，Header 只有 alg／typ，Payload 七欄依 SDK adapter 順序輸出；appHash 使用本錢包原始 appId、Android 大小寫正確，keyId 由該應用公鑰的正規化 Base64 SPKI 文字摘要計算。bodyHash 綁定實際送出的 bytes。holder 金鑰仍只處理其持有者證明，不用來代替應用 signer。

沒有複製、解出或內建官方 APK 私鑰。程式使用本專案身分 `diw.wallet.app` 與本次建置版本；Secrets 功能供自行產生或合法取得的配對使用。

## 新舊流程選擇

- 預設為已確認的 moda 平台啟用應用簽章；其他具有正式契約的目標可經 `ecosystemSignatureHosts` callback 指定。
- `defaultEcosystemBase` 保留 issuer `/api/` 前的服務前綴，讓 `/oid4vci/api/ext/nonce/generate?type=ecosyst` 正確定位。
- 擴充端點 HTTP 404／410 時維持舊版不帶應用簽章的領卡；token `c_nonce`、無 nonce endpoint 的舊版 proof 流程保留。
- nonce endpoint 已存在但出現 5xx、拒絕代碼、無 nonce 或非 JSON 時回報錯誤，不默默當成舊版；協程取消保留。
- 有 proof nonce endpoint 的新平台仍採現有伺服器實測相容策略，優先取 endpoint nonce；應用 ecosystem nonce 與 holder proof nonce 完全分開。
- 不再呼叫推測性裝置註冊 POST，也沒有 holder-key fallback。`TwdiwDeviceKeys` 僅讀取／刪除舊紀錄，原 holder identity 與既有憑證不受遷移影響。

這裡的舊版支援指已驗證的 OID4VCI／token c_nonce／無生態系簽章擴充流程，不是宣稱存在另一種未確認的舊版應用簽章契約。

## 金鑰與建置

Gradle 的 `generateTwdiwApplicationKey` 呼叫 JDK 工具 `tools/twdiw/GenerateApplicationKey.java`：

- 同時給 `DIW_TWDIW_APP_PRIVATE_KEY`／`DIW_TWDIW_APP_PUBLIC_KEY`：接受 PKCS#8／SPKI PEM 或 Base64 DER，核對 P-256 及實際簽署／驗簽的配對。
- 兩值皆空：以 JDK 產生配對，保存在 ignored build 目錄至 clean，使同一工作目錄的 APK、AAB、桌面包共用 keyId。
- 只給一個、曲線／格式錯或配對不符：建置失敗，不取其他金鑰兜底。
- 產生的 Kotlin source 與 state 在 POSIX 下為 0600，任務不快取私鑰 source，不將 secrets 放入命令列／task inputs；紀錄只顯示來源與 public keyId。
- App 初始化另將實際建置配對匯入 Multipaz 並驗證配對。

規劃的 CI `TWDIW_APP_PRIVATE_KEY`／`TWDIW_APP_PUBLIC_KEY` secrets 對應上述環境變數，僅 push 注入，PR 使用生成測試配對；本次提交排除 workflow，需手動套用後才生效。這不保證在客戶端內嵌的私鑰無法擷取，詳細邊界與手動設定見 [發佈建置](../release.md)。

## AAB

AAB 已可透過下列 Gradle 命令建置，使用同 build type 的 signingConfig，正式 upload key 與既有 Android keystore secrets 相同。CI 同時建立並上傳 APK／AAB 的設定仍待使用者手動套用 workflow，本次提交不會自動新增 nightly AAB 產物。

```bash
./gradlew :app:assembleDebug :app:bundleDebug
./gradlew :app:assembleRelease :app:bundleRelease
```

工作區的 `.github/workflows/github-actions-ci.yml` 已備妥修改，YAML 已以拒絕重複 key 的 parser 核對 secrets、push 條件與 AAB 產物路徑；依使用者要求，該檔保留為未提交的本機變更。代理未手動觸發遠端 Actions 或發佈；推送 PR commit 可能依既有 workflow 自動啟動檢查。

## 已執行的本機驗證

| 驗證 | 結果 |
|---|---|
| `:core:compileKotlinJvm` | 通過 |
| `:app:compileKotlinDesktop` | 通過 |
| `TwdiwEcosystemSignatureTest` | 8 項通過：精確 wire／SPKI 文字指紋、獨立 signer、JDK P1363 獨立驗簽、body bytes、舊端點、錯誤處理、取消及 PEM 配對 |
| `TwdiwPlatformTest` | 19 項通過：含新版完整領卡的應用／holder 金鑰與 nonce 分離，以及沒有擴充的舊版領卡 |
| `DraftIssuersTest` | 2 項通過 |
| `tools/twdiw/test_generate_application_key.py` | 8 項通過：空值生成／重用、PEM／DER、錯誤配對／曲線、部分 secrets、毀損 state、私鑰不出現在錯誤訊息 |
| `TwdiwBuildKeyTest` | 1 項通過：建置產生的實際配對可匯入 App runtime 並簽署／驗證 JWS，公鑰文字指紋一致 |
| `WalletModelE2eTest.preAuthorizedIssuanceThenPresentation` | 1 項通過：App 初始化、既有領卡／出示與紀錄流程 |
| `:app:bundleDebug`／`:app:bundleRelease` | 均產生 AAB，通過 bundletool 1.18.1 結構驗證、jarsigner 驗簽及 ZIP CRC 檢查 |
| `:app:assembleDebug`／`:app:assembleRelease` | 均產生 APK，通過 Android build-tools apksigner 驗簽 |

測試使用自行產生金鑰、合成 nonce 與 MockEngine／本機測試服務，沒有向官方送出領卡或註冊請求。本機建置驗證以 `-Pdiw.zkNative=skip` 執行，不重建 Rust／NDK 原生庫；CI 的 `DIW_ZK_NATIVE=require` 與既有 ZK features 保留。

共 39 項相關測試通過（29 項協議、8 項建置金鑰、2 項 App runtime／流程），未宣稱執行整個 repo 的全部測試。本機紀錄位於 `/workspace/scratch/twdiw-protocol-tests.log`、`twdiw-key-build-tests.log`、`twdiw-final-checks.log`、`twdiw-aab-build.log`、`twdiw-aab-release-retry.log`，產物驗證結果為同目錄的 `twdiw-debug-aab-validation.json`、`twdiw-release-aab-validation.json`、`twdiw-apk-validation.json`；紀錄與報告不包含私鑰內容。

本機 AAB 使用既有預設 debug 憑證，未驗證正式 Play upload key。首次以專案預設 Gradle／獨立 Kotlin daemon 記憶體設定執行 release 時遭系統 OOM 終止；改成單 worker、Gradle 4 GiB 與 in-process Kotlin 後 release 建置成功，待手動套用的 CI Android 命令也採用此設定。既有 Kotlin 2.4／AGP 8.13.2 的 lint／R8 metadata 相容性警告仍存在，本次未升級工具鏈。

## 官方資產用途與限制

已確認 `dwapp201i_private.txt` 是目前 `dwapp-201i` 簽章 reader 的來源，`dwapp201i_public.txt` 的文字摘要用於 payload.keyId。無副檔名的兩份資產未找到具體成功呼叫鏈，不能斷言是舊版／測試／備援，沒有放進本專案的 signer 或環境選擇邏輯。兩個 private 資產均未解碼，也未做數學配對驗證。

詳見 [四個金鑰資產用途核對](../research/twdiw-1.0.14/twdiw-1.0.14-key-asset-usage.md)。正式平台是否接受本錢包身分與合法配對仍需官方准入及端到端驗收；目前沒有可用來宣稱正式領卡成功的實機 JWS 或合法正式測試配對。

# 零知識證明版型

這裡是隨 GitHub Release 發布的版型資料。新增或修改版型只要改這個資料夾，不需要更新 App。

- `zktls/`：zkTLS 查驗頁描述檔，一個檔案一個查驗頁（格式見 `core/src/commonMain/kotlin/diw/wallet/core/zktls/ZkTlsProfile.kt` 與 `docs/design/p4-circuits.md` 第 4.2 節）。
- `zkpdf/`：zkPDF 文件版型，一個檔案一個版型（格式在 WP3b 凍結公開輸入後定義）。

## 發布方式

Release workflow 執行 `./gradlew :test-servers:templatePack`，把 `build/zk-templates.jwt` 附加到 Release。
這個檔案是以本專案發布金鑰（GitHub Secret `ZK_TEMPLATES_KEY`，P-256）簽章的 JWS，版本為建置時間。
App 只接受 `ZkTemplatePack.TRUSTED_KEYS` 中公鑰簽的版型包，也不會安裝比已安裝版本舊的版型包。

## 規則

- 查驗頁的揭露規則要以真實回應在本機核對後才能加入；真實回應與查詢結果不進 repo。
- 揭露規則必須在值之後以分隔字元結束（例如結束標籤或換行），第一個群組是查驗方讀回的值。
- 版型只描述版面與揭露範圍，不會改變電路；電路仍以 App 內釘選的版本為準。

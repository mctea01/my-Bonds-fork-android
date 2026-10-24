# 零知識證明版型

這裡是隨 GitHub Release 發布的版型資料。新增或修改版型只要改這個資料夾，不需要更新 App。

- `zktls/`：zkTLS 查驗頁描述檔，一個檔案一個查驗頁（格式見 `core/src/commonMain/kotlin/diw/wallet/core/zktls/ZkTlsProfile.kt` 與 `docs/design/p4-circuits.md` 第 4.2 節）。
  目前有：`cn.chsi.xjbg.json`（學信網學籍在線驗證報告，新版中文報告）與 `cn.chsi.xjbg-en.json`（同一報告的英文版，
  需先在學信網申請英文版；另揭露線上驗證到期日），都只輸入在線驗證碼；`tw.gov.immigration.entryexit.json`（移民署入出國日期證明書驗證，
  輸入證號、序號與圖形驗證碼；揭露發證日期、姓名、國籍、性別、出生日期與最近一次出入境日期，不揭露證號與序號）。
- `zkpdf/`：zkPDF 文件版型，一個檔案一個版型（格式在 WP3b 凍結公開輸入後定義）。

## 發布方式

每次推送到 main，CI 的 test 工作會執行 `./gradlew :test-servers:templatePack`，release 工作再把 `zk-templates.jwt`
附加到 nightly Release（App 從 `releases/download/nightly/zk-templates.jwt` 下載）。
這個檔案是以本專案發布金鑰（GitHub Secret `ZK_TEMPLATES_KEY`，P-256 私鑰 PEM）簽章的 JWS，版本為建置時間；沒有設定 Secret 時略過。
App 只接受 `ZkTemplatePack.TRUSTED_KEYS` 中公鑰簽的版型包，也不會安裝比已安裝版本舊的版型包。

## 手動發布（替代來源）

nightly 沒有版型包或版型包有問題時，可在本機以同一把金鑰簽章，上傳到另一個 Release 作為替代來源。
App 每次更新都會讀 nightly 與 `zk-templates` 兩個 Release，安裝其中簽章有效且版本最新的一份（設定頁會顯示來源）。

1. 在 repo 根目錄產生並簽章（版本為當下時間，所以會比先前任何一份新）：
   - Linux／macOS：`ZK_TEMPLATES_KEY="$(cat zk-templates.key)" ./gradlew :test-servers:templatePack`
   - Windows PowerShell：`$env:ZK_TEMPLATES_KEY = Get-Content -Raw .\zk-templates.key; .\gradlew.bat :test-servers:templatePack; Remove-Item Env:ZK_TEMPLATES_KEY`
2. 輸出在 `test-servers/build/zk-templates.jwt`。
3. 在 GitHub 建立（或編輯）tag 為 `zk-templates` 的 Release（可標為 pre-release），上傳這個檔案，檔名維持 `zk-templates.jwt`；更新時刪除舊檔再上傳。
   App 下載位址為 `releases/download/zk-templates/zk-templates.jwt`。

## 從檔案匯入

App 設定「零知識證明」頁的「從檔案匯入」可匯入 `zk-templates.jwt` 或含有它的 ZIP（例如 CI 產物），簽章與版本檢查和線上更新相同。

測試環境另可匯入未簽章的查驗頁描述檔（單一查驗頁 JSON、測試伺服器 `/zktls/profiles` 的回應，或未簽章的版型包內容），
只在測試環境提供，查驗時附在請求中；持有端也須開啟測試環境才會接受，並標示為測試查驗頁。與已簽章查驗頁同名的不會匯入。

產生金鑰（私鑰只放進 Secret，公鑰加入 `TRUSTED_KEYS`）：

```
openssl ecparam -name prime256v1 -genkey -noout -out zk-templates.key
openssl ec -in zk-templates.key -pubout -out zk-templates.pub
```

## 在本機核對查驗頁

`drafts/zktls/` 放尚未核對的描述檔草稿，不會打包。用自己的資料在本機核對：

```
./gradlew -q :test-servers:checkProfile -Pprofile=templates/zktls/cn.chsi.xjbg.json
```

工具會照描述檔送出與錢包完全相同的請求（只用 TLSNotary 支援的 TLS 1.2 ECDHE AES-128-GCM），再以持有端的揭露規劃與查驗方的判定檢查回應，
列出 TLS 版本與加密套件、網站憑證、回應大小、狀態規則與每個欄位是否對到。輸入從主控台讀取，不會寫入任何地方（經 Gradle 執行時輸入會顯示在畫面上）。
欄位值預設不顯示，加 `-Pshow` 才顯示；加 `-Psave=build/page.html` 會把完整回應存在本機以便調整規則，檔案含查詢結果，不可放進 repo。
調整規則時加 `-Pfrom=build/page.html` 可用存下的回應離線核對，不再連網站（需要驗證碼的查驗頁只要實際查詢一次）。
結果為「通過」後再把描述檔移到 `zktls/`。

需要圖形驗證碼的查驗頁（`prepare.type` 為 `captcha`）：工具會先開網頁取得工作階段，把驗證碼圖片存成暫存檔並嘗試開啟，再請你輸入。
查一次後加 `-Psave` 存下結果頁，之後以 `-Pfrom` 離線調整規則，不必每次重填驗證碼。

## 規則

- 查驗頁的揭露規則要以真實回應在本機核對後才能加入；真實回應與查詢結果不進 repo。
- 揭露規則必須在值之後以分隔字元結束（例如結束標籤或換行），第一個群組是查驗方讀回的值。
- 網站依 User-Agent 回傳不同版面時，描述檔要在 `headers` 固定 User-Agent，規則對應那個版面（學信網固定 `Mozilla/5.0`，回傳桌面版）。
- 以分塊傳輸（chunked）回應時，規則對的是去掉分塊標頭後的內容；欄位被分塊切開時，揭露範圍會包含中間的分塊標頭，查驗方讀取前會去掉。
- 查詢輸入（驗證碼、序號等）所在的列不可作為欄位；結果頁常把輸入值帶回表單欄位或結果列表（移民署結果頁的列表與明細都有證號與序號），規則不可對到那裡。
- `prepare.type` 為 `captcha` 時，`page` 是先開的表單頁，`image` 是驗證碼圖片，`input` 是填驗證碼的輸入，`cookies` 是工作階段 Cookie 名稱。
  圖片由持有端直接向網站取得，Cookie 放在不揭露的請求標頭，查驗方都看不到。
- 版型只描述版面與揭露範圍，不會改變電路；電路仍以 App 內釘選的版本為準。

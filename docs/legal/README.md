# 法律聲明

本資料夾是 App 內法律文字的網頁版，內容由 `app/src/commonMain/kotlin/diw/wallet/app/legal/LegalTexts.kt` 產生，兩者必須一致（`LegalDocumentsTest` 會檢查）。修改文字時改 `LegalTexts.kt`，再以 `DIW_UPDATE_LEGAL=1 ./gradlew :app:desktopTest --tests 'diw.wallet.app.legal.*'` 重新產生本資料夾的檔案；內容有實質變更時調高該文件的 `version`，使用者下次開啟 App 會被要求重新確認。

英文譯本在 [en/](en/)（由 `LegalTextsEn.kt` 產生，App 介面為英文時顯示），內容與中文原文逐節對應，兩者不一致時以中文原文為準。修改文字時兩種語言都要改；同一文件的兩種語言共用 `version`。英文隱私權政策網址可用於英文商店資訊：`docs/legal/en/privacy-policy.md`。

| 文件 | 內容 |
|---|---|
| [privacy-policy.md](privacy-policy.md) | 隱私權政策（應用程式商店的隱私權政策網址） |
| [terms-of-use.md](terms-of-use.md) | 用戶協議 |
| [twdiw.md](twdiw.md) | 數位憑證皮夾（TWDIW）專門聲明 |
| [microsoft-verified-id.md](microsoft-verified-id.md) | Microsoft Entra Verified ID 專門聲明 |
| [mobile-moica.md](mobile-moica.md) | 行動自然人憑證專門聲明 |
| [mydata.md](mydata.md) | MyData 專門聲明 |
| [zkpassport.md](zkpassport.md) | zkPassport 專門聲明（查驗他人的 zkPassport 證明，以及以已保存的電子護照回應請求） |

## 同意的規則

- 首次啟動依序顯示歡迎頁（列出接下來要確認的內容，標明哪些必要、哪些可選）、確認頁與結果頁。確認頁把所有待決定的文件放在同一頁：用戶協議與隱私權政策標為「必要」，以一個勾選項「我已閱讀並同意用戶協議與隱私權政策」同意，兩份文件的重點摘要列在上方；各專門聲明標為「可選」，各有一個預設不勾選的勾選項「我同意（聲明名稱）並啟用相關功能」，附用途、營運者（連到營運者的官方說明頁，`Integration.operatorUrl`，以瀏覽器開啟）與可展開的重點摘要（勾選時自動展開）。勾選項中的文件名稱是連結，點選後在同一頁上方顯示全文，返回後勾選狀態不變。按「同意並繼續」一次記錄所有選擇：未勾選的專門聲明記錄為不同意。結果頁分開列出必要文件與可選服務。完成前 App 不處理任何連結或請求，也不在背景連線。
- 聲明的法律文字與版本不因同意畫面的形式改變。
- 專門聲明不同意時停用該服務：不連線其營運者，入口顯示為停用列並可開啟聲明；已保存的證件與文件保留，標準協議與其他功能不受影響。
- 同意紀錄（版本、是否同意、時間）存在裝置的 `DiwLegal` 表格；文件 `version` 提高後，只重新詢問有變更的文件。
- 可在「設定 > 法律聲明與同意」重新閱讀、撤回或同意；因連結需要而開啟的聲明，同意後會接著處理該連結。

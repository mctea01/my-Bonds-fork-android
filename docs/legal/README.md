# 法律聲明

本資料夾是 App 內法律文字的網頁版，內容由 `app/src/commonMain/kotlin/diw/wallet/app/legal/LegalTexts.kt` 產生，兩者必須一致（`LegalDocumentsTest` 會檢查）。修改文字時改 `LegalTexts.kt`，再以 `DIW_UPDATE_LEGAL=1 ./gradlew :app:desktopTest --tests 'diw.wallet.app.legal.*'` 重新產生本資料夾的檔案；內容有實質變更時調高該文件的 `version`，使用者下次開啟 App 會被要求重新確認。

| 文件 | 內容 |
|---|---|
| [privacy-policy.md](privacy-policy.md) | 隱私權政策（應用程式商店的隱私權政策網址） |
| [terms-of-use.md](terms-of-use.md) | 用戶協議 |
| [twdiw.md](twdiw.md) | 數位憑證皮夾（TWDIW）專門聲明 |
| [microsoft-verified-id.md](microsoft-verified-id.md) | Microsoft Entra Verified ID 專門聲明 |
| [mobile-moica.md](mobile-moica.md) | 行動自然人憑證專門聲明 |
| [mydata.md](mydata.md) | MyData 專門聲明 |
| [zkpassport.md](zkpassport.md) | zkPassport 專門聲明（功能上線前不會在 App 內詢問） |

## 同意的規則

- 首次啟動依序顯示歡迎頁、用戶協議與隱私權政策（兩者都同意才能使用）、各專門聲明（逐項同意或不同意）與結果頁。完成前 App 不處理任何連結或請求，也不在背景連線。
- 專門聲明不同意時停用該服務：不連線其營運者，入口顯示為停用列並可開啟聲明；已保存的證件與文件保留，標準協議與其他功能不受影響。
- 同意紀錄（版本、是否同意、時間）存在裝置的 `DiwLegal` 表格；文件 `version` 提高後，只重新詢問有變更的文件。
- 可在「設定 > 法律聲明與同意」重新閱讀、撤回或同意；因連結需要而開啟的聲明，同意後會接著處理該連結。

# 新增與維護介面翻譯

性質：現行。2026-11-26 建立。說明怎麼手動加入一種新語言、怎麼維護簡體中文，之後改用 Weblate 或其他翻譯平台時要怎麼設定，以及 Google Play 商店資訊的翻譯（第 5 節）。字串的程式規則（`stringResource`、`tr`、`ct`）見 [i18n.md](../design/i18n.md)。

## 1. 翻譯檔在哪裡

| 檔案 | 內容 |
|---|---|
| `app/src/commonMain/composeResources/values/strings.xml` | 英文，預設檔，也是所有翻譯的來源（鍵的清單以它為準） |
| `app/src/commonMain/composeResources/values-zh/strings.xml` | 繁體中文（`zh-TW`），與英文同時維護 |
| `app/src/commonMain/composeResources/values-zh-rCN/strings.xml` | 簡體中文（`zh-CN`），由繁體中文轉換後校訂，見第 3 節 |
| `app/src/commonMain/composeResources/values-<語言>/strings.xml` | 其他語言，可以只翻一部分 |
| `app/src/androidMain/res/values-<語言>/strings.xml` | Android 系統顯示的少數字串（NFC 服務名稱、zkPassport 舊版電路元件名稱），可省略 |

格式是 Android 字串資源（Compose Multiplatform 與 Android 共用），每行一個 `<string name="鍵">文字</string>`，UTF-8。

規則：

- 資料夾名稱決定語言：`values-ja`（日文）、`values-pt-rBR`（巴西葡萄牙文）、`values-b+sr+Latn`（拉丁字母塞爾維亞文，BCP 47 寫法）。地區用 `-r` 加兩個大寫字母，有文字（script）時用 `b+` 寫法。
- 檔案缺少的鍵會顯示英文，所以新語言可以先翻常用畫面，之後再補。
- 每個鍵都必須存在於英文檔，佔位符（`%1$s`、`%2$d`）要和英文相同，可以調換位置；字串頭尾的空白要保留（片段會和其他文字接起來）。
- `&lt;h2&gt;` 這類標記保持原樣，只翻譯標記之間的文字。
- 規格原文（憑證狀態 `revoked`、演算法名稱、`B-LTA` 等）、產品與機關名稱照原文，見 [i18n.md](../design/i18n.md) 第 2 節與第 3 節的術語表。

## 2. 手動加入一種語言

以日文為例（在 repo 根目錄執行，Windows 先 `chcp 65001`）：

1. 建立翻譯檔：

   ```
   python3 tools/i18n/i18n.py new ja 日本語
   ```

   會寫出 `values-ja/strings.xml`，只含 `language_tag`（`ja`）與 `language_self`（語言自稱，顯示在語言選單）。地區或文字變體照第 1 節的資料夾寫法，例如 `new pt-rBR "Português (Brasil)"`。

2. 匯出待翻譯清單：

   ```
   python3 tools/i18n/i18n.py missing ja ja.tsv
   ```

   `ja.tsv` 是 UTF-8 的 Tab 分隔檔，欄位為鍵、英文、繁體中文（參考用）、譯文（空白）。把譯文填在第 4 欄；換行寫成 `\n`。可以用試算表編輯，存檔時選 UTF-8 的 Tab 分隔文字。不需要的列留空即可。

3. 匯入譯文：

   ```
   python3 tools/i18n/i18n.py import ja ja.tsv
   ```

   鍵不存在或佔位符不符時會停下並指出第幾行。可以重複第 2、3 步：`missing` 只列出還沒翻的字串。

4. 檢查：

   ```
   python3 tools/i18n/i18n.py status
   ./gradlew :app:desktopTest --tests '*LocalizationTest*'
   ```

   `status` 列出每個翻譯檔的語言、已翻譯數量與錯誤（有錯誤時結束碼為 1）。

5. （可選）Android 系統字串：複製 `app/src/androidMain/res/values/strings.xml` 到 `values-ja/`，刪掉 `app_name` 並翻譯其餘各行。

完成後不必改程式：建置時 `generateAppLanguages` 讀取所有翻譯檔，語言自動出現在「設定 > 顯示與語言」與首次啟動的語言選單，Android 13 以上的系統「App 語言」清單（`locales_config.xml`）也會列出。

### 法律文件

法律文件本文只有繁體中文原文（`LegalTextsZh`）與英文譯本（`LegalTextsEn`）。新語言以字串 `legal_language` 選擇顯示哪一份：不填時沿用英文檔的 `en`（英文譯本），填 `zh` 時顯示繁體中文原文（簡體中文就是如此，並以 `legal_translation_note` 說明）。要提供該語言自己的法律譯本，需要在程式加入新的本文與網頁版（`docs/legal/`），並讓 `LegalDocumentsTest` 檢查節數一致，屬於開發工作而不是翻譯工作。

### 跟隨系統時用哪個語言

跟隨系統時，介面依裝置語言挑選翻譯檔：先找語言與地區都相同的（`zh-CN` 用 `values-zh-rCN`），再找同語言沒有地區的（`zh-TW`、`zh-HK` 用 `values-zh`），都沒有就用英文。新加坡、馬來西亞等使用簡體中文但地區不是 `CN` 的裝置會顯示繁體中文，可以在 App 內改選「简体中文」。

## 3. 簡體中文

`values-zh-rCN` 由繁體中文以 [OpenCC](https://github.com/BYVoid/OpenCC) 的 `tw2sp`（台灣用詞轉中國大陸用詞，例如「軟體」改「软件」、「檔案」改「文件」、「文件」改「文档」）轉換，`tools/i18n/i18n.py` 的 `HANS_KEEP` 固定少數詞的寫法（「數位憑證皮夾」、「數位發展部」等名稱照原名，「離線」、「啟用」、「複製」、「查詢」、「預設」改為大陸常用的「离线」、「启用」、「复制」、「查询」、「默认」）。OpenCC 只在開發時使用，不隨 App 發佈。

- 安裝：`pip install opencc`。
- `python3 tools/i18n/i18n.py apply ...` 搬移新字串時會一併轉換寫入簡體中文；沒有安裝 OpenCC 時會提示改跑 `hans`。
- 手動新增英文與繁體中文字串後，執行 `python3 tools/i18n/i18n.py hans`：只補上簡體中文缺少的鍵，並移除英文檔已沒有的鍵，已經存在的譯文（包括人工修改過的）不會被覆蓋。
- 繁體中文改了某個字串時，用 `python3 tools/i18n/i18n.py hans 鍵1 鍵2` 重新轉換這幾個鍵。
- 轉換結果可以直接在 `values-zh-rCN/strings.xml` 修改，之後的 `hans` 不會改回。
- `LocalizationTest` 要求簡體中文與繁體中文的鍵相同，且不含常見的繁體專用字。

## 4. 改用 Weblate

翻譯檔的格式與路徑本來就是 Weblate 支援的單語 Android 字串資源，接上後不必改程式或搬檔案。

### 元件設定

| 欄位 | 值 |
|---|---|
| 檔案格式 | Android String Resource |
| 檔案遮罩 | `app/src/commonMain/composeResources/values-*/strings.xml` |
| 單語基礎語言檔 | `app/src/commonMain/composeResources/values/strings.xml` |
| 新翻譯的範本 | 同上 |
| 來源語言 | English |
| 語言代碼樣式 | Android 樣式（`pt-rBR`） |
| 新增翻譯 | 建立新的語言檔 |

Android 系統字串另建一個元件：檔案遮罩 `app/src/androidMain/res/values-*/strings.xml`，基礎檔 `app/src/androidMain/res/values/strings.xml`（`app_name` 標成唯讀，或在 Weblate 設為不翻譯）。

### 對應現有的中文檔

Weblate 依資料夾名稱辨識語言。現有的 `values-zh` 是繁體中文、`values-zh-rCN` 是簡體中文，請在 Weblate 專案設定的「語言別名」加上：

```
zh:zh_Hant,zh-rCN:zh_Hans
```

否則 `values-zh` 會被當成未指定字體的中文。

### Weblate 產生的檔案

- `language_tag` 與 `language_self` 標了 `translatable="false"`，Weblate 建立的語言檔可能沒有這兩個字串。沒有時建置改由資料夾名稱推得語言（`values-ja` 是 `ja`），語言選單顯示 Java 提供的語言自稱（`ja` 是「日本語」）；要換顯示名稱，在該檔手動加上 `language_self`。
- Weblate 推送時建議推到分支並開 PR（或用 Weblate 的 GitHub 拉取請求推送方式），讓 CI 的 `LocalizationTest` 檢查鍵與佔位符；不要直接推 `main`。
- 鍵的新增、改名與刪除仍在程式 PR 完成（英文檔是基礎檔）；Weblate 只改各語言的譯文。PR 合併後 Weblate 會依基礎檔更新待翻譯清單。
- 若簡體中文也交給 Weblate 維護，可以繼續用 `hans` 補缺：它不覆蓋已有的譯文。

### 其他平台

Crowdin、Transifex、Lokalise、POEditor 等平台也支援 Android XML，來源檔與翻譯檔路徑照上表設定即可；資料夾名稱要符合第 1 節的寫法（多數平台可自訂語言代碼對應，例如把 `zh-CN` 對應到 `zh-rCN`）。不使用平台時，以第 2 節的 TSV 交給譯者，也可以用試算表或其他電腦輔助翻譯工具處理。

## 5. Google Play 商店資訊

商店的標題、簡短說明、完整說明與版本資訊的固定文字也是翻譯檔，在 `distribution/play/listing/<Play 語言代碼>/`（`zh-TW` 原文、`en-US`、`zh-CN`），規則與字數上限見 [google-play.md](../google-play.md) 第 5.2 節。

- 新增語言：建立 `distribution/play/listing/<語言代碼>/`（Play 的代碼，例如 `ja-JP`），放入 `title.txt`、`short_description.txt`、`full_description.txt`，以及版本資訊的 `release_notes_header.txt`、`release_notes_more.txt`、`release_notes_footer.txt`（分別保留 `{version}`、`{count}`、`{url}`）。它和介面翻譯是分開的：介面有某個語言不代表商店也要有，反之亦然。
- 簡體中文：`python3 tools/i18n/i18n.py play-hans` 從繁體中文補上缺的檔案，`play-hans 檔名` 重新轉換指定的檔案。
- 檢查：`python3 -I tools/play-store.py check`，CI 的 `LocalizationTest` 也會檢查。
- Weblate：另建一個元件，檔案格式選「App store metadata files」，檔案遮罩 `distribution/play/listing/*`，單語基礎語言檔 `distribution/play/listing/zh-TW`（來源語言為繁體中文；也可以改以 `en-US` 為基礎），語言代碼樣式選 BCP 樣式（`zh-TW`）。每個檔案是一個翻譯單位，佔位符要保留。

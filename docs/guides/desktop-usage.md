# 電腦版的版面與鍵盤操作

現行。適用 JVM 版與 GraalVM 原生版（Windows、Linux、macOS jar），程式在 `app/src/desktopMain/kotlin/diw/wallet/app/desktop/`（視窗與快捷鍵在 `DesktopWindow.kt`）與共用的 `ui/UiKit.kt`。

## 版面

| 情況 | 行為 |
|---|---|
| 寬視窗（寬度 600 dp 以上且不明顯比高度窄） | 主畫面的五個分頁改為左側導覽列，內容區最寬 840 dp 並置中，不會被拉成一長條 |
| 窄視窗或直式 | 維持底部導覽列 |
| 一列多個按鈕 | 放不下時自動換行，不再需要左右捲動；按鈕之間保留間距方便點選 |
| 長頁面 | 右側顯示可拖曳的捲軸；成績單等寬表格下方顯示水平捲軸 |
| 視窗大小 | 記住上次的大小、位置與最大化狀態（Java Preferences 節點 `diw/wallet/app/window`），最小 360 x 560 dp |

Android 版共用同一套版面元件：手機直式不變，平板或橫向寬螢幕同樣改用側邊導覽列；捲軸只在電腦版顯示。

## 鍵盤與滑鼠

| 按鍵 | 動作 |
|---|---|
| Esc、Alt+左方向鍵、滑鼠側鍵「上一頁」 | 返回，等同 Android 的返回鍵（流程中會走相同的取消步驟） |
| Ctrl+1 至 Ctrl+5（macOS 為 Command） | 切到文件、檔案、使用、驗證、紀錄分頁；在其他畫面時先依序返回主畫面 |
| Ctrl+,（macOS 為 Command+,） | 開啟設定 |
| 解鎖畫面 Enter | 第一次設定時從 PIN 跳到確認欄，其餘情況直接解鎖；開啟時游標自動在 PIN 欄 |
| PIN 對話框 Enter | 送出 |
| Tab、Shift+Tab | 在欄位與按鈕間移動焦點（Compose 內建） |

快捷鍵在焦點元件處理之後才生效，所以文字欄位內的 Esc、方向鍵、Ctrl+A／C／V 等仍由欄位自己處理。

## 同一時間只能開一個

同一個資料夾（Windows 為 `%APPDATA%\DIW-MY-WALLET`）同一時間只能由一個 App 使用，JVM 版與原生版也共用這個資料夾。第二個啟動時會提示已在執行並結束，避免兩邊同時寫入資料庫而出現 `SQLITE_BUSY`（database is locked）。看不到視窗卻提示已在執行時，從工作管理員結束殘留的程序即可。

## 原生版的錯誤紀錄

原生版（Windows 沒有主控台）遇到結束 App 的錯誤時會顯示對話框，並把堆疊寫到資料夾的 `logs/error-*.txt`（保留最新 20 份），回報問題時附上即可。

# TWDIW 1.0.14 native helper 雲端模擬驗證（2026-11-02）

## 結果與範圍

在使用者要求於雲端執行後，已以 unidbg 0.9.9／Unicorn2 成功載入使用者提供、先前已核對官方簽章分包內容的 `libd186.so`，執行其初始化與 `JNI_OnLoad`，取得 98 筆 native 註冊。四個目標 helper 均已綁到實際函式位址、實際呼叫並核對結果。依 DTO 原始常數與實際 helper 回傳值還原的 appPlatform 是 **`Android`**，大小寫如列，狀態由 candidate_only 升為 **native_emulation_verified**。

本輪是離線 native 執行驗證，與先前純靜態分析不同；沒有安裝或執行完整官方 APK，沒有讀取私鑰資產、產生官方應用簽章或向正式服務送出請求。這項結果未驗收官方服務對第三方皮夾的准入。

## 雲端環境與儲存

- 主機：雲端 Linux x86_64；Temurin Java 21.0.13。
- 框架：Maven Central 發行的 `unidbg-android:0.9.9`、`unidbg-unicorn2:0.9.9`。
- ARM64 以 Unicorn2 模擬，AndroidResolver 使用框架附帶 API 23 相依庫；不是完整 Android OS 或裝置相容性測試。
- 本次新增框架、Maven、相依快取、編譯與紀錄總計約 **104 MB**；不計先前已存在的研究 APK 與工具。
- 設定時雲端可用空間約 5.5 GB，執行後約 5.4 GB。使用者設備不需要安裝模擬器或下載這些相依套件。

Maven 下載初次遇到 Java 憑證信任錯誤，改指定環境的 `/etc/ssl/certs/java/cacerts` 後完成；TLS 驗證保持開啟。框架執行於本機 JVM，guest 網路 syscall 由自訂 syscall handler 回拒；guest 檔案開啟請求由 IOResolver 回拒。該次 native 執行沒有觀察到 guest socket 呼叫，三項檔案要求 `/dev/__properties__`、`/proc/stat`、`/sys/fs/selinux/enforce` 被拒絕後，初始化仍完成。

## 輸入與註冊映射

輸入 `libd186.so` 大小 1,612,328 bytes，SHA-256：

```text
58965369093f15eaaad64181744a3bfb2e3e30d9d79b2899a5eec58ce50afbd5
```

harness 啟動前檢查此完整雜湊。該次模擬載入基址為 `0x12000000`；下表均為相對於 library 基址的位址，適用這份輸入檔，不是跨版本固定值。

| Java native 方法 | RegisterNatives 回傳映射 | 實際觀察 |
|---|---:|---|
| `o.yKMXuur2$ISyARpnL.n(Object,int,int):void` | `0xca010` | 將和數對 65535 的餘數寫入 state 的 char 欄位；helper 呼叫執行到 `0x1608d4` |
| `o.N3Kf59pP$A6APTThS.l(int,int):char` | `0xa09bc` | 傳回和數除以 65535 的商；helper 呼叫執行到 `0x59458` |
| `o.Mmy8OPSI.o(Object):int` | `0x85558` | index 為 0–7 時，傳回 `(index+2)%4` |
| `o.iJeuXD.m(Object):int` | `0x13eecc` | index 為 0–7 時，傳回 `(index+3)%4` |

映射取自目標 `JNI_OnLoad` 實際呼叫模擬器 `RegisterNatives` 的 name／signature／fnPtr 資料，非由符號名稱猜測。unidbg 日誌的 `Find native function Java_*` 是框架生成的查找標籤，不表示 ELF 新增或原本存在同名 Java_* 匯出。

## Java 反射呼叫與 native 目標的核對

另外直接還原 stage-a ClassLoader 的 class-name 表，核對 `IeeqwtWx` string helper 四次反射解析的三參數；不是僅採用先前報告給定的 class 名稱。

| 方法 | 長度 | 表偏移 | char 參數 | 解碼 class |
|---|---:|---:|---:|---|
| o | 10 | 832 | 0 | `o.Mmy8OPSI` |
| m | 8 | 807 | 47903 | `o.iJeuXD` |
| n | 19 | 3727 | 47528 | `o.yKMXuur2$ISyARpnL` |
| l | 19 | 3234 | 0 | `o.N3Kf59pP$A6APTThS` |

解碼使用 `mUHNhY6P` 的 3,961-char 表與其實際 XOR／索引乘法算式，對應結果再與上述註冊紀錄交叉比對。因而閉合「DTO 反射參數 → Java native 方法 → 註冊函式指標 → 執行結果」鏈。

## helper 與字串還原

商數 helper 的五組 `(a,b) → result` 實測：

```text
(0,0)          → 0
(65534,1)      → 1
(65535,1)      → 1
(32718,99)     → 0
(123456,54321) → 2
```

另外以 index 0–7 核對兩個索引 helper，並在每組狀態以 `n(state,65534,5)` 驗證 state char 為 4。這些比較在 harness 中是 assertion；不同結果會使執行失敗。

最後依 `IeeqwtWx$ebZ5jVfe` 的合成建構子與 Java string helper 還原 7 個字元。四槽初值、密文、步進乘數、seed 與輸出 mask 均取自既有 DEX；每一輪的索引、餘數與商數均呼叫剛註冊的真實 native 方法，不使用先前候選模型替代其回傳值。

| index | first | second | remainder | quotient | 輸出 codepoint |
|---:|---:|---:|---:|---:|---:|
| 0 | 2 | 3 | 32565 | 9812 | 65 |
| 1 | 3 | 0 | 27320 | 20036 | 110 |
| 2 | 0 | 1 | 6341 | 14034 | 100 |
| 3 | 1 | 2 | 7674 | 18315 | 114 |
| 4 | 2 | 3 | 42210 | 16258 | 111 |
| 5 | 3 | 0 | 62821 | 13639 | 105 |
| 6 | 0 | 1 | 26986 | 3165 | 100 |

串接 codepoint 得到 `Android`。harness 最後對還原文字作 assertion，但該文字不參與前面的字元計算。

## harness 的模型邊界

unidbg 0.9.9 原有的 GetCharField／SetCharField 尚未實作，因此 harness 補上這兩個 JNI 介面的欄位讀寫，並以 Map 代表 `Bq1Hr1VJ` 的 int／char 欄位。GetIntField 提供輸入 index；SetCharField 保存 native 方法提供的真實值。這些補充只是 JNI 記憶體物件模型，沒有將 n／l／o／m 的計算替換為 Java 公式，也沒有修補目標 SO。

算術基本區塊的追蹤在模擬器 backend 進行，非於手機附加 Frida。初始化與 helper 的執行具超時限制；此次兩次程序均正常完成。成功驗證範圍為這四個 helper 與該常數，沒有推論整個 App 已可在模擬器運作或所有 int 輸入皆已窮舉驗證。

## 重現產物

工作目錄：`/workspace/scratch/twdiw-unidbg/`。

- `src/main/java/research/JniProbe.java`：完整 harness，含輸入雜湊檢查、IO／網路限制、JNI char 欄位支援、註冊查找、assertions 與字串還原。
- `run-01.log`：初次成功載入、註冊及 helper 呼叫。
- `run-02.log`：加入算術區塊追蹤與完整字串還原的成功紀錄。
- `jni-registrations.json`：98 筆完整映射。
- `reflection-bindings.json`：四個反射 class-name 對照。
- `native-verification-result.json`：輸入／程式／紀錄雜湊、方法位址、測例、字元序列及驗證狀態。

精簡交接包：`/workspace/scratch/twdiw-native-helper-verification.zip`。包含 harness、相依宣告、重現說明與證據，不含完整相依快取、原始 APK、目標 SO 或金鑰資產。先前 v2 靜態分析包保持不變；其中 candidate_only JSON 是當時的歷史紀錄，本輪結果另存，不覆蓋原證據。

研究脈絡見 [分析附件核對](twdiw-1.0.14-issuance-review.md) 與 [裝置金鑰註冊查證](twdiw-device-registration.md)。

# 第三方元件清單（關於頁）

現行文件。App 的「設定 > 關於 > 第三方元件與授權」列出這個版本實際包含的每個第三方元件與授權全文，清單由建置產生，不手寫在程式碼裡。法律上的總表仍是根目錄的 [NOTICE](../NOTICE)，兩者要一起維護。

## 清單從哪裡來

`app/third-party.gradle.kts` 的 `generateThirdPartyAndroid` 與 `generateThirdPartyDesktop` 在建置時合併三個來源，寫成平台專屬的 Compose 資源 `files/third-party.json`，並附上建置當下的 `NOTICE.txt` 與 `LICENSE.txt`（App 內直接顯示，不再連到 GitHub 的 main）：

| 來源 | 內容 | 怎麼來 |
|---|---|---|
| Maven 相依 | Android 取 `releaseRuntimeClasspath`，桌面版取 `desktopRuntimeClasspath`，只列實際有檔案的模組 | POM 的名稱、網址、組織與授權（沒有時往上找 parent POM），加上 jar／AAR 內的 `LICENSE`、`NOTICE` 等檔案 |
| Rust crate | 每個打包進去的原生程式庫所連結的 crate（不含 proc-macro 與只在建置時用的 crate，也不含本專案自己的 crate） | `native/build.sh` 建好每個程式庫後以 `native/third_party.py` 寫出 `<程式庫>.third-party.json`（`cargo tree` 取 crate 集合，`cargo metadata` 找原始碼目錄讀授權檔），也記下該程式庫連結的執行階段（`rust-std`、`barretenberg-6`、`ndk-libcxx`、`llvm-mingw` 等）與功能 |
| 精選項目 | 不是 Maven 或 crate 的元件：C/C++ 程式庫、執行階段、模型、電路、內建資料、使用時下載的資產、安裝檔附帶的執行環境 | 本目錄的 `components.json`；`when.runtime`／`when.feature` 依實際打包的原生程式庫決定是否列入，`platforms` 決定平台，`files` 附上 repo 內的授權或聲明檔 |

沒有原生程式庫的建置（`-Pdiw.zkNative=skip`）就不會列出 crate 與只在原生程式庫裡的項目。CI（`GITHUB_ACTIONS=true`）中若有程式庫缺少 `.third-party.json` 就失敗；本機只警告。`*.third-party.json` 不會被打包進 jar（`core/build.gradle.kts` 排除）。

## 授權

`components.json` 的 `licenses` 是唯一允許的授權表（SPDX 識別碼，非 SPDX 的用 `LicenseRef-`），每一個都要有 `licenses/<識別碼>.txt` 全文。SPDX 授權的全文取自 [spdx/license-list-data](https://github.com/spdx/license-list-data) 的 `text/`；`LicenseRef-BouncyCastle` 取自 bcprov jar 的 `META-INF/LICENSE.md`；`LicenseRef-Android-SDK`、`LicenseRef-PlayCore` 取自 developer.android.com 的條款頁（檔尾註明來源）。

- Maven 的 POM 授權文字以 `mavenLicenseAliases`（不分大小寫的正規表示式，比對「名稱 | 網址」，第一個符合的生效）對應到識別碼；POM 沒寫授權的模組用 `mavenOverrides`（`群組:名稱` 或 `群組:*`）。
- crate 的授權用 Cargo 宣告的 SPDX 運算式（`MIT/Apache-2.0` 視為 `MIT OR Apache-2.0`）；沒有宣告的用 `crateOverrides`（名稱可含 `*`）。
- 任何對應不到、或不在授權表的授權都會讓建置失敗並列出元件，必須先在這裡補上，所以新相依不會在沒有授權資料的情況下發佈。

## 新增或移除第三方元件時

1. Maven 相依與 crate 會自動出現；只有建置失敗說授權未知時才需要改 `components.json`。
2. 不是 Maven 或 crate 的元件（新的 C/C++ 程式庫、模型、電路、內建資料、執行環境）在 `components.json` 的 `components` 加一項，`description` 至少要有 `en` 與 `zh`（簡體中文介面顯示 `zh`，其他語言顯示 `en`）。
3. 同一個 PR 更新 `NOTICE`。
4. 驗證：`./gradlew :app:generateThirdPartyDesktop :app:generateThirdPartyAndroid -Pdiw.zkNative=skip`，以及 `:app:desktopTest --tests diw.wallet.app.ThirdPartyTest`。畫面截圖：`DIW_SCREENSHOTS=<資料夾> ./gradlew :app:desktopTest --tests '*WalletModelE2eTest.thirdPartyScreenshots'`。

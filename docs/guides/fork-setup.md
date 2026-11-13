# 新 Fork 的配置指南

性質：現行。對象是把這個 repo fork 出去、要在自己的 GitHub 帳號下建置、開發或發佈的人。內容分三層：只想讓 CI 跑起來（第 1 節）、要有固定簽章的建置（第 2 節）、要以自己的名義發佈（第 3 節）。本機建置的需求見 [README](../../README.md#建置與測試)，發佈檔案與金鑰的細節見 [release.md](../release.md)。

## 1. 讓 CI 跑起來

不設定任何 secret 也能建置：CI 會用臨時金鑰，產物可安裝、可測試，只是每次簽章都不同。

1. **啟用 Actions。** Fork 的 Actions 預設關閉，到 Actions 頁按啟用。排程的 workflow（`codeql.yml` 每週、`update-trust-roots.yml` 每月）在 fork 上還要各自到該 workflow 的頁面按一次 Enable。
2. **Settings > Actions > General > Workflow permissions。** 勾選「Allow GitHub Actions to create and approve pull requests」，`update-trust-roots.yml` 才能開 PR。發佈 nightly 與版型包的工作已在 workflow 內宣告 `contents: write`，不必把預設權限改成讀寫。
3. **Settings > General > Pull Requests。** 只留 Squash merge（本專案的 PR 一律 Squash 合併，版本的修訂號是 main 上的 commit 數）。
4. **Settings > Code security。** Code scanning 不要開「Default setup」，本專案用自己的 `codeql.yml`（Advanced setup），兩者不能並存。
5. **Renovate（可選）。** 安裝 [Renovate GitHub App](https://github.com/apps/renovate) 並選這個 repo，它會讀根目錄的 `renovate.json`。不裝就沒有自動的相依更新 PR。

push 到 main 後，CI 會建立「nightly」預先發行版。沒有 secret 時的差別：

| 項目 | 沒有設定時 |
|---|---|
| release APK、AAB | 改用 debug 金鑰簽章 |
| debug APK | 每次 CI 用新產生的金鑰，無法覆蓋安裝舊版 |
| TWDIW 應用金鑰 | 每次建置產生新的配對，keyId 每次不同 |
| 版型包 `zk-templates.jwt` | 不產生；App 仍下載上游的版型包（見 3.3） |
| Google Play 上傳 | `google-play.yml` 執行時直接失敗並說明缺少 secret |

## 2. Secrets 與 variables

在 Settings > Secrets and variables > Actions 設定。產生方式與排查見 [release.md](../release.md) 的對應章節。

| 名稱 | 種類 | 用途 | 必要性 |
|---|---|---|---|
| `ANDROID_KEYSTORE_BASE64`、`ANDROID_KEYSTORE_PASSWORD`、`ANDROID_KEY_ALIAS` | secret | release APK 與 AAB 的簽章金鑰 | 要發佈就必須 |
| `ANDROID_KEY_PASSWORD` | secret | 舊式 JKS 且金鑰密碼不同時才設 | 通常不設 |
| `DEBUG_KEYSTORE_BASE64`、`DEBUG_KEYSTORE_PASSWORD`、`DEBUG_KEY_ALIAS` | secret | 固定 debug APK 的簽章 | 建議 |
| `ZK_TEMPLATES_KEY` | secret | 版型包的發布私鑰（P-256 PEM） | 要自己發佈版型才需要，見 3.3 |
| `TWDIW_APP_PRIVATE_KEY`、`TWDIW_APP_PUBLIC_KEY` | secret | TWDIW 應用簽章的固定配對 | 要跨版本保持同一個 keyId 才需要 |
| `PLAY_SERVICE_ACCOUNT_JSON` | secret（可放在 `google-play` environment） | 上傳 Google Play 的服務帳戶 | 上架才需要，見 [google-play.md](../google-play.md) |
| `PLAY_AUTO_TRACK`、`PLAY_AUTO_STATUS` | variable | 每次 nightly 自動上傳的 track 與狀態 | 可選 |

金鑰一律自己產生，不要沿用別人的：

- Android 簽章金鑰遺失後無法再更新已安裝的 App；用不同金鑰簽的建置也無法覆蓋安裝上游的版本。
- TWDIW 應用金鑰只能是自行產生或合法取得的配對，不得取用官方 App 的私鑰。
- 行動自然人憑證的 SP 帳號（`DIW_MOICA_SP_SERVICE_ID`、`DIW_MOICA_SP_AES_KEY`、`DIW_MOICA_SP_ENV`）要向內政部申請自己的，不可使用他人的 SP 金鑰。目前的 CI 沒有傳入這三個值；建議把 SP 放在自己的正式服務端。

金鑰檔不要放進 repo。`.gitignore` 已排除 `*.jks`、`*.keystore`、根目錄的 `*.pem`、`*.p12`、`*.key` 與 `.env`，但提交前仍要自己確認。

## 3. 以自己的名義發佈時要改的地方

只做開發或自用時可以跳過這一節。要把建置給別人用（尤其是上架）時，下列項目仍指向上游，必須改成自己的。

### 3.1 應用程式識別

| 項目 | 位置 | 說明 |
|---|---|---|
| Android 套件名稱 | `app/build.gradle.kts` 的 `applicationId` | 改這一個就夠，`namespace` 與程式的 package 不必動。Google Play 的套件名稱上傳後不能更改 |
| Google Play 套件名稱 | `.github/workflows/google-play.yml` 的 `PLAY_PACKAGE` | 與 `applicationId` 相同 |
| TWDIW 應用簽章的應用身分 | `WalletModel.twdiwAppIdentity()` | 與 `applicationId` 無關，改套件名稱不會改變它；目前的取值有待確認的不一致，見 [STATUS.md](../STATUS.md#4-未完成與待決定) |
| 桌面安裝檔 | `app/build.gradle.kts` 的 `nativeDistributions`：`packageName`、`vendor`、`menuGroup`、`upgradeUuid` | `upgradeUuid` 一定要換成新的 UUID，否則你的 .msi 會被 Windows 當成上游 App 的升級版 |
| App 名稱與圖示 | `app/src/commonMain/composeResources` 的字串、`app/src/androidMain/res` | Apache-2.0 不授予商標使用權；對外發佈的修改版建議換名稱與圖示，避免被當成上游的版本 |

App 註冊的連結 scheme（`diw-wallet://`、`diw-zktls://`、`diw-server://`、`diw-prover://`）是協定的一部分，與正式服務端互通，不要改。

### 3.2 原始碼與開發者資訊

| 項目 | 位置 |
|---|---|
| 原始碼網址 | `LegalTexts.kt` 與 `SettingsScreen.kt` 的 `SOURCE_URL`；`SelfAttestationWalletProvider.kt`、`MultipazTestWalletProvider.kt` 與 `test-servers` 的 `WalletProviderService.kt` 的 `wallet_link` |
| 法律聲明中的開發者 | `LegalTexts.kt` 與 `LegalTextsEn.kt` 的 `DEVELOPER`，以及內文中的聯絡方式與發布事實 |
| 商店的版本說明 | `distribution/whatsnew/` |
| 商店資訊與隱私權政策網址 | [google-play.md](../google-play.md) 第 5、6 節 |

法律聲明寫的是「誰發布這個 App、誰處理資料」。發佈修改版的人就是新的發布者，要把聲明改成自己的名義與聯絡方式，並調高各文件的 `version`。改完以 `DIW_UPDATE_LEGAL=1 ./gradlew :app:desktopTest --tests 'diw.wallet.app.legal.*'` 重新產生 `docs/legal/`（規則見 [legal/README.md](../legal/README.md)）。

### 3.3 版型包與證明資產的來源

App 內寫死了兩類下載位址，都指向上游 repo 的 Release，並以內建的公鑰或雜湊驗證。

| 項目 | 位置 | 不改 | 要自己發佈時 |
|---|---|---|---|
| 零知識版型包 | `core/.../zk/ZkTemplatePack.kt` 的 `RELEASE_URL`、`MANUAL_URL`、`TRUSTED_KEYS` | 繼續使用上游簽章的版型包；你的 `ZK_TEMPLATES_KEY` 簽的包 App 不會接受 | 產生自己的 P-256 金鑰（[templates/README.md](../../templates/README.md)），公鑰加進 `TRUSTED_KEYS`，兩個網址改成自己的 repo，私鑰放進 `ZK_TEMPLATES_KEY` |
| 年齡證明的 witness graph、zkPDF 電路與 CRS | `native/assets.json` 的 `urls`、`native/openac-age/package_graphs.py` | 繼續從上游的 `openac-age-graph-v1`、`zkpdf-v1-bb6` Release 下載，雜湊已釘選，內容被換掉時 App 會拒絕 | 網址改成自己的 repo，再手動執行 `zkPDF assets` workflow 從原始碼建置並發佈；它會檢查 `assets.json` 的網址與執行的 repo 相同 |

上游的 Release 不保證永久存在。長期維護的 fork 建議把兩類資產都改由自己發佈。

### 3.4 授權與標示

- 保留 `LICENSE` 與 `NOTICE`（Apache-2.0 第 4 條）。修改過的檔案要標明已修改；可以在 `NOTICE` 開頭加上自己的著作權行，不要刪掉原有的。
- 新增、移除或更換相依時，同一個 PR 更新 `NOTICE`。
- GPL 家族的元件不可連結進隨 App 散布的程式（[AGENTS.md](../../AGENTS.md) 的規則）。年齡證明的電路資產是 GPL-3.0，只能像現在這樣分開下載。

### 3.5 正式服務端

服務端在另一個 repo [diw-wallet-server](https://github.com/mctea01/diw-wallet-server)，以 git submodule 引用錢包。錢包 fork 之後若也要自己建置服務端，fork 該 repo 並把 submodule 指到自己的錢包 fork，步驟見該 repo 的 `docs/fork-setup.md`。

## 4. 與上游同步

```bash
git remote add upstream https://github.com/mctea01/my-Bonds-fork-android
git fetch upstream
git merge upstream/main        # 或在分支上開 PR 合併
```

- 第 3 節的修改集中在少數幾個檔案，盡量放在同一個 commit，之後合併上游時衝突才容易處理。
- 版本的修訂號是「最後一次修改 `version.properties` 的 `version=` 之後的 commit 數」。Fork 的 commit 數與上游不同，所以同一個版本號在兩邊不代表同一份程式；要區分時改 `version.properties` 的版本線。
- Agent 不能推送 `.github/workflows/`。上游的 workflow 有更新時，合併 commit 由有權限的人推送。

## 5. 開發流程的設定

- 開發規則在 [AGENTS.md](../../AGENTS.md)，專案狀態在 [STATUS.md](../STATUS.md)。Fork 之後 STATUS.md 記的是上游的狀態：把「最後更新」改成自己的基準點，之後照同樣的規則維護（會改變狀態的 PR 要在同一個 PR 內更新）。
- 分支保護（可選）：對 main 要求 CI 的 `test`、`build`、`desktop` 通過。`desktop-native` 是實驗性工作，失敗不擋其他工作，不要列為必要檢查。
- 實機記錄、含個資的真實文件與金鑰不可提交；文件中的卡號、證號與姓名先遮蔽。

## 6. 檢查清單

只開發：

- [ ] 啟用 Actions 與兩個排程 workflow
- [ ] 允許 Actions 開 PR、只留 Squash merge
- [ ] （可選）安裝 Renovate、設定 `DEBUG_KEYSTORE_BASE64`

要發佈：

- [ ] 自己的 Android 簽章金鑰（三個 `ANDROID_*` secret），並備份
- [ ] `applicationId`、`PLAY_PACKAGE`、桌面的 `upgradeUuid` 與名稱
- [ ] `SOURCE_URL`、`wallet_link`、法律聲明的開發者與聯絡方式，重新產生 `docs/legal/`
- [ ] 決定版型包與證明資產的來源（3.3）
- [ ] `NOTICE` 加上自己的著作權行
- [ ] 需要時：TWDIW 應用金鑰、自己的 SP 帳號、Google Play 服務帳戶

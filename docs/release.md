# 發佈建置

## 發佈管道

| 管道 | 何時產生 | GitHub Release | 內容 |
|---|---|---|---|
| 穩定版 | 手動執行 `Stable release` workflow（見下方「穩定版發佈」） | 標籤 `v<主>.<次>.<修訂>`，標示為 Latest，一直保留 | release 最佳化建置，不含 debug 版 |
| nightly | 每次 push 到 main | `nightly` 預先發行版，每次取代 | 同上，另附 debug APK 與 debug AAB |

兩者都由同一個 CI workflow 建置，Android 走 R8、桌面走 ProGuard，檔案不經壓縮。Release 頁的內文由 `tools/release-notes.py` 產生：最上方是一次性的下載指引（依裝置列出該下載的檔案，只列出這次真的有的檔案，其他檔案收在摺疊區），下面是上一個穩定版標籤以來的變更（相依套件更新摺疊在一起），GitHub 的檔案清單接在最後並顯示每個檔案的 SHA-256。下載指引只放在 Release 頁，README 與本頁不再重複；要改說明文字時改這個腳本，不必改 workflow。

下表是開發者參考，說明每個檔案怎麼產生：

| 檔案 | 說明 |
|---|---|
| `DIW-MY-WALLET-<版本>.apk` | Android release 版：R8 縮減與最佳化，網路安全設定只允許本機與模擬器主機的 HTTP；兩個 ABI 與所有選用元件都在裡面 |
| `DIW-MY-WALLET-<版本>-arm64-v8a.apk`、`-x86_64.apk` | 同上，只含一個 ABI，檔案較小（一般手機用 arm64-v8a） |
| `DIW-MY-WALLET-<版本>.apks` | 同一版的分割 APK 組，與 Google Play 的分割相同，選用元件是獨立分割；用 `bundletool install-apks` 或 SAI 等分割安裝程式安裝，可以只裝需要的部分 |
| `DIW-MY-WALLET-<版本>-debug.apk` | Android debug 版：未最佳化，允許區網測試伺服器的 HTTP；含所有選用元件 |
| `DIW-MY-WALLET-<版本>.aab`、`DIW-MY-WALLET-<版本>-debug.aab` | release／debug App Bundle，供 Google Play 或 bundletool 使用，不能直接安裝 |
| `DIW-MY-WALLET-<版本>-mapping.txt` | release 版的 R8 mapping，與 AAB 一起上傳 Google Play 以還原當機記錄 |
| `DIW-MY-WALLET-<版本>.msi` | Windows 安裝檔（ProGuard 最佳化，內含 Java 執行環境，不需系統管理員權限） |
| `diw-my-wallet_<版本>_amd64.deb` | Linux 安裝檔（同上） |
| `DIW-MY-WALLET-<平台>-<版本>-release.jar` | 需自行安裝 Java 21，以 `java -jar` 執行；macOS（Apple 晶片）只提供這個檔案 |
| `DIW-MY-WALLET-<版本>-windows-x64-native.zip`、`-linux-x64-native.tar.gz` | 實驗的 GraalVM 原生桌面版（不需要 Java），`desktop-native` 工作成功時才有，見下方 |
| `zk-templates.jwt` | 零知識證明版型包（zkTLS 查驗頁與 zkPDF 版型），以 `ZK_TEMPLATES_KEY` 簽章；沒有設定這個 secret 時不附上。格式與手動發佈見 [templates/README.md](../templates/README.md) |

Google Play 的上架步驟、自動提交 workflow（`google-play.yml`，預設從 nightly 取 AAB 上傳，手動執行時 `tag` 填穩定版標籤如 `v0.5.3` 即上傳穩定版）、商店資訊與資料安全表單見 [google-play.md](google-play.md)。

每個 64 位元平台都連結零知識證明的 OpenAC 年齡證明、TLSNotary（zkTLS）與 zkPDF／zkPassport（Barretenberg 6.0.0）後端，另含驗證舊 zkPassport 電路的 Barretenberg 5（CI 以 `DIW_ZK_FEATURES=openac,tlsn,zkpdf,bb5` 建置；Android 的 Barretenberg 5 是選用元件，見下方）。Windows 的函式庫不能在 Windows 主機上連結 zkPDF，CI 在 Linux 上交叉建置整個函式庫（`native/build.sh x86_64-pc-windows-gnullvm`，腳本會下載固定版本的 llvm-mingw；產物靜態連結 libc++ 等寬鬆授權的執行階段，不含 libstdc++ 與 libgcc）。各平台有哪些後端見 [專案現況](STATUS.md#35-平台)。Android 的 32 位元 ABI（`armeabi-v7a`、`x86`）只有不含證明後端的 runtime 函式庫，用來解碼 JPEG 2000 相片。zkPDF 的電路資產在 `zkpdf-v1-bb6` release，由手動執行的 `zkPDF assets` workflow 從原始碼建置並核對雜湊後發佈，App 依 `native/assets.json` 下載並核對；CI 的測試也從這裡取得資產（`native/circuits/tools/fetch_assets.py`），尚未發佈時略過 zkPDF 證明測試並警告。zkPassport 人臉比對的金鑰證明版電路在 `zkpassport-facematch-v1` release，由手動執行的 `zkPassport FaceMatch assets` workflow 從 `native/circuits-zkpassport` 建置，金鑰雜湊須與 `circuits.json` 相同才發佈；App 只在需要時下載這台裝置用得到的那一個。Linux 的 Barretenberg 須以 clang 編譯（GCC 版對 P-256 簽章電路算出不同的驗證金鑰，見 `native/zkpdf-prover/README.md`）。mdoc 的 Longfellow 由 Multipaz 提供，沒有 Windows 版。

零知識原生函式庫在 CI 由獨立工作建置：`native-android`（Linux，每個 ABI 一個工作）、`native-linux`（Linux 桌面，也供測試使用）、`native-windows`（在 Linux 以 llvm-mingw 交叉建置 Windows 版）、`native-desktop`（macOS）。它們只上傳最終函式庫（`zk-native-android-<abi>`、`zk-native-<os>` Artifacts，保留 3 天），`test`、`build`、`desktop` 下載回 `native/dist` 並以 `DIW_ZK_NATIVE=prebuilt` 執行 Gradle，不再安裝 Rust、NDK 編譯工具或建置 Barretenberg。發佈只收 `android`、`windows`、`linux`、`macos`、`zk-templates` 這幾個 Artifacts，原生函式庫不會出現在 nightly。

桌面版原生執行檔（實驗）由 `desktop-native` 工作以 GraalVM Community 25 和 `tools/desktop-native.sh` 建置（Linux、Windows；macOS 的 GraalVM 視窗支援無法載入 libawt，不建置），先跑執行檔的 `--self-check` 與定時啟動視窗，並以 java.awt.Robot 在視窗裡打字、右鍵、貼上與解鎖（`DIW_EXERCISE_INPUT`），通過後上傳為 `desktop-native-<os>` Artifact（保留 14 天，內容就是發佈的資料夾：執行檔、它旁邊的程式庫、`LICENSE` 與 `NOTICE`）；自我檢查結果與冒煙執行的 stderr（`self-check.txt`、`self-check-jvm.txt`、`smoke-stderr.txt`）另存為 `native-check-<os>` Artifact，失敗時也上傳，不放進發佈的壓縮檔。Windows 執行檔在 native-image 連結時加入版本資源與圖示（`rc.exe` 編譯、`-H:NativeLinkerOption` 連結）：檔案描述與產品名稱「DIW MY WALLET」、檔案版本為 `主.次.修訂.0`、產品版本為 `tools/app-version.sh` 的完整版本（PR 建置帶 `-pr<編號>`，並標為預先發行）、著作權取 `NOTICE` 的第一行 Copyright 加上 Apache License 2.0、圖示為 `app/icons/app-icon.ico`；建置後以 Windows 讀回版本與圖示，不符即失敗；Robot 的輸入沒送到視窗但經 AWT 事件佇列送入的點擊與按鍵能進入欄位時（結束碼 4），只發警告並照常上傳，輸入改由實機確認。這個工作 `continue-on-error`，失敗不影響其他工作；成功時 `release` 工作把兩個資料夾各打包成一個檔案（最上層一個同名資料夾），附在 nightly 與穩定版：`DIW-MY-WALLET-<版本>-windows-x64-native.zip`、`DIW-MY-WALLET-<版本>-linux-x64-native.tar.gz`（Artifact 不保留執行權限，打包時重設），Release 頁的下載指引把它們列在「實驗版」摺疊區；失敗時那次的 Release 就沒有這兩個檔案。原生版不設堆積上限，預設最多使用實體記憶體的 80%。桌面版（JVM 與原生）結束程式的錯誤會寫到資料夾的 `logs/error-*.txt`（Windows 在 `%APPDATA%\DIW-MY-WALLET\logs`），對話框會顯示檔案位置。

## 版本號

版本號只記在 repo 根目錄的 `version.properties`（`version=主版號.次版號`，由穩定版發佈 workflow 或 PR 修改；目前 `0.5`，對應 P5），建置時補上修訂號：從最後一次修改 `version=` 那一行的 commit 起算的 commit 數。同一個 commit 在任何機器算出的版本都相同，換新的主版號或次版號時修訂號從 0 重新開始，之後每合併一次到 main 加 1。不再使用 CI 執行次數。

| 建置 | 版本 | Android versionCode |
|---|---|---|
| 穩定版標籤 `v0.5.<修訂號>` | `0.5.<修訂號>`，與標籤相同 | 主版號 × 1,000,000 + 次版號 × 10,000 + 修訂號（0.5.3 為 50003） |
| push 到 main（nightly） | `0.5.<修訂號>` | 同上 |
| pull request | `0.5.<修訂號>-pr<PR 編號>` | 同上 |
| 本機 | `0.5.<修訂號>-dev` | 同上 |

修訂號需要完整的 git 歷史：CI 的 checkout 使用 `fetch-depth: 0`，`tools/app-version.sh` 在歷史不完整時讓發佈檔案的工作失敗；只跑測試的工作只警告並以修訂號 0 繼續。修訂號達 10,000 時建置要求換新的版本線。在 `v*` 標籤上建置時，`tools/app-version.sh` 要求標籤與算出的版本完全相同，手動推錯號碼的標籤會讓發佈失敗，不會發出版本號不符的檔案。

versionCode 由版本算出，換新版本線時一定變大（0.5 起為 50000 以上，大於 0.4 的所有建置），所以新建置能覆蓋安裝舊版（同一把簽章金鑰時）；同一版本線內只要從 main 依序建置，也一定變大。Windows 安裝檔與 Linux 套件使用不含字尾的數字版本（`0.5.<修訂號>`）。`-Pdiw.versionName`、`-Pdiw.versionCode`、`-Pdiw.desktopVersion` 仍可覆寫。CI 以 `tools/app-version.sh`（與 Gradle 同一規則）算出 `APP_VERSION` 為檔名，`./gradlew -q :app:printVersion` 可查看 Gradle 算出的版本。關於頁顯示版本與 commit。

## 穩定版發佈

在 GitHub 的 Actions 頁選 `Stable release`，在 main 上按 Run workflow：

| 輸入 | 結果 |
|---|---|
| `bump: keep`（預設） | 發佈目前的版本線，版本是 main 現在的版本，例如 `v0.5.12`；只推標籤 |
| `bump: minor` | 開始下一個次版本線並發佈它的第一版：`version.properties` 改成 `0.6`，發佈 `v0.6.0` |
| `bump: major` | 開始下一個主版本線：改成 `1.0`，發佈 `v1.0.0` |
| `version: 主.次`（選填） | 直接指定新的版本線，例如 `1.2` 發佈 `v1.2.0`，優先於 `bump`；不可低於目前的版本線（Android 會拒絕降版） |
| `dry_run` | 只顯示會發佈的版本，不改任何東西 |

流程：`tools/stable-release.sh` 決定版本，要換版本線時在 main 加一個只改 `version.properties` 的 commit，與標籤一起以一次原子推送送出；之後 CI 在標籤上完整建置與測試（約一個半小時），通過後以 `tools/release-notes.py` 產生內文並建立穩定版 Release。同一個 commit 已經有標籤時（main 沒有新 commit）會直接失敗。要上架 Google Play 時，手動執行 `Google Play` workflow 並把 `tag` 填成這次的標籤。

權限：

- `keep` 只推標籤，workflow 自己的權杖就夠；由於這個權杖推的標籤不會觸發其他 workflow，`Stable release` 會改以 workflow_dispatch 在標籤上啟動 CI。
- `minor`、`major` 與指定版本要直接推 commit 到 main，main 的 `MUST CI` 規則集只允許 bypass 對象推送。請建立 secret `RELEASE_TOKEN`：repo 管理員的 fine-grained personal access token，只選這個 repo，權限 Contents 讀寫。有這個 secret 時推送由它完成，標籤的 push 觸發 CI（main 的 commit 也會觸發一次 nightly）。沒有時推送會被拒絕並提示，什麼都不會改；也可以改用 PR 修改 `version.properties`，合併後再以 `keep` 發佈。
- 也可以在本機推標籤（`git tag -a v0.5.12 -m ... && git push origin v0.5.12`），CI 一樣會發佈，但標籤必須等於該 commit 算出的版本。

## Windows 程式碼簽章

CI 產生的 Windows 檔案沒有 Authenticode 簽章。程式碼簽章憑證只存在 YubiKey（或其他智慧卡）時，在自己的 Windows 電腦上以 `tools/windows-sign.ps1` 簽署後傳回同一個 Release；私鑰不離開卡片，也不需要放進 CI。

需要：Windows SDK 的 `signtool`（Signing Tools for Desktop Apps）、YubiKey Smart Card Minidriver（插上 YubiKey 時憑證出現在「目前使用者 > 個人」，簽署時 Windows 詢問 PIV PIN）、已 `gh auth login` 的 GitHub CLI；預設模式另需 `jpackage`（JDK 21 以上，依序取 `-JdkHome`、`JAVA_HOME`、PATH）與 WiX Toolset：WiX 3.14（`candle.exe`、`light.exe`）可搭配任何版本的 jpackage；WiX 4 以上（單一的 `wix.exe`）要搭配 JDK 24 以上的 jpackage，並先安裝 jpackage 用到的擴充 `wix extension add -g WixToolset.Util.wixext/<與 wix --version 相同的版本>`（缺少時腳本會提示這行指令）。只用那個 JDK 的 jpackage 打包，MSI 內仍是原本映像裡的 Java 執行環境，所以可另外裝一個 JDK 24 以上並以 `-JdkHome` 指定，例如 `-JdkHome "C:\Program Files\Java\jdk-25"`。執行前 `chcp 65001`，腳本本身以 UTF-8 輸出。只有一張可用的程式碼簽章憑證時自動選用，否則以 `-Thumbprint` 指定。時戳預設 `http://timestamp.digicert.com`（`-TimestampUrl` 可改）。

不用 signtool 時以 `-SignCommand` 改用自己的簽章命令（例如整合好的 jsign 腳本）：第一個元素是程式，其餘是參數，參數中的 `{file}` 換成要簽的檔案，沒有 `{file}` 時把檔案接在最後。命令要就地簽署檔案（時戳由命令自己處理）並以 0 結束；腳本之後以 `Get-AuthenticodeSignature` 確認檔案帶有簽章，`-Thumbprint` 與 `-TimestampUrl` 只用於 signtool。例如：

```powershell
.\tools\windows-sign.ps1 -Tag v0.5.3 -SignCommand C:\tools\jsign-yubikey.cmd,"{file}"
.\tools\windows-sign.ps1 -Tag v0.5.3 -SignCommand java,-jar,C:\tools\jsign.jar,--storetype,YUBIKEY,--storepass,$env:PIV_PIN,--tsaurl,http://timestamp.digicert.com,"{file}"
```

| 模式 | 指令 | 簽署的內容 |
|---|---|---|
| `Full`（預設） | `.\tools\windows-sign.ps1 -Tag v0.5.3` | 以系統管理安裝（`msiexec /a`）解開 MSI（補回 jpackage 不安裝、但 `--app-image` 需要的 `app\.jpackage.xml`，並移除重建時會再產生的 `app\.package`，否則 JDK 24 以上的 jpackage 交給 WiX 的檔案重複，出現 WIX0091），簽署啟動程式與所有尚未簽章的 .exe、.dll，以及 jar 內本專案的零知識原生程式庫（`zk/native/windows-x86_64/` 的 `diw_zk.dll`、`diw_bb5.dll`），再以 `jpackage --app-image` 依 CI 相同的名稱、版本、升級 UUID 與安裝選項重建 MSI 並簽署；Release 的 `DIW-MY-WALLET-windows-x64-<版本>-release.jar` 內的原生程式庫也一併簽署 |
| `MsiOnly` | `.\tools\windows-sign.ps1 -Tag v0.5.3 -Mode MsiOnly` | 只簽 MSI 本身，裡面的程式不變；只需要 `signtool` |
| `Native` | `.\tools\windows-sign.ps1 -Mode Native -Tag v0.5.3` | 實驗的 GraalVM 原生版：下載該 Release 的 `DIW-MY-WALLET-<版本>-windows-x64-native.zip`（或以 `-Path` 指定本機的檔案、資料夾或 Actions 的 `desktop-native-windows` Artifact），簽署 `diw-desktop.exe` 與同一資料夾及其子資料夾內所有尚未簽章的 .exe、.dll（native-image 複製的 JDK 程式庫、`j2pcsc.dll`、`jawt.dll` 與 `bin\jawt.dll`），列出每個簽署的檔案並確認沒有遺漏，以相同的檔名與資料夾結構重新打包並取代；舊版壓縮檔裡的 `self-check.txt`、`smoke-stderr.txt` 重新打包時移除 |

說明：

- 原生程式庫在 jar 內有對應的 `.sha256`，`ZkNative` 解出時核對它；簽章會改變檔案，所以腳本同時改寫 `.sha256`。
- 原生版的零知識程式庫是編進執行檔的資源，事後無法個別簽章；執行檔只在檔案的 SHA-256 與執行檔內釘選的值相同時才解出載入，而這個值在已簽章的執行檔內。要讓解出的 DLL 本身也帶簽章，須在 native-image 建置前就簽好 DLL，目前 CI 不這樣做。
- jar 在執行時解出的第三方程式庫（Skiko、SQLite、JNA）不簽署：不是本專案的程式，載入器各自核對內容。
- 上傳以 `--clobber` 取代同名檔案，GitHub 的檔案清單隨即顯示新的 SHA-256；腳本在 Release 內文的下載指引之後加一行說明已簽署的內容與簽署者（`-NoNotes` 不加，同模式再執行時取代該行）。`-NoUpload` 只在本機產生檔案，`-Msi` 可簽本機的 MSI。
- 重建失敗時 jpackage 的 WiX 原始檔與記錄留在工作資料夾（預設 `%TEMP%\diw-windows-sign\jpackage`）。
- nightly 每次 push 到 main 都會重建並取代，簽好的檔案只保留到下一次；正式散布請簽穩定版。

## Android 選用元件與 APK

少數人需要、體積又大的元件放在隨選動態功能模組（`features/`）：`features/bb5` 是 Barretenberg 5（`native/zkpassport-bb5`），用來驗證 zkPassport 0.22.0 以前電路的證明；`features/facenet` 是人臉比對的選用模型 FaceNet-512（約 24 MB 的模型檔，沒有程式碼，`tools/facematch-eval/README.md`），只有 Android 版有相機比對，所以沒有桌面版。Google Play 版在用到時由 App 向 Play 要求安裝（設定的 zkPassport 區段或查驗結果頁的按鈕）；Play 政策不允許從 Play 以外下載可執行程式碼，模型也照同樣方式只經由 Play 或完整 APK 提供。

GitHub 的 APK 與 `.apks` 由 CI 用 `tools/bundle-apks.sh` 從 Google Play 收到的同一個 AAB 產生（bundletool，版本與 SHA-256 釘選在腳本裡），所以程式碼、版本號與簽章都和 Play 版相同：`.apk` 已含所有模組，`.apks` 的模組是獨立分割。電腦版把同一個函式庫放在 JAR 的資源裡，所以每個版本的功能一致。新增這類元件時照同樣方式：加一個 `features/` 模組並列入 `app` 的 `dynamicFeatures`，在 `ZkComponent` 的實作裡載入（原生函式庫用 `PlayFeatureComponent`，資料檔用 `PlayFeatureAsset`），桌面版放進資源。

本機建置 Android 時要在 `DIW_ZK_FEATURES` 加上 `bb5`（需要 `zkpdf`），`native/build.sh` 才會建置 `native/dist/android-bb5`；沒有時模組是空的，App 會顯示元件不可用。bundletool 要求有原生程式碼的模組都支援和 base 相同的 ABI，而 base 含相依套件（JNA、Tesseract、CameraX 等）的 32 位元函式庫；32 位元沒有 Barretenberg（`diw_zk` 在 32 位元只有 runtime），所以 `build.sh` 在 `armeabi-v7a` 與 `x86` 放一個空的 `libdiw_bb5_none.so`，App 不會載入它。

## Android 簽章

release APK 以 repo secrets 的金鑰簽章；沒有設定時改用 debug 金鑰。debug APK 以 `DEBUG_KEYSTORE_BASE64` 的金鑰簽章，沒有設定時每次 CI 用新產生的金鑰，無法覆蓋安裝舊版。CI 記錄會印出兩把金鑰的 SHA-256 指紋（`Debug APK signed with key ...`、`Release APK signed with key ...`），每次相同才代表簽章固定。

AAB 使用相同 build type 的 signingConfig。AAB 是分發格式，不能直接當 APK 安裝；由 Google Play 或 bundletool 產生適合裝置的 APK。要上架時必須提供正式 upload key，debug 金鑰的 fallback 僅供測試。

建立金鑰（PowerShell，金鑰請自行保管，遺失後無法再更新已安裝的 App）：

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
keytool -genkeypair -v -keystore diw-release.jks -alias diw -keyalg RSA -keysize 4096 -validity 10000
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path "diw-release.jks"))) | Set-Clipboard
```

JDK 9 以後 keytool 預設建立 PKCS12 keystore，金鑰密碼固定等於 keystore 密碼（指定不同的 `-keypass` 會被忽略）。

到 GitHub repo 的 Settings、Secrets and variables、Actions 新增：

| Secret | 內容 |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | 上面複製的 base64（換行與空白會自動去除） |
| `ANDROID_KEYSTORE_PASSWORD` | keystore 密碼 |
| `ANDROID_KEY_ALIAS` | `diw` |
| `ANDROID_KEY_PASSWORD` | 只有舊式 JKS 且金鑰密碼不同時才設；PKCS12 請不要設 |
| `DEBUG_KEYSTORE_BASE64` | debug keystore 的 base64，固定 debug APK 的簽章 |
| `DEBUG_KEYSTORE_PASSWORD` | 只有 debug keystore 密碼不是 `android` 時才設 |
| `DEBUG_KEY_ALIAS` | 只有 debug keystore 內有多把金鑰時才設 |
| `ZK_TEMPLATES_KEY` | 版型包的發布私鑰（P-256 PEM），公鑰釘選在 App；見 templates/README.md |

建立 debug keystore（PowerShell，與 release 金鑰分開保管）：

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
keytool -genkeypair -v -keystore diw-debug.p12 -storetype PKCS12 -storepass android -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=DIW MY WALLET Debug"
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path "diw-debug.p12"))) | Set-Clipboard
```

本機建置要用同一把金鑰時，設定環境變數 `DIW_DEBUG_KEYSTORE_FILE` 指向這個檔案（密碼不是 `android` 時另設 `DIW_DEBUG_KEYSTORE_PASSWORD`）。

CI 的 Signing keys 步驟會先檢查 base64、keystore 密碼與別名，並印出憑證 SHA256 指紋；Gradle 在 release 建置開始前開啟金鑰，`ANDROID_KEY_PASSWORD` 打不開時改用 keystore 密碼，兩者都不行就以明確訊息停止，不會改用 debug 金鑰。

### 簽章失敗排查

| CI 訊息 | 原因與處理 |
|---|---|
| `ANDROID_KEYSTORE_BASE64 is not valid base64` | base64 不完整，重新複製整段 |
| `ANDROID_KEYSTORE_PASSWORD does not open the keystore` | keystore 密碼錯，或 base64 不是整個 .jks 檔 |
| `ANDROID_KEY_ALIAS is not a key in the keystore` | 別名錯，上一行會列出 keystore 內的別名 |
| `Key "..." opens with neither ANDROID_KEY_PASSWORD nor ANDROID_KEYSTORE_PASSWORD` | JKS 的金鑰密碼錯 |
| `Given final block not properly padded` | 舊版建置腳本把空的 `ANDROID_KEY_PASSWORD` 當成密碼，更新後即可 |

在自己電腦確認金鑰（PowerShell）：

```powershell
[Console]::OutputEncoding = [Text.Encoding]::UTF8
keytool -list -v -keystore diw-release.jks -alias diw
Get-FileHash diw-release.jks -Algorithm SHA256
```

`Keystore type` 為 `PKCS12` 時刪除 `ANDROID_KEY_PASSWORD`；`SHA256` 指紋要與 CI 印出的相同，不同代表 secret 存的是另一個檔案。

本機建置 release：設定環境變數 `DIW_KEYSTORE_FILE`、`DIW_KEYSTORE_PASSWORD`、`DIW_KEY_ALIAS`（金鑰密碼不同時再設 `DIW_KEY_PASSWORD`）後執行 `./gradlew :app:assembleRelease`。

APK 與 AAB 一起建置：

```bash
./gradlew :app:assembleDebug :app:bundleDebug
./gradlew :app:assembleRelease :app:bundleRelease
```

本機驗證使用 `--max-workers=1 -Dorg.gradle.jvmargs='-Xmx4g -Dfile.encoding=UTF-8' -Pkotlin.compiler.execution.strategy=in-process`，讓 Kotlin 與 R8 共用受限的 JVM heap，避免另外保留大型 Kotlin daemon 後在 R8 階段達到記憶體上限。手動更新 CI Android 建置命令時也建議加入相同參數。

## TWDIW 應用簽章金鑰

這組金鑰用於新版 TWDIW `dwapp-201i` 格式的 `Twdiw-Signature`，獨立於 holder／Android APK 簽章金鑰。尚未找到 `diwapp-200i` 的另一份契約，因此設定不以該未確認名稱命名。只匯入自行產生或合法取得的應用金鑰，不讀取官方 APK 的私鑰資產。

| GitHub Actions secret | Gradle／本機環境變數 | 格式 |
|---|---|---|
| `TWDIW_APP_PRIVATE_KEY` | `DIW_TWDIW_APP_PRIVATE_KEY` | 未加密 P-256 PKCS#8 PEM（`BEGIN PRIVATE KEY`），或其 DER 的標準 Base64 |
| `TWDIW_APP_PUBLIC_KEY` | `DIW_TWDIW_APP_PUBLIC_KEY` | P-256 SPKI PEM（`BEGIN PUBLIC KEY`），或其 DER 的標準 Base64 |

兩個值都空白或未設時，`:app:generateTwdiwApplicationKey` 以 JDK 產生新的 P-256 配對。它在 `app/build/twdiwApplicationKeyState/` 保留本機配對，讓同一工作目錄的 APK、AAB、桌面產物及後續增量建置使用相同應用 keyId；`clean` 或新 CI runner 會產生另一組。要跨 CI 發行保持 keyId，必須提供固定配對。

兩值須同時提供；只填一個、格式錯誤、曲線不是 P-256，或簽署／驗簽證明不匹配時，建置失敗，不會悄悄改用隨機金鑰。建置只記錄來源及公鑰文字指紋，不輸出私鑰。產生的 Kotlin source 位於 `app/build/generated/twdiwApplicationKey/kotlin/`；POSIX 系統下 state 與 source 權限為 0600，不作此任務的 build-cache artifact，也不提交或額外上傳 state/source。

CI 的 `build` 與 `desktop` job 只在 push 建置注入這兩個 secrets；PR 建置使用自己的生成測試配對。Android debug／release 的 APK／AAB 及桌面包都支援相同環境輸入。沒有設定這兩個 GitHub secrets 時 push 建置也產生測試配對，不必手動填空字串。兩個 job 的 `env` 為：

```yaml
DIW_TWDIW_APP_PRIVATE_KEY: ${{ github.event_name == 'push' && secrets.TWDIW_APP_PRIVATE_KEY || '' }}
DIW_TWDIW_APP_PUBLIC_KEY: ${{ github.event_name == 'push' && secrets.TWDIW_APP_PUBLIC_KEY || '' }}
```

Android 建置以 `:app:bundleDebug`／`:app:bundleRelease` 一併產生 AAB 並收進 `android` Artifact。金鑰建置測試可透過 `python3 tools/twdiw/test_generate_application_key.py` 執行。

本機 PowerShell 匯入合法金鑰：

```powershell
$env:DIW_TWDIW_APP_PRIVATE_KEY = [IO.File]::ReadAllText((Resolve-Path "my-application-private.pem"))
$env:DIW_TWDIW_APP_PUBLIC_KEY = [IO.File]::ReadAllText((Resolve-Path "my-application-public.pem"))
./gradlew :app:assembleRelease :app:bundleRelease
```

Secrets 保護的是 repo 與建置輸入；這項設計會把應用簽章能力放進發行產物，不能把客戶端內嵌私鑰視為無法擷取的機密。不得提供不允許散布在客戶端的金鑰；未來平台若要求非匯出金鑰或後端簽署，需依正式契約另接 signer。

應用身分的 appHash 固定為 `tw.gov.moda.diw`（`TwdiwAppIdentity.DEFAULT.appId`，2026-11-13 使用者確認以此為準，與本專案的套件名稱 `diw.wallet.app` 無關），appVersion 是本次建置的版本，appPlatform 依平台為 `Android` 或 `Desktop`；keyId 是該配對 Base64 SPKI 文字的 SHA-256。自動生成或合法匯入不代表官方平台已准入；正式受理仍須官方授權與端到端驗收。新版／舊版流程與驗證紀錄見 [TWDIW 新版領卡實作](acceptance/twdiw-application-signature.md)。

## 行動自然人憑證 SP 帳號

SP 帳號在建置時由 `DIW_MOICA_SP_SERVICE_ID`、`DIW_MOICA_SP_AES_KEY`、`DIW_MOICA_SP_ENV`（`UAT` 或 `PRODUCTION`）產生 `BuiltInSp`，不提交進 repo。目前的 CI workflow 沒有傳入這三個值，所以 nightly 沒有內建 SP 帳號；可改用正式服務端的 SP（服務端啟用 `twfido`，App 設定正式服務端與存取權杖），或在「設定 > 開發者與測試」手動輸入（只存在記憶體）。持有 SP 許可的開發者可在本機設定環境變數後建置；要讓 CI 內建，需新增同名 secrets 並在 workflow 的 build 與 desktop job 的 `env` 加入這三行（workflow 由使用者手動修改）。

## 縮減規則

- Android：`app/proguard-rules.pro`。Bouncy Castle 只保留 JCA provider 的類別名稱與建構子，以及 Multipaz 以反射取用的 ML-DSA、ML-KEM 類別；Multipaz 只保留反射用到的進入點。不要用整包的萬用字元保留規則（Google Play 會回報 DEX 最佳化不足），程式也不可依賴第三方類別的 simpleName。
- 桌面版：`app/compose-desktop.pro`，另保留 SQLite JDBC 與 Ktor Java 引擎；不做名稱混淆。

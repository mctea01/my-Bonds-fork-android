# P4 工作包與交接約定

撰寫日期：2026-10-16。設計見 [p4-zkp.md](p4-zkp.md)，電路規格見 [p4-circuits.md](p4-circuits.md)。P4 由 Claude 主導，部分工作包交給 ChatGPT Codex。每個工作包寫明目標、可以修改的檔案、介面、驗收條件與測試指令，接手者不需要讀過對話紀錄就能獨立完成。

## 1. 分工與流程

### 1.1 原則

- Claude 負責：電路的規格與審查（Noir、OpenAC 電路修補、zkTLS 揭露規則，見 p4-circuits.md 第 1.3 節）、跨模組整合、信任判定、證據與持有者的綁定邏輯、版型與查驗頁描述檔（標籤參考 P3 的文件解析，見 p4-circuits.md 第 3.11 節）、UI、驗收文件，以及審查 Codex 的 PR。
- Codex 負責：介面已凍結、可用合成資料驗收的工作，例如建置、原生綁定、證明器、純函式與 Multipaz 整合；電路的里程碑也可以逐步交給 Codex。Codex 的 PR 若修改 `native/circuits/**`、OpenAC 的 `predicate.rs` 或 zkID patch，必須附上「電路實作報告」（第 4 節），Claude 檢查後才合併。
- 介面（本文的 Kotlin 與 Rust 簽名、p4-zkp.md 第 5 節的資料格式、p4-circuits.md 第 3.6 節的公開輸入順序）由 Claude 維護。接手者發現介面不夠用時，在 PR 說明「介面變更提案」並等 Claude 更新文件，不自行改動其他工作包的介面。

### 1.2 分支與 PR

| 項目 | 規則 |
|---|---|
| 整合分支 | `claude/p4-zkp-design-fmkasd`（P4 的整合分支，最後以一個 PR 合併進 main） |
| 工作包分支 | Codex：`codex/p4-wpN-<簡稱>`；Claude：`claude/p4-wpN-<簡稱>`；都從整合分支最新狀態開出 |
| PR | 目標分支為整合分支；標題 `P4 WPn: <英文摘要>`；說明含：完成的驗收條件與測試輸出、與規格不同之處、介面變更提案（若有） |
| 合併 | Claude 審查後合併；整合分支定期合併 main（不 rebase 他人分支） |
| CI | `.github/workflows` 代理無法推送；需要改 CI 時，把完整檔案放在 PR 說明或 `docs/design/ci/` 的草稿，由使用者手動貼上 |

### 1.3 所有工作包共同的完成條件

1. 遵守 AGENTS.md（繁體中文介面字串、英文程式碼註解與 commit、不用 emoji、完整實作不留 TODO）。
2. 測試放在 `test-servers/src/test`（協定與 core）或 `app/src/desktopTest`（App 流程），方法寫 `runBlocking<Unit> { ... }`；Rust 與 Noir 的單元測試放在各自的 crate。
3. 不提交真實文件、個資或真實查詢結果；測試資料以合成方式產生，產生器一起提交。
4. 新增第三方元件時更新 `NOTICE`，並在 PR 說明列出授權。
5. `./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test` 通過；動到 Android 時 `./gradlew :app:assembleRelease` 通過（R8）。
6. 私密輸入不出現在 log、例外訊息與測試輸出（p4-zkp.md 第 10 節）。

### 1.4 開發環境

| 工具 | 版本 | 備註 |
|---|---|---|
| JDK | 17（core、app）、21（test-servers） | 既有設定 |
| Android SDK | compileSdk 36、minSdk 29（app）、28（core） | 既有設定 |
| Rust | 以 `native/rust-toolchain.toml` 釘選的 stable | WP0 建立 |
| Android NDK、cargo-ndk | WP0 釘選 | 目標 `aarch64-linux-android`、`x86_64-linux-android` |
| uniffi | WP0 釘選 | Kotlin 綁定使用 JNA |
| nargo、bb | WP3a 釘選在 `native/circuits/VERSIONS` | bb 使用零知識版本 |
| tlsn | `v0.1.0-alpha.15` 的 commit | WP5 釘選 |
| zkID | `b395e09c225ff45b003f0087c28e2e208e22f944` | 與 Bonds `openac-age-v1` 相同（WP7） |
| circom、circomlib、@zk-email/circuits | 2.2.3、2.0.5、6.3.4 | 只在建置見證計算圖時使用（WP7） |
| circom-witnesscalc | `d48eb7c97857d46b8a75c94ab96f769207263245` 加 `native/openac-age/patches/circom-witnesscalc-secq256r1.patch` | 取代 witnesscalc\_adapter（WP7 授權） |

## 2. 工作包一覽

| WP | 名稱 | 負責 | 依賴 | 產出 |
|---|---|---|---|---|
| WP0 | 原生建置與 ZK 共用層 | Codex | — | `native/` 工作區、uniffi 綁定、`core/zk`、資產下載、裝置分級 |
| WP1 | 效能量測與門檻 | Codex（實機由使用者執行） | WP0；WP3a 的 M3a、WP5、WP7 | `docs/research/p4-benchmarks.md`、等級門檻 |
| WP2 | zkPDF 公開側基礎函式 | Codex | — | `Sha256State`、PDF 結構與加密輔助、字型解碼匯出、`PdfTextExtractor.runs` |
| WP3a | zkPDF Noir 電路 | Claude 主導（規格與審查），里程碑可逐步交給 Codex | WP2 | `native/circuits/pdf_text_v1`（子電路、完整電路、Noir 測試、`VERSIONS`） |
| WP3b | zkPDF 證明器與合成測試文件 | Codex | WP0、WP3a | `native/zkpdf-prover`、uniffi 匯出、合成測試文件產生器 |
| WP4 | zkPDF 版型、遮蔽與查驗整合 | Claude | WP2、WP3b | `core/document/zkpdf`、版型描述檔、衍生憑證證據、自架主機產生 |
| WP5 | TLSNotary 原生綁定 | Codex | WP0 | `native/zktls`、prover 與 verifier 的 uniffi API、Noise 通道 |
| WP6 | zkTLS 查驗頁、即時模式與存證 | Claude | WP5 | `core/zktls`、描述檔、傳輸路徑（wss、區域網路、中繼）、手機與電腦查驗端、網頁證明與裝置證明紀錄 |
| WP7 | OpenAC 年齡證明（引用 Bonds，第一個端對端測試） | Codex（原生與包裝）、Claude（流程與電路審查） | WP0 | `native/openac-age`、`profile/bonds/BondsAgeProof*` |
| WP8 | Longfellow mdoc ZK | Codex | — | Multipaz ZkSystem 註冊、近距離與 DC API、測試 |
| WP9 | App 整合與 UI | Claude | WP4、WP6、WP7、WP8 | 啟用停用列、證據卡、設定頁、紀錄 |
| WP10 | 驗收與文件 | Claude | 全部 | `docs/acceptance/p4-acceptance.md`、README、AGENTS.md、Review 指引的 P4 節 |

建議順序：WP0、WP2、WP8 平行開始，同時做 WP3a 的 M3a（SHA-256 與 inflate 子電路）供 WP1 量測；WP0 完成後先做 WP7 的原生部分，當作整條管線（建置、資產下載、Android 打包、自驗）的第一個端對端測試（D5）；接著 WP3b、WP5 平行；WP4、WP6 接在後面；WP9、WP10 收尾。

## 3. 工作包細節

### WP0 原生建置與 ZK 共用層（Codex）

目標：建立可在 Android 與桌面 JVM 載入的 Rust 原生函式庫與 Kotlin 綁定，以及所有 ZK 功能共用的能力偵測與資產下載。

可修改：`native/**`（新）、`core/src/commonMain/kotlin/diw/wallet/core/zk/**`（新）、`core/src/jvmCommonMain/kotlin/diw/wallet/core/zk/native/**`（新）、`core/build.gradle.kts`、`app/build.gradle.kts`（打包原生函式庫）、`gradle/libs.versions.toml`、`NOTICE`、`test-servers/src/test/kotlin/diw/testservers/zk/**`（新）。

Rust（`native/diw-zk-ffi`，uniffi 命名空間 `diw_zk`）：

```rust
pub struct ZkNativeInfo { pub crate_version: String, pub features: Vec<String>, pub tlsn: Option<String>, pub noir: Option<String>, pub bb: Option<String>, pub zkid: Option<String> }
#[uniffi::export] pub fn native_info() -> ZkNativeInfo;
#[uniffi::export] pub fn self_test() -> bool;            // 以內建小向量檢查各 feature 可執行
#[derive(uniffi::Error)] pub enum ZkError { InvalidInput { reason: String }, Unsupported { reason: String }, ResourceExhausted { reason: String }, Cancelled, Internal { code: u32 } }
```

- 工作區成員：`diw-zk-ffi`（cdylib，feature `zkpdf`、`tlsn`、`openac`）、`zkpdf-prover`、`zktls`、`openac-age`（後三者先建空殼，由各 WP 填入）。
- 每個長時間函式接受 `ZkCancelToken`（uniffi object，Kotlin 端可呼叫 `cancel()`），並在獨立執行緒以可設定的堆疊大小執行（OpenAC 需要 64 MB）。

Kotlin（commonMain，`diw.wallet.core.zk`）：

```kotlin
enum class ZkTier { A, B, C }
enum class ZkBackend { NOIR_ULTRAHONK, TLSN, OPENAC_SPARTAN2, LONGFELLOW }
data class ZkPlatformInfo(val abi: String, val totalRamMb: Long, val availableRamMb: Long, val freeDiskMb: Long, val isDesktop: Boolean)
data class ZkCapability(val tier: ZkTier, val backends: Set<ZkBackend>, val reasons: Map<ZkBackend, String>)
object ZkCapabilities { fun evaluate(platform: ZkPlatformInfo, native: ZkNativeStatus?): ZkCapability }

sealed interface ZkResult<out T> {
    data class Ok<T>(val value: T) : ZkResult<T>
    data class Failed(val reason: String, val retryable: Boolean) : ZkResult<Nothing>
    data object Cancelled : ZkResult<Nothing>
}

@Serializable data class ZkAsset(val id: String, val backend: ZkBackend, val role: Set<String>, val urls: List<String>,
    val gzipSha256: String, val gzipBytes: Long, val installedSha256: String, val installedBytes: Long, val license: String)
interface ZkAssetStore {
    suspend fun status(id: String): ZkAssetStatus                 // MISSING, PARTIAL, READY, CORRUPT
    suspend fun download(id: String, onProgress: (Long, Long) -> Unit): ZkResult<Unit>
    fun path(id: String): String?                                  // 只在 READY 時回傳
    suspend fun delete(id: String)
}
```

- 資產清單原始檔 `native/assets.json`，建置時成為資源 `zk/assets.json`，其 SHA-256 以 Kotlin 常數釘選；下載以 ktor，續傳、兩層 SHA-256 檢查、失敗刪除。
- 裝置等級規則見 p4-zkp.md 第 8 節，門檻放在一個常數物件，WP1 後更新。
- 平台取得 `ZkPlatformInfo`：Android 以 `ActivityManager.MemoryInfo` 與 `Build.SUPPORTED_ABIS`；桌面以 `OperatingSystemMXBean`。由 app 的 `PlatformServices` 提供，core 不直接碰平台 API。
- 原生函式庫打包：Android 放進 APK 的 `lib/arm64-v8a`、`lib/x86_64`；桌面放進 jar 的資源並在首次使用解壓到 App 資料目錄，依 OS 與架構選擇。`native/build.sh` 一次建出全部目標；CI 需要的步驟另寫成完整 workflow 草稿。

驗收：

- `./gradlew :test-servers:test --tests 'diw.testservers.zk.ZkNativeTest'`：桌面載入函式庫，`native_info()` 回傳 feature 清單，`self_test()` 為真。
- `ZkAssetStoreTest`：以 ktor `MockEngine` 模擬下載，涵蓋續傳、壓縮檔雜湊錯、安裝後雜湊錯、取消。
- `ZkCapabilitiesTest`：涵蓋三個等級與「原生函式庫載入失敗」。
- Android 模擬器（x86\_64）安裝 release APK 後，設定頁（WP9 前可先用測試用的 log 畫面）顯示 `native_info()`；PR 說明附上 APK 大小變化。

### WP1 效能量測與門檻（Codex；實機由使用者執行）

目標：用數字決定 zkPDF、OpenAC、zkTLS 能不能在手機上做，並設定裝置等級門檻。

產出：`docs/research/p4-benchmarks.md`、可在 App 內執行的量測頁（開發者設定內）、桌面量測指令 `./gradlew :test-servers:test --tests '*ZkBenchmark*' -Pbench=true`。

量測項目（每項記錄裝置型號、RAM、冷啟與熱啟時間、峰值原生記憶體、證明大小、驗證時間）：

1. Noir：SHA-256 壓縮 65、130、260 個區塊；inflate 子電路 16 KB、32 KB、40 KB 輸出（WP3a 的 M3a）；完整 `pdf_text_v1_1p`（WP3b 完成後重跑）。
2. bb 的零知識設定：記錄確認方式（CLI 說明、原始碼位置）與證明大小差異。
3. tlsn Proxy 與 MPC：回應 1 KB、16 KB、200 KB，持有端 Android，查驗端分別為桌面與另一支 Android（區域網路、中繼），記錄雙方傳輸量。
4. OpenAC：Prepare、Show、reblind、verify\_linked。
5. Longfellow：1 個屬性的 mDL 年齡證明產生與驗證。

驗收：至少一台中階機（使用者的 D1）與一台桌面的完整數據；文件最後一節寫出等級門檻建議，以及每種證明的記憶體與時間估計公式，供 `ZkCapability` 在選擇畫面顯示（p4-zkp.md 第 8 節）。

### WP2 zkPDF 公開側基礎函式（Codex）

目標：查驗端與證明前檢查需要的純函式，全部在 commonMain、可用合成 PDF 測試。

可修改：`core/src/commonMain/kotlin/diw/wallet/core/document/pdf/**`（只新增公開 API，不改既有行為）、`core/src/commonMain/kotlin/diw/wallet/core/document/zkpdf/Sha256State.kt`、`.../zkpdf/PdfZkSupport.kt`（新）、`test-servers/src/test/kotlin/diw/testservers/zkpdf/**`（新）。

介面：

```kotlin
/** SHA-256 with an exposed chaining state (FIPS 180-4). */
class Sha256State private constructor(...) {
    companion object { val INITIAL: Sha256State; fun of(words: IntArray): Sha256State }
    fun compress(block: ByteArray): Sha256State          // exactly 64 bytes
    fun words(): IntArray                                // 8 words, big-endian semantics
    fun toBytes(): ByteArray                             // 32 bytes
}
object Sha256Chain {
    /** Message M of a PDF signature: the two ByteRange parts concatenated, with SHA-256 padding. */
    fun message(pdf: ByteArray, byteRange: IntArray): Sha256Message
    /** States at the given block boundaries, computed over [message] with [skip] ranges taken from [states] instead. */
    fun stateAt(message: Sha256Message, block: Int): Sha256State
    fun digestWithWindows(message: Sha256Message, windows: List<HashWindow>): ByteArray   // uses each window's midOut
}
data class HashWindow(val firstBlock: Int, val blocks: Int, val midIn: Sha256State, val midOut: Sha256State)

object PdfZkSupport {
    /** The file as of the revision a signature covers (bytes [0, end of the ByteRange)), parsed with its own xref only. */
    fun signedRevision(pdf: ByteArray, byteRange: IntArray, password: String = ""): PdfFile
    /** Object number of the content stream of page [index]; fails for arrays of streams in v1. */
    fun pageContentObject(pdf: PdfFile, index: Int): Int
    /** Where the raw (still encoded) data of stream object [num] lies in the file. */
    fun streamExtent(pdf: PdfFile, num: Int): IntRange
    /** RC4 key stream for stream object [num], only for Standard V2 R3 with an empty user password (checked against /U). */
    fun rc4KeyStream(pdf: PdfFile, num: Int, length: Int): ByteArray?
    /** Decoder of the fonts named in page [index]'s resources: raw string bytes to text, and digits to codes. */
    fun fontDecoders(pdf: PdfFile, index: Int): Map<String, ZkFontDecoder>
}
interface ZkFontDecoder {
    val kind: Int                                        // 1 = single byte, 2 = two byte (Identity-H)
    fun decode(raw: ByteArray, literal: Boolean): String // handles literal escapes when literal is true
    fun digitCodes(): IntArray?                          // codes of '0'..'9', or null when a digit has no unique code
}

/** One text-showing operator of a page content stream, in stream order (added to PdfTextExtractor). */
data class PdfTextRun(val op: Int, val font: String, val raw: ByteArray, val literal: Boolean, val text: String, val x: Double, val y: Double)
// PdfTextExtractor.runs(pdf: PdfFile, page: Int): List<PdfTextRun>
```

- 盡量重用既有的 `PdfFile`（修訂版、物件位移）、`StandardSecurity`（RC4 物件金鑰）、`PdfFont`（ToUnicode、編碼空間）；只把需要的部分開成 `internal` 以外的 API 或加包裝，不複製實作。
- 字型解碼要處理 WinAnsi（含 `/Differences`）、Type0 Identity-H 加 ToUnicode（bfchar、bfrange 兩種）。
- `PdfTextExtractor.runs` 與既有 `extract` 共用同一套解碼與分行邏輯；以 `runs` 依既有規則組成的文字必須與 `extract` 完全相同。

驗收：

- `Sha256StateTest`：NIST 測試向量；隨機長度訊息逐塊壓縮的結果等於 JCA `MessageDigest`；`digestWithWindows` 在視窗的 midOut 正確時等於整體摘要。
- `PdfZkSupportTest`：以 `test-servers` 的 `fixtures/PdfComposer` 或其他測試產生器做出一頁含 Type0 與 WinAnsi 字型、有增量更新與 RC4（空白使用者密碼）的 PDF，驗證 `signedRevision` 不讀到之後的修訂、`streamExtent` 與實際位元組一致、`rc4KeyStream` XOR 後是合法 zlib、`fontDecoders` 能還原文字與數字編碼；`runs` 組成的文字等於 `extract`（含既有 P3 測試用的合成文件）。

### WP3a zkPDF Noir 電路（Claude 主導）

目標：實作 p4-circuits.md 第 3 節的 `pdf_text_v1_1p`。Claude 管控規格與審查，里程碑可逐步交給 Codex；交給 Codex 的里程碑以電路實作報告（第 4 節）回報，Claude 檢查後才合併。

範圍：`native/circuits/**`。

里程碑：

- M3a：`sha256_window` 與 `inflate` 子電路及其 Noir 測試；交給 WP1 量測。
- M3b：詞法掃描、運算子表完整性、錨點、承諾、述詞；完整電路；公開輸入順序與第 3.6 節一致；凍結 `ZkPdfPublicSpec` 與見證輸入格式，交給 WP3b。

驗收：`nargo test` 全過（子電路的正確與錯誤案例，含 Z8、Z9、Z13 的電路層案例）；`VERSIONS` 記錄 nargo、bb 版本與 ACIR、驗證金鑰的 SHA-256。

### WP3b zkPDF 證明器與合成測試文件（Codex）

目標：Rust 端的見證產生、證明與驗證，以及合成測試文件。電路由 WP3a 提供；需要改電路時依 WP3a 的方式提出並附報告。

可修改：`native/zkpdf-prover/**`、`native/diw-zk-ffi/src/zkpdf.rs`、`tools/zkpdf-testdocs/**`（新，合成測試文件產生器）、`test-servers/src/test/resources/zkpdf/**`、`test-servers/src/test/kotlin/diw/testservers/zkpdf/**`。

里程碑：

- M3c：Rust 見證產生（由下列輸入算出所有提示）、證明、自驗、驗證，uniffi 匯出。
- M3d：合成測試文件產生器（可在 M3a 期間先做）。

uniffi 介面：

```rust
pub struct ZkPdfWindowInput { pub role: String, pub mid_in: Vec<u8>, pub first_block_bytes_before: Vec<u8>, pub private_data: Vec<u8>, pub bytes_after: Vec<u8>, pub key_stream: Option<Vec<u8>> }
pub struct ZkPdfAnchorInput { pub font: String, pub literal: bool, pub raw: Vec<u8>, pub ordinal: u32 }
pub struct ZkPdfClaimInput { pub slot: u32, pub before_anchor: u32, pub after_anchor: u32, pub salt: Vec<u8> }
pub struct ZkPdfPredicateInput { pub kind: String, pub claim_slot: u32, pub date_format: u32, pub cutoff: u32 }
pub struct ZkPdfDigitTable { pub font: String, pub codes: Vec<u32> }
pub struct ZkPdfProveInput { pub circuit: String, pub binding: Vec<u8>, pub windows: Vec<ZkPdfWindowInput>, pub anchors: Vec<ZkPdfAnchorInput>,
    pub claims: Vec<ZkPdfClaimInput>, pub digit_tables: Vec<ZkPdfDigitTable>, pub predicates: Vec<ZkPdfPredicateInput>, pub assets_dir: String }
pub struct ZkPdfProof { pub proof: Vec<u8>, pub public_inputs: Vec<u8>, pub mid_outs: Vec<Vec<u8>>, pub anchor_outputs: Vec<ZkPdfAnchorInput>,
    pub commitments: Vec<Vec<u8>>, pub anchor_totals: Vec<u32>, pub claim_sources: Vec<Vec<u8>>, pub prove_ms: u64 }
#[uniffi::export] pub fn zkpdf_check(input: ZkPdfProveInput) -> Result<(), ZkError>;            // 不做證明，只檢查大小限制與 Word 類規則
#[uniffi::export] pub fn zkpdf_prove(input: ZkPdfProveInput, cancel: Arc<ZkCancelToken>) -> Result<ZkPdfProof, ZkError>;  // 內含自驗
#[uniffi::export] pub fn zkpdf_verify(circuit: String, proof: Vec<u8>, public_inputs: Vec<u8>, assets_dir: String) -> Result<bool, ZkError>;
#[uniffi::export] pub fn zkpdf_public_inputs(spec: ZkPdfPublicSpec) -> Result<Vec<u8>, ZkError>;  // 查驗端以自己的資料組出公開輸入
```

- `ZkPdfPublicSpec` 欄位與第 3.6 節一一對應（由 Claude 在 WP3a 的 M3b 凍結）。
- 合成測試文件產生器（Python 或 Kotlin 皆可，以 `-I` 執行 Python）：輸出「仿在學證明」（WinAnsi 數字、Type0 中文、QR 影像）與「仿出入境記錄」（RC4、數字為 CID）兩種，以 test-servers 的測試 PKI 簽章；字型使用授權允許再散布的字型子集（例如 Noto Sans CJK，OFL），在 NOTICE 記錄。

驗收：

- `ZkPdfCircuitTest`（test-servers）：p4-circuits.md 第 3.10 節 Z1、Z4、Z5、Z8、Z9、Z12、Z13、Z14 在 Rust 或 Kotlin 層重現（Z2、Z3、Z6、Z7、Z10、Z11 在 WP4 驗收）。
- 證明大小、證明與驗證時間寫進 WP1 的文件。
- 以 WP3a 的 `VERSIONS` 核對建置出的 ACIR 與驗證金鑰 SHA-256，不符時建置失敗。

### WP4 zkPDF 版型、遮蔽與查驗整合（Claude）

目標：從保存的文件產生 zkPDF 證據並放進衍生憑證，以及查驗端完整的 V1–V10。

範圍：`core/document/zkpdf/`（`ZkPdfProfile`、`ZkPdfProfiles`（釘選清單）、`ZkPdfPlanner`（選擇視窗，依描述檔的錨點標籤找出欄位，見 p4-circuits.md 第 3.11 節）、`ZkPdfEvidence`（p4-zkp.md 第 5.1 節）、`ZkPdfVerifier`）、描述檔的正規化規則（可重用 P3 的輔助函式）、`DerivedCredentials` 與 `DerivedEvidence` 的擴充、福州大學與移民管理局兩份文件的版型描述檔（以真實樣本在本機核對，描述檔只含版型標籤）。

里程碑：M4a 合成文件的產生與查驗；M4b 兩份真實版型；M4c 電腦版匯出與手機匯入 `.zkpdf`，以及自架主機產生（主機端是同一套原生程式庫的無頭程式，放在 `tools/zk-prover-server`，只接受設定裡加入的主機，結果在手機先驗證；p4-zkp.md 第 8 節）。

```kotlin
interface ZkPdfProofEngine {   // WP3b 的 uniffi 函式包裝
    suspend fun check(input: ZkPdfProveRequest): ZkResult<Unit>
    suspend fun prove(input: ZkPdfProveRequest, cancel: ZkCancel): ZkResult<ZkPdfProofOutput>
    suspend fun verify(circuit: String, proof: ByteArray, publicInputs: ByteArray): ZkResult<Boolean>
}
object ZkPdf {
    fun match(file: StoredFileView, report: DocumentReport): ZkPdfProfile?
    suspend fun prepare(pdf: ByteArray, profile: ZkPdfProfile, holderJwk: JsonObject, claims: List<String>, predicates: List<ZkPdfPredicateRequest>): ZkResult<ZkPdfProveRequest>
    suspend fun evidence(request: ZkPdfProveRequest, output: ZkPdfProofOutput): Pair<JsonObject, List<DerivedClaim>>   // zkPdf 與 zkOpen: disclosures
    suspend fun verify(credential: JsonObject, disclosed: Map<String, JsonElement>, trust: DocumentTrustSource, policy: ZkPdfPolicy): ZkPdfVerification
}
```

驗收：Z2、Z3、Z6、Z7、Z10、Z11 測試；以合成文件完成「產生衍生憑證、出示、查驗」；`.zkpdf` 匯出匯入與自架主機產生各一次；真實樣本在本機核對（不提交）。

### WP5 TLSNotary 原生綁定（Codex）

目標：Android 與桌面都能以 tlsn 當 prover，桌面與測試伺服器能當 verifier；Proxy 模式為預設、MPC 為選項。

可修改：`native/zktls/**`、`native/diw-zk-ffi/src/zktls.rs`、`test-servers/src/test/kotlin/diw/testservers/zktls/**`、`test-servers/src/main/kotlin/diw/testservers/zktls/**`（測試用 HTTPS 目標網站與查驗端）。

uniffi 介面（I/O 由 Kotlin 提供 WebSocket，Rust 端以位元組通道收發，tlsn 對目標網站的連線在 Proxy 模式由查驗端建立）：

```rust
#[uniffi::export(callback_interface)] pub trait ZkTlsChannel { fn send(&self, data: Vec<u8>) -> Result<(), ZkError>; fn receive(&self) -> Result<Vec<u8>, ZkError>; fn close(&self); }
pub struct ZkTlsRequest { pub host: String, pub port: u16, pub request: Vec<u8>, pub max_sent: u32, pub max_recv: u32, pub mode: String }   // "proxy" | "mpc"
pub struct ZkTlsTranscript { pub sent: Vec<u8>, pub received: Vec<u8>, pub server_name: String, pub cert_chain_der: Vec<Vec<u8>>, pub time: u64, pub cipher_suite: String }
pub struct ZkTlsReveal { pub sent: Vec<ZkRange>, pub received: Vec<ZkRange>, pub commit_sha256: Vec<ZkRange> }
pub struct ZkRange { pub start: u32, pub end: u32 }
#[uniffi::export] pub fn zktls_prove(channel: Box<dyn ZkTlsChannel>, request: ZkTlsRequest, choose: Box<dyn ZkTlsRevealChooser>, cancel: Arc<ZkCancelToken>) -> Result<ZkTlsTranscript, ZkError>;
#[uniffi::export(callback_interface)] pub trait ZkTlsRevealChooser { fn choose(&self, transcript: ZkTlsTranscript) -> ZkTlsReveal; }
pub struct ZkTlsVerified { pub server_name: String, pub cert_chain_der: Vec<Vec<u8>>, pub time: u64, pub sent: Vec<u8>, pub received: Vec<u8>, pub sent_mask: Vec<ZkRange>, pub received_mask: Vec<ZkRange>, pub commitments: Vec<ZkTlsCommitment> }
#[uniffi::export] pub fn zktls_verify(channel: Box<dyn ZkTlsChannel>, expected_host: String, port: u16, max_sent: u32, max_recv: u32, mode: String, cancel: Arc<ZkCancelToken>) -> Result<ZkTlsVerified, ZkError>;
```

- `ZkTlsRevealChooser` 在 prover 端拿到完整明文後回傳揭露範圍（由 WP6 依描述檔計算）；未揭露的位元組在 `ZkTlsVerified` 中以 0 填滿並由遮罩標示。
- 伺服器憑證以 tlsn 的根憑證庫驗證；另回傳憑證鏈，由 Kotlin 端用既有信任判定再算一次等級。
- 端對端加密通道（p4-zkp.md 第 5.2 節）在 Rust 端實作：`zktls_prove` 另收 `request_hash`（請求 JWS 的 SHA-256）與 `verifier_static_public`，`zktls_verify` 另收 `request_hash` 與 `verifier_static_private`，以 Noise `NK_25519_ChaChaPoly_SHA256`（例如 `snow` crate）包住 `ZkTlsChannel`；Kotlin 端的 `ZkTlsChannel` 只搬運密文。

驗收：

- `ZkTlsLoopbackTest`：test-servers 啟動本機 HTTPS 目標（測試 CA，tlsn 設定為信任該 CA）與查驗端，桌面 prover 以 Proxy 與 MPC 各完成一次，揭露 1 個片段、隱藏查詢參數；查驗端收到的明文中隱藏的部分為 0。
- 回應使用 chunked 時仍正確。
- Android 模擬器以 Proxy 模式對桌面查驗端完成一次（附上 log 摘要，不含明文）。
- Android 當查驗端：兩個模擬器（或模擬器與桌面持有端）以 Proxy 模式完成一次。
- Noise：prologue 不同或回應方金鑰不同時握手失敗；通道中途竄改一個位元組時中止。

### WP6 zkTLS 查驗頁、即時模式與存證（Claude）

範圍：`core/zktls/`（`ZkTlsProfile`、描述檔清單、`ZkTlsSession`（p4-zkp.md 第 5.2 節的請求 JWS、同意資料、揭露規劃）、`ZkTlsTransports`（wss、區域網路、中繼）、`WebProofCredentials`（vct `web-proof:1` 與 `web-record:1`））；查驗端（test-servers、桌面、Android）、可部署到使用者主機的中繼與 notary 服務；學信網與移民署查驗頁描述檔（欄位名稱沿用 P3，以真實回應在本機核對，描述檔只含版型）。

里程碑：

- M6a（過渡方案）：電腦版與測試伺服器當查驗方，wss 路徑。
- M6b（目標）：Android 當查驗方。查驗方在同一個區域網路開啟 WebSocket 伺服器（只綁私有位址），或連到中繼；中繼（`test-servers` 內的可部署實作）以 `room` 配對、只轉送位元組、每個房間有大小與時間上限。

驗收：學信網即時出示三次（手機為持有者；查驗方分別是電腦版、同網路的另一支手機、經中繼的另一支手機）；notary 簽發網頁證明憑證並以一般 SD-JWT VC 出示與驗證；裝置證明紀錄在 Android 產生並由桌面查驗顯示 T3 與「不是零知識證明」。

### WP7 OpenAC 年齡證明（引用 Bonds）

OpenAC 是可替換的後端之一（p4-zkp.md 第 2 節 D5），先引入是因為電路與資產現成。它也是 WP0 完成後第一個端對端測試：從資產下載、SHA-256 比對、uniffi 呼叫、Android 打包到自驗，整條管線先用它跑通，WP3b、WP5 再沿用。對 `predicate.rs` 或 zkID patch 的任何修改由 Claude 審查（p4-circuits.md 第 1.3 節）。

原生部分（Codex）：`native/openac-age/**`、`native/diw-zk-ffi/src/openac.rs`。

- 以 zkID `b395e09c225ff45b003f0087c28e2e208e22f944` 的 `wallet-unit-poc/ecdsa-spartan2` 為基礎，套用 Bonds-iOS `Native/OpenACAge` 的 `predicate.rs` 與 `zkid-mobile.patch` 的證明流程部分（Apache-2.0，保留著作權聲明並在 NOTICE 記錄），以 cargo-ndk 輸出 Android 兩個 ABI 與桌面三個平台；建置腳本同樣拒絕其他 zkID revision。
- 不使用 Mopro 與 witnesscalc\_adapter：匯出走既有的 `diw-zk-ffi`（uniffi），見證計算改用 circom-witnesscalc 的圖形計算（見下方「見證計算與授權」）。`ecdsa-spartan2` 以 `default-features = false` 引入（關掉 `native-witness`），見證由 `openac-age` 計算後以 `with_witness`（或同等的建構子）交給電路；zkID 的 `parse_witness` 讀 `.wtns`，circom-witnesscalc 的 `calc_witness` 正好輸出 `.wtns`，不需要轉換。
- 匯出的函式與 Bonds 相同：`create_age_prepare_input`、`create_age_show_input`、`prove_jwt`、`prove_show`、`reblind_jwt`、`reblind_show`、`generate_shared_blinds`、`verify_age_presentation`；另外匯出公開訊號讀取函式（Bonds 在 iOS 缺的部分）。
- 證明在 64 MB 堆疊的專用執行緒執行。

見證計算與授權（2026-10-17 決定，取代原本的 witnesscalc\_adapter）：

- 原因：witnesscalc\_adapter（MIT／Apache）在建置時 clone 並靜態連結 iden3 witnesscalc（GPL-3.0）與 GMP，App 的原生函式庫會變成 GPL-3.0。Bonds 的 README 沒有寫到這點。
- 改用 [circom-witnesscalc](https://github.com/iden3/circom-witnesscalc)（MIT）：執行期只有 `calc_witness(inputs_json, graph_bytes)`，依賴全為 MIT、Apache 或同等寬鬆授權（2026-10-17 以 `cargo tree -e normal --target aarch64-linux-android` 確認）。上游只支援 64 與 254 位元的質數，`native/openac-age/patches/circom-witnesscalc-secq256r1.patch` 加上 256 位元（secq256r1）的 `FieldOps`、圖形讀取與 `build-circuit -p secq256r1`；建置腳本 clone 上述 commit、套用 patch，其他 commit 或 patch 不符時失敗。建置需要 `protoc` 與 libclang（bindgen）；CI workflow 要加裝 `protobuf-compiler`，代理無法推送 workflow，完整檔案交給使用者貼上。
- 見證計算圖由 `native/openac-age/build-graphs.sh` 產生：zkID 的 `wallet-unit-poc/circom` 以 `yarn install`（circomlib 2.0.5、@zk-email/circuits 6.3.4）取得電路函式庫，`build-circuit circuits/main/<name>.circom <name>.graph -l node_modules -p secq256r1`。`build-circuit` 連結 circom 編譯器（GPL-3.0），只在建置時執行，不打包進 App。同一個 commit 重建兩次的圖形雜湊相同，`-i` 輸入檔不影響輸出。
- 2026-10-17 在雲端驗證（Linux x86\_64）：

  | 電路 | r1cs SHA-256（與 Bonds 釘選相同） | 圖形 bytes | 圖形 SHA-256 | gzip -9 約 | 見證計算 |
  |---|---|---:|---|---:|---|
  | `show` | `3809e705…a37a9a` | 551,178 | `352eeef11b56b48d2ffe71ea6f4a7c305fa4840cd2c111ae10878722891482a3` | 198 KB | 8 ms |
  | `jwt_2k` | `d4f8b34d…51dc6a` | 93,459,128 | `cc49cb201e406a03089d72217718b38941c893a970d5d809996605148a2ed63c` | 29.7 MB | 0.7 秒（circom wasm 3.2 秒） |

  zkID 附的輸入與 `generate-inputs.ts --size 2k` 重新產生的合成輸入（新的發行端與裝置金鑰）各一組，圖形算出的見證與 circom 產生的 wasm 見證計算器逐值相同（`show` 18,890 個、`jwt_2k` 1,523,033 個），代入 r1cs 後約束全部成立（`show` 19,084 條、`jwt_2k` 1,567,388 條）；改動一個見證值時有約束不成立，確認檢查有效。`show` 另以 1k、4k、8k 的輸入檔比對也相同。circom-witnesscalc 加 patch 後以 cargo-ndk 編出 Android arm64-v8a 的函式庫（約 1 MB），實機執行在 WP1 量測。
- 圖形是新的資產：`openac-age-graph-v1` 的 `jwt_2k.graph.gz` 與 `show.graph.gz`，由使用者上傳到本 repo 的 Release（代理不建立 Release）；`assets.json` 以安裝後的雜湊（上表）與上傳檔案的壓縮雜湊釘選，角色為持有端。查驗端不需要圖形。
- 電路資產的授權：zkID 電路是 MIT，但電路引用的 circomlib 2.0.5（`bitify`、`comparators`、`gates`、`multiplexer`、`mux1`、`poseidon`、`sign`、`sha256` 等）是 GPL-3.0-or-later，所以 r1cs、證明金鑰與圖形都含有編譯後的 circomlib 內容。【推論，非法律意見】這些資產與 App 分開下載，由 App 中 MIT／Apache 的程式讀取執行，類似直譯器執行 GPL 程式，App 本身仍為 Apache-2.0；資產本身依 GPL-3.0 散布，NOTICE 寫明 zkID commit、circomlib 版本與重建方法（`build-graphs.sh`）作為對應原始碼。Bonds 的 `openac-age-v1` 資產也是同樣情況。若之後要避免任何 GPL 資產，只能以其他授權重寫這些範本，電路與金鑰會改變而不再與 Bonds 相容，不在 P4 範圍。
- NOTICE（WP7 合併時更新）：在隨 App 散布的元件加入 circom-witnesscalc（MIT，含本 repo 的 patch）、zkID `ecdsa-spartan2` 與其依賴（Spartan2、circom-scotia、halo2curves 等，依 `cargo tree` 列出授權）、Bonds `predicate.rs`（Apache-2.0）；另立一段「下載的證明資產」，列出 `openac-age-v1` 與 `openac-age-graph-v1`、MIT（zkID）與 GPL-3.0-or-later（circomlib 2.0.5）以及原始碼位置；在不隨 App 散布的建置工具加入 circom 2.2.3 與 `build-circuit`（GPL-3.0）、protoc。同時刪除 NOTICE 末段「沒有複製 Bonds 原始碼」的說法或改為只描述 P3 以前的部分。

資產（`assets.json`，全部來自 `https://github.com/bonds-tw/backupTW-iOS/releases/download/openac-age-v1/`）：

| 檔案 | 壓縮 bytes | 壓縮 SHA-256 | 安裝 bytes | 安裝 SHA-256 | 角色 |
|---|---:|---|---:|---|---|
| `jwt_2k.r1cs.gz` | 28,202,219 | `efb45ed790e81fb6e1e3947f3749ee6ee1b3f03c069fff0227bd7ccb94d974a6` | 374,342,852 | `d4f8b34dfd454234872a34f47ea486545cb4d989c41ed75f856268718251dc6a` | 持有端 |
| `show.r1cs.gz` | 590,365 | `20d785277560fa96309832926bd7efc927e3976c0385b3e2bcae455ad4ad8c7d` | 4,017,428 | `3809e70502fa90f2038760da5f1399a1e3eb17923e5af872edf3dfa0b7d37a9a` | 持有端 |
| `prepare_proving.key.gz` | 23,609,142 | `3b45f8b1c24e5e82fc2462ed819a73fab0167dcce303e15e272fc6f99e44a277` | 431,866,474 | `853657d2e701215a65c5d97ab3cf5640e9aa8379ac6d106b7c82dc9b9d078e79` | 持有端 |
| `prepare_verifying.key.gz` | 23,609,093 | `d84ef20b28f0dd26b836022fc023424592d476a80b54d9ab80d51e43f698ee6a` | 431,866,442 | `9b45cc7462a236b1056d21c19e1e4dfc2cf52fd20538d43fbe072d9ed106e9d6` | 兩端 |
| `show_proving.key.gz` | 575,666 | `fa34e2cefe8da70476843f0a7037e249c7b1cf13c5c26a3f09a268393de61223` | 4,862,778 | `809f24ca6ee003b684e2282b77f5a47279528edee7654a3801770a2ffca67831` | 持有端 |
| `show_verifying.key.gz` | 575,630 | `b6daa9cefd23d27ce80bd182ced987caa1a4eeb91083fc6ceafbeb1210dfbad0` | 4,862,746 | `f0c447a9757d182e8aa23083bc3dba5a9a22f3e0fcbb344724568cc3c83352d8` | 兩端 |

（數值取自 Bonds-iOS `Native/OpenACAge/RELEASE-openac-age-v1.md` 與 `AgePredicateCircuitAssets.swift`，2026-10-16。）

見證計算圖（`https://github.com/mctea01/my-Bonds-fork-android/releases/download/openac-age-graph-v1/`，2026-10-22 併入 `assets.json`；gzip 以 `package_graphs.py` 重現，位元組相同）：

| 檔案 | 壓縮 bytes | 壓縮 SHA-256 | 安裝 bytes | 安裝 SHA-256 | 角色 |
|---|---:|---|---:|---|---|
| `jwt_2k.graph.gz` | 29,623,857 | `245734ace2b95c595d94b7ca920bdebc0a2b78be6f61ec1c9628e958be2cca55` | 93,459,128 | `cc49cb201e406a03089d72217718b38941c893a970d5d809996605148a2ed63c` | 持有端 |
| `show.graph.gz` | 197,657 | `062a85829dcac8d255ed17b5929c0cafd5f5573497daad1fa76bafba8f67e5b7` | 551,178 | `352eeef11b56b48d2ffe71ea6f4a7c305fa4840cd2c111ae10878722891482a3` | 持有端 |

PR #17 審查決定（2026-10-22）：查驗結果不含憑證效期與撤銷狀態；只支援 `vc.credentialSubject._sd` 容器，`BondsAgeCredential` 派生的自發年齡憑證也放在這個容器（細節見 p4-circuits.md 第 5 節）。Kotlin 流程每次操作使用私有目錄（輸入、instance、witness、shared blinds），Prepare 到 Show 與 reblind 之間不可刪除，完成或取消後整個刪除；reblind 保留原始 cache；reblind 本身不重複驗證，新 proof 一律經過之後必跑的 `verify_age_presentation`（兩個證明與連結）通過才讀取送出。原生端用核心數決定執行緒（2 到 8），釘選檔案的雜湊在同一個行程內只算一次（以實際路徑、大小與修改時間辨識）。

Kotlin 部分（Codex 寫包裝與測試，Claude 寫流程）：`core/profile/bonds/BondsAgeProof.kt`（請求解析與產生、證明包編碼與驗證、允許的回應主機）、`BondsAgeCredential.kt`（從 TWDIW 卡片取 SD-JWT 與生日欄位；從 `BondsNationalId` 派生只含 `birthdate` 的自發 SD-JWT）。

驗收：

- `BondsAgeProofTest`：Bonds 請求 QR 與證明包的編碼、解碼與欄位驗證（以 Bonds 原始碼的規則：版本 1、nonce 長度、claim 名稱、格式 2 或 3、證明大小上限、`issuerDID` 為 did:key）。
- `OpenAcAgeTest`（桌面）：以測試發行端的 ES256 SD-JWT 完成 Prepare、Show、reblind、驗證；cutoff 晚一天時驗證失敗；換一把發行端公鑰時驗證失敗。
- `OpenAcWitnessTest`（桌面）：以 zkID 附的 `inputs/jwt/2k`、`inputs/show/2k` 輸入，圖形算出的見證雜湊等於固定值（由 circom wasm 見證計算器取得並寫在測試內）；圖形檔雜湊不符時拒絕載入。
- 建置檢查：`cargo tree -e normal` 對 Android 與桌面目標都沒有 GPL、LGPL 或 AGPL 授權的 crate，也沒有連結 GMP；CI 在 `require` 模式執行。
- 與 Bonds 互通：使用者以 Bonds iPad 查驗方掃描本 App 的證明（BLE），以及本 App 查驗 Bonds 的證明，結果記在驗收文件。

### WP8 Longfellow mdoc ZK（Codex）

可修改：`gradle/libs.versions.toml`、`core/build.gradle.kts`、`core/src/commonMain/kotlin/diw/wallet/core/zk/LongfellowZk.kt`（新）、`app/.../ProximityModel.kt` 與 `ReaderModel.kt` 中 ZK 相關的最小改動、`test-servers` 的發行端（產生 ZK 友善 mdoc）與驗證端（DCQL `mso_mdoc_zk`）、相關測試。

- 加入 `org.multipaz:multipaz-longfellow:0.101.0`；建立 `ZkSystemRepository` 並註冊 `LongfellowZkSystem`，傳給 `ResponseBuilder` 的來源與 `PresentationVerifier`。
- ISO 18013-5：持有端處理 `ZkRequest` 回 `ZkDocument`；查驗端可要求 ZK。
- Windows 桌面沒有 Longfellow 原生函式庫：`ZkCapabilities` 回報不支援，相關選項顯示停用原因。

驗收：`./gradlew :test-servers:test --tests '*LongfellowZkTest'`：OpenID4VP DCQL `mso_mdoc_zk` 出示 `age_over_18` 並驗證；回應中沒有 MSO；`./gradlew :app:desktopTest --tests '*proximityZk*'`（近距離迴路）。

### WP9 App 整合與 UI（Claude）

依 p4-zkp.md 第 11 節：文件詳情、加入證件、使用、查驗（Android 與電腦版的官方網站即時查驗）、設定的「零知識證明」頁（含自架主機）、算力不足時的選擇畫面（p4-zkp.md 第 8 節）、同意畫面的洩漏說明、證據卡、紀錄；新增 `ZkModel` 管理背景證明與進度；截圖以 `uiScreenshots` 更新。

### WP10 驗收與文件（Claude）

`docs/acceptance/p4-acceptance.md`（自動化測試表與實機驗證表）、README 的功能與畫面、AGENTS.md 的 P4 要點、`docs/review/project-review.md` 的 P4 節。

## 4. 交接範本

接手一個工作包時，在 PR 說明或 issue 依下列格式回報：

```
工作包：WPn <名稱>
基準：整合分支 commit <sha>
完成的驗收條件：
- [x] <條件>（指令與結果摘要）
未完成或偏離規格：
- <項目>：<原因與建議>
介面變更提案：
- <無>／<提案內容>
新增第三方元件與授權：
- <無>／<名稱、版本、授權>
```

修改電路（`native/circuits/**`、OpenAC `predicate.rs` 或 zkID patch）時，另附電路實作報告：

```
電路：<名稱與版本>，里程碑 <M3x>
約束對照：
- <p4-circuits.md 小節或條目>：<實作方式、所在檔案與函式>
與規格不同之處：
- <無>／<差異、原因、對安全性的影響>
公開輸入：<順序與 p4-circuits.md 第 3.6 節是否一致>
測試：
- 正向：<測試名稱與結果>
- 負向：<對應 Z 編號、預期失敗的約束>
規模與量測：<約束或閘數、證明與驗證時間、記憶體峰值、測試機器>
VERSIONS：<nargo、bb 版本，ACIR 與驗證金鑰 SHA-256>
需要 Claude 特別檢查：<無>／<項目>
```

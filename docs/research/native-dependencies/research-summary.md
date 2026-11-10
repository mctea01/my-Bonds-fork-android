# 原生依賴跨架構研究：第一輪結果

**第四輪更新（2026-11-10）**：[Longfellow Windows PoC](longfellow-windows-poc.md) 找出原版 sha2-asm 的 Windows compile guard；隔離的六份 manifest patch 保留同版 SHA-2，成功建出 DLL，並在 Wine 通過 LLP64、電路配置／釋放及公開 proof 正反向驗證。v7 電路仍依賴編譯時來源目錄，尚不能直接部署。

**第三輪更新（2026-11-10）**：[Windows GNU 公開 proof PoC](bb-windows-proof-poc.md) 在 Wine 接受固定合成 UltraHonk fixture，拒絕修改 public input／proof 與整個 field 截斷，還原後再次接受。這是使用 fixture 自帶 key 的驗證，未涵蓋 registry／錢包政策、prover、原生 Windows 或跨架構互通。

**第二輪更新（2026-11-10）**：[Windows GNU BB PoC](bb-windows-link-poc.md) 已將官方 archive 與原 DIW bridge 連結為 PE executable，並在 Wine 通過 C API、buffer ownership、初始化與環境 hooks 子集。原生 Windows、有效 proof、BB 全庫重建與 MSVC 仍未測。下列第一輪紀錄保留其當時範圍；CSV 已反映第二輪證據。

日期：2026-11-09。研究分支：`claude/native-dependencies-pc-research`。重新取得指定遠端 `claude/project-thread-lu73pi`，HEAD 為 `3428b8ee12ac5e644f478d4c6e43854376202fa4`，與 v3 附件基準無差異。原環境的 `work` 分支不是該研究基準；沒有在其上修改產品。來源／規格雜湊與命令見 [baseline.json](evidence/baseline.json)。

本輪完成依賴來源盤點、14 個 target 的研究表、PC 直接 FFI 評估，以及可重現的隔離 PoC。**Linux x86_64 上，DIW runtime 與 Longfellow 均已取得不經 JVM/JNA 的 C 呼叫證據。其他架構仍以來源研究為主，沒有宣稱新增 App 平台支援。**

## 已執行結果

| 實驗 | 結果 | 證據與限制 |
|---|---|---|
| DIW runtime-only | Rust 1.99.1 + 原 Cargo.lock 建出 debug cdylib；C 載入、UniFFI contract/checksum、SHA-256 `abc`、native_info 讀取／釋放通過 | [runtime/result.json](evidence/runtime/result.json)、[建置記錄](evidence/runtime-build.log)；未啟用 proof features，非完整 C SDK |
| runtime 負向檢查 | 缺少檔案／不含必要符號的 libc 都以非零狀態拒絕 | [negative-probes.json](evidence/runtime/negative-probes.json)；不表示已測所有 ABI 錯誤路徑 |
| OPRF Rust API | 10 tests passed，包含 3 項 OPRF 測試：public key hash、無效 keys/points、隨機 blinding 與 proof/key binding | [oprf-tests.log](evidence/oprf-tests.log)；OpenAC/TLSn 在此組合關閉，BB disclosure circuit 與 OPRF C ABI 未測 |
| Longfellow C caller | 連結並呼叫六個 exports；已知 v7/1 spec、LP64 layout、null-input 拒絕通過 | [longfellow-linux-x86_64.json](evidence/longfellow-linux-x86_64.json)；使用釘選預建庫，未 source-build、未驗正向 proof／成功 allocation-free 路徑 |
| BB Windows static | 下載 v6.0.0 release archive、hash 符合 GitHub digest，確認 PE/COFF objects、C/C++ symbols | [bb-release-inspection.json](evidence/bb-release-inspection.json)；沒有 Windows 編譯／連結／執行，也未驗證建置 provenance |
| Gradle 依賴圖 | desktopRuntimeClasspath、releaseRuntimeClasspath 連網解析成功，沒有 FAILED 節點 | [desktop](evidence/gradle-desktop-online.txt)、[Android](evidence/gradle-android-online.txt)；先前離線 FAILED 記錄保留；不是 App 建置 |
| 預建檔盤點 | JNA 5.19.1 有 27 native entries；Longfellow JVM JAR 有 3、Android AAR 有 2；Linux SO 與已測上游 blob hash 相同 | [Maven 來源](evidence/maven-downloads.json)、[entries](evidence/maven-native-entries.csv)；其他項目為 [快取檢查](evidence/cached-native-entries.csv)，未逐一載入 |

兩個 C PoC 的工具、重現指令與輸出說明在 [tools/native-research](../../../tools/native-research/README.md)。所有二進位、下載來源與編譯產物放在 repo 外；repo 只加入研究文字、工具原始碼與無個資記錄。

交付檢查見 [validation.json](evidence/validation.json)：來源雜湊、文件連結、CSV／JSON、矩陣唯一性與範圍、Python 語法、archive scanner 合成測試均通過；它不增加任何平台功能驗收結論。

## 會影響後續實作的發現

1. **Windows BB 的問題不是「完全沒有原生庫」。** 官方 v6.0.0 有 Windows static；庫為 `libbb-external.a`，其 libc++／Itanium ABI 與 DIW 現有 archive 組合不同，不能直接當 MSVC `.lib`。上游已有 Win32 RNG、allocator、mmap guards；正式腳本仍拒絕 Windows，須處理 bridge、runtime 與 env hooks。
2. **最低 CPU 尚不能宣稱通用 x86-64。** 固定 BB 的 `arch.cmake` 使用 `-march=skylake`；未見 `TARGET_ARCH` 被讀，`DISABLE_ASM` 也不會禁止編譯器產生進階指令。Longfellow ARM64 另有 AES/PMULL 要求。
3. **Longfellow 可直接使用 C ABI，但文件／包裝有落差。** 0.102.0 已發佈 Intel macOS 庫；舊 header 與 Rust exports 不一致；JNA `NativeLong` 不能在 Windows LLP64 代表 `usize`。直接 C caller 用 size_t 可避開該包裝錯配，完整 App 政策仍需另實作。
4. **工具鏈與授權文字有版本漂移。** 實際 toolchain 為 1.99.1、MSRV 1.95，OpenAC wrapper 卻硬限 1.95.0；BB/Noir/snow 的部分 NOTICE 文字過時。本輪登錄缺口，不修改正式腳本或變更密碼學版本。
5. **UniFFI 是可由原生程式呼叫的版本化 ABI，不是穩定 public C SDK。** 生成 Kotlin 的 RustBufferByReference 配置大小／pointer 讀取有來源可見風險，尚未重現記憶體錯誤；需後續針對 callback 驗證。`rlib` 亦不能等同 C staticlib。
6. **目前不需 wasm2native／Perry。** Android matcher WASM 與瀏覽器 JS 確有執行期用途，但屬 host 契約；PC 密碼學依賴已有原生路線，bb.js/Circom WASM 測量用途不構成轉譯需求。

## 交付索引

| 工作包 | 交付與目前範圍 |
|---|---|
| R00 | [依賴清冊](native-dependency-inventory.csv)、[依賴圖](dependency-graph.md)：45 個用途條目，另附 581 個 lock package；傳遞授權／完整發行包稽核仍待補 |
| R01 | [Barretenberg](barretenberg-native.md)：固定源、預建檔、CPU、各 target blocker 與工時 |
| R02 | [Longfellow](longfellow-native-matrix.md)：C ABI、實測及目標矩陣 |
| R03–R05 | [Rust backends](rust-backends.md)：OpenAC、TLSn、Noir、zkPassport、OPRF 邊界 |
| R06 | [ABI contracts](native-abi-contracts.md)：ownership、panic、callbacks、CRT、JVM 與直接 FFI |
| R07 | [其他原生依賴](other-native-dependencies.csv)：JNI 包裝、底層 C/C++、系統／瀏覽器契約 |
| R08 | [工具鏈 targets](toolchain-targets.csv)：14 target triples；Android ABI 分欄 |
| R09–R10 | [備援工具結論](fallback-tools.md)：未觸發轉譯方案研究 |
| R11 | [PC readiness](pc-native-dependency-readiness.md)、[PC FFI matrix](pc-native-ffi-matrix.csv)：91 列；7 個 PC target/ABI × 13 依賴群 |
| R12 | [支援研究矩陣](native-support-matrix.csv)：98 列；14 targets × 7 核心後端群；[後續實作](future-porting-backlog.md) |

## 矩陣讀法與未完成的驗證

`source-reviewed` 只代表檢視固定來源。`linked` 表示表內 scope 所述產物已完成連結；OPRF 是 Rust 測試執行檔，並非已測 C 動態庫。`smoke-tested` 僅涵蓋列明的向量／ABI 子集。Longfellow 的 `library_native_build=not-tested` 與 `library_runtime_usable=smoke-tested` 可以同時成立，因為本輪使用預建庫而未自建它。

`pc_native_direct_ffi_ready` 與 native build/runtime 分開，Android 的 PC 欄為不適用。所有 `wallet_app_support` 都是 `deferred`；未執行測試填 `not-tested`。來源可行性、預建檔存在與工具鏈文件不能升格為已支援。各 family 的傳遞依賴詳見清冊，而非把每個 Cargo.lock package 重複展成支援聲明。

尚未執行：Windows／ARM／macOS／32-bit／RISC-V／musl 原生 PoC、BB 全庫重建與 proof、Longfellow source-build 與 proof、OpenAC/TLSn feature 功能、最舊 CPU/OS runner、完整 callback/allocator 壓力測試、跨架構雙向證明驗證。此階段不修改 App、Kotlin、Gradle、CI、正式 build scripts、電路或發行配置；不建立平台支援 PR；iOS 不在本輪。

# R02：Multipaz Longfellow 原生依賴與直接 C ABI

研究日期：2026-11-09。DIW 基準 `3428b8ee12ac5e644f478d4c6e43854376202fa4`。本輪不更動 Kotlin、loader、電路、參數或正式建置腳本；不研究 iOS。上游目錄中的 iOS archives 僅確認存在，不評估。

## 結論與證據等級

Multipaz 0.102.0 的 `libzkp` 是 Rust `cdylib`／`staticlib`，公開六個 C exports，沒有強制 JVM/JNI/JNA 相依。Linux x86_64 上，獨立 C 執行檔已連結並呼叫六個 exports，成功比對 v7／1 attribute 的公開 spec 及錯誤回傳；狀態是 **`smoke-tested`（ABI 子集）**。沒有產生／驗證證明、沒有跨架構互通驗證，也沒有自原始碼編譯該庫；這些項目均為 `not-tested`。其他 target 的研究狀態是 `source-reviewed`，不可因預建庫存在而宣稱可載入。

現有 DIW `AGENTS.md:167` 與 `LongfellowNative.kt` 的註解未列 Intel macOS，但 **Multipaz 0.102.0 的 Git tree、build script 與 JVM loader 均已包含 macOS x86_64**。這是盤點修正，不代表本次已在 Intel Mac 跑過。

## 來源、鎖版與依賴鏈

| 項目 | 固定證據 |
|---|---|
| Multipaz tag | `0.102.0`；annotated tag object `c1ceb0dfa1af52bd57c064efb4b9e9de53427274`；commit `a015c9d93874fe6e09df1354006353ce6f94751d` |
| Rust wrapper | `multipaz-longfellow-ffi` 0.1.0；edition 2021；`crate-type = ["cdylib", "staticlib"]`；release `panic=abort`, LTO, codegen-units=1 |
| Longfellow submodule | `d5e6be77336933d50bf7f25a954f8ec273eb51ce`；`.gitmodules` 的 `branch=main` 不取代 Git tree 的固定 gitlink |
| 執行依賴 | `mdoc-zk-runtime` 0.1.0 → Rust mdoc parser／circuits／runtime algebra／random／Ligero／ZK；另有 `libc`, `zstd`（C zstd）、`sha2`（asm feature）、`aes`, `getrandom` |
| 不應誤分類 | 上游仍有 C++ 樹，但本版 Multipaz wrapper 走 Rust runtime；不是 JNI C++ glue。`testonly` 名稱不全等於 dev-only：runtime manifest 明確啟用多個 circuit crates 的 `testonly` feature，它們屬該依賴圖的一部分 |
| 鎖檔缺口 | tag tree 的 wrapper 及 submodule Rust workspace 未附 Cargo.lock；`libc="0.2"`, `zstd="0.13"` 等範圍無法證明預建庫當時完整解析版本。DIW `native/Cargo.lock` 不鎖住這個獨立發佈物 |
| 授權 | Multipaz wrapper／Longfellow 源為 Apache-2.0；重新建置前須以實際解析鎖檔核對傳遞 crate 與 zstd 授權。此次沒有將第三方二進位或原始碼加入產品 |

固定來源：[Multipaz tree](https://github.com/openwallet-foundation/multipaz/tree/a015c9d93874fe6e09df1354006353ce6f94751d/multipaz-longfellow)、[Rust wrapper](https://github.com/openwallet-foundation/multipaz/blob/a015c9d93874fe6e09df1354006353ce6f94751d/multipaz-longfellow/rust/src/lib.rs)、[wrapper Cargo](https://github.com/openwallet-foundation/multipaz/blob/a015c9d93874fe6e09df1354006353ce6f94751d/multipaz-longfellow/rust/Cargo.toml)、[runtime Cargo](https://github.com/longfellow-zk/longfellow-zk/blob/d5e6be77336933d50bf7f25a954f8ec273eb51ce/rust/applications/mdoc_zk/runtime/Cargo.toml)。Git blob 清單見 [longfellow-source-pins.json](evidence/longfellow-source-pins.json)。

實際 DIW 呼叫位置：`core/build.gradle.kts:132` 引入 Multipaz Longfellow；`core/src/jvmCommonMain/kotlin/diw/wallet/core/zk/LongfellowNative.kt` 預先載入；`core/src/commonMain/kotlin/diw/wallet/core/zk/LongfellowZk.kt` 管理 spec、證明及查驗。這是一條獨立於 `diw_zk` Cargo features 的條件式 mdoc ZK 執行依賴。

## ABI 契約：現有 JVM 與未來 Native

| Export | 契約／所有權 |
|---|---|
| `find_zk_spec_by_attributes(size_t,size_t,Spec*) -> int32_t` | caller 提供輸出 struct；成功 0，找不到或 null out 為 -1；`system` 指向靜態 NUL-terminated bytes，不可釋放；hash 為 65-byte 陣列 |
| `generate_circuit(const Spec*,uint8_t**,size_t*) -> int32_t` | 成功輸出 `libc::malloc` 配置的 bytes；只在成功後讀取輸出並用同一庫的 `free_circuit_bytes` 釋放 |
| `run_mdoc_prover(...) -> int32_t` | 同步，借用 circuit／mdoc／transcript／attrs／UTF-8 NUL strings；成功 proof 為同庫 malloc，配對 `free_mdoc_proof` |
| `run_mdoc_verifier(...) -> int32_t` | 同步、借用輸入，無輸出 allocation；proof／transcript／attributes 的 bytes 和 spec 必須一致 |
| `free_mdoc_proof(uint8_t*,size_t)` | Rust 實作忽略 length，null 為 no-op；非 null 必須為同庫擁有的 allocation，不可傳 caller buffer |
| `free_circuit_bytes(uint8_t*,size_t)` | 同上，不可跨 Windows CRT 用 host `free` |

`RequestedAttributeC` 是 64／32／64 bytes 加三個 `usize`；`ZkSpecStructC` 是 pointer、65-byte hash、四個 `usize`。本次 LP64 實測大小分別 184、112 bytes，`num_attributes` offset 80。**不可把這些固定尺寸套用到 32-bit**。C caller 使用 `size_t`；Rust 使用 `usize`。呼叫約定是 target 的 `extern "C"`，沒有 `JNIEnv*`。

上游 [mdoc_zk.h](https://github.com/openwallet-foundation/multipaz/blob/a015c9d93874fe6e09df1354006353ce6f94751d/multipaz-longfellow/rust/include/mdoc_zk.h) 與 Rust exports 不完全相符：它宣告 `circuit_id`、`find_zk_spec`、`kZkSpecs`，實測 SO 沒有這些符號；反而缺 `find_zk_spec_by_attributes` 和兩個 free 宣告。本次 PoC 依固定 Rust source 寫最小宣告，不能把該舊 header 視為已驗證 SDK。未來應先向上游修正 header 並加入 layout／symbol parity 檢查。

現有 [LongfellowCLibrary.kt](https://github.com/openwallet-foundation/multipaz/blob/a015c9d93874fe6e09df1354006353ce6f94751d/multipaz-longfellow/src/javaSharedMain/kotlin/org/multipaz/mdoc/zkp/longfellow/LongfellowCLibrary.kt) 使用 JNA `NativeLong`／`NativeLongByReference` 表示 `usize`。在 Windows LLP64，C long 為 32-bit、size_t 為 64-bit，因此 **即使將來成功建出 DLL，這個 JVM wrapper 仍須修正**；Native caller 可直接用 size_t，毋須繼承這個錯誤。Windows loader 目前也沒有分支。這些只記為後續整合要求，本輪未改 Kotlin。

Rust FFI 沒有提供跨版 ABI version 握手；必須固定 wrapper／header／library／spec 資產整組版本。`find_spec_from_c` 先匹配 hash，再回退 version+attribute count，不能以它代替呼叫端對完整 spec 的嚴格驗證。string 必須 NUL 結尾且有效；pointer+length 必須真實可讀；attrs 長度欄會被 min 到陣列上限，但不代表任意輸入已安全。release panic 會 abort 整個程序，不存在可恢復的 panic boundary。無 callbacks 或明確初始化函式；circuit compilation 使用 scoped threads，並行安全、資源峰值、取消語義尚未驗證。Native host 須在工作執行緒排程並控制輸入／memory budget。

## 各 target 矩陣

表中「預建」先由固定上游 Git tree 確認，再下載 Maven 0.102.0 的 JVM JAR 與 Android AAR 核對：確有三個桌面與兩個 Android 產物；JAR 內 Linux SO 的 SHA-256 與本次 PoC 使用的上游檔案完全相同。下載來源與雜湊見 [maven-downloads.json](evidence/maven-downloads.json)、逐檔清單見 [maven-native-entries.csv](evidence/maven-native-entries.csv)。除 Linux x86_64 ABI smoke 外，其餘執行結果皆 `not-tested`。原始碼建置在本輪全部 `not-tested`。

| Target | 預建／產物 | 原生與 FFI 評估 | 主要限制／後續試驗 |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | `nativeLibs/linux-x86_64/libzkp.so` | C ABI 子集 `smoke-tested`；shared 使用不需 JVM；staticlib 由 manifest 宣告但未建 | NEEDED libc/libm/libpthread/libdl/ld-linux；最高 GLIBC symbol 2.17。未在 glibc 2.17 系統執行，不把 symbol floor 當 OS 驗收；最低 CPU 未完整量測 |
| `aarch64-unknown-linux-gnu` | 未見 | `source-reviewed`；Rust+C zstd 來源路線合理 | wrapper config `+aes,+sha2`；runtime AArch64 compile_error 要求 AES/PMULL；ARMv8 基本指令集不夠。需 aarch64 sysroot/linker、真機 CPU gate 與合成 proof |
| `x86_64-pc-windows-msvc` | 未見 | `source-reviewed`；預期輸出 zkp.dll／zkp.lib，未編譯 | zstd/sha2 asm 的 MSVC toolchain、UCRT 與 exports 驗證；header 過時；現有 JNA size_t 錯配與 loader 缺口；先 C caller 再 JVM 整合 |
| `aarch64-pc-windows-msvc` | 未見 | `source-reviewed` | wrapper 尚無 ARM64 Windows rustflags；須明確處理 +aes/+sha2、ARM64 MSVC C compiler、zstd；LLP64 與 CPU capability 同樣必查 |
| `aarch64-apple-darwin` | `nativeLibs/macos-arm64/libzkp.dylib` | `source-reviewed`，直接 C ABI 有來源依據 | Apple SDK／Clang；deployment target／Mach-O imports 尚未量測；不可將其他 Apple 平台設定套用 macOS |
| `x86_64-apple-darwin` | `nativeLibs/macos-x86_64/libzkp.dylib` | `source-reviewed`；上游已有 Intel loader | 先在 Intel Mac 或有效執行環境跑相同 C smoke，後做 proof；不需以「缺上游產物」為理由 fork |
| `aarch64-linux-android` (`arm64-v8a`) | `jniLibs/arm64-v8a/libzkp.so` | `source-reviewed` | NDK + cargo-ndk；`+aes,+sha2` 不是所有 ARM64 Android 的無條件 baseline；最低 API 未從 ELF 驗證 |
| `x86_64-linux-android` (`x86_64`) | `jniLibs/x86_64/libzkp.so` | `source-reviewed` | 模擬器／真機 CPU、Android linker/API、NDK zstd 編譯；Android SO 不等於 Linux glibc SO |
| `armv7-linux-androideabi` (`armeabi-v7a`) | 未見 | `source-reviewed`，條件式 | 上游有 generic／ARM NEON／32-bit limbs，不等於整個 mdoc stack 可用；pointer layout、address space、130 MB circuit 上界、prove peak memory；先 verifier-only crate 研究 |
| `i686-linux-android` (`x86`) | 未見 | `source-reviewed`，條件式 | 32-bit layout、stack/heap、asm fallback；需明確限制輸入長度，不能只改 ABI 清單 |
| `riscv64gc-unknown-linux-gnu` | 未見 | `source-reviewed`，前瞻 | runtime algebra 有 generic fallback；Rust target／sysroot、zstd/sha2 fallback、endianness／alignment／性能均需編譯與向量驗證 |
| `x86_64-unknown-linux-musl`／`aarch64-unknown-linux-musl` | 未見 | `source-reviewed`，前瞻 | 不可重用 glibc SO；staticlib host 與 musl link 優先。cdylib 如需 `-C target-feature=-crt-static` 必須獨立驗證；ARM64 仍需 crypto flags |

CPU 來源：[architecture selection](https://github.com/longfellow-zk/longfellow-zk/blob/d5e6be77336933d50bf7f25a954f8ec273eb51ce/rust/runtime/algebra/src/arch/mod.rs)、[AArch64 compile guard](https://github.com/longfellow-zk/longfellow-zk/blob/d5e6be77336933d50bf7f25a954f8ec273eb51ce/rust/runtime/algebra/src/arch/aarch64.rs)、[wrapper config](https://github.com/openwallet-foundation/multipaz/blob/a015c9d93874fe6e09df1354006353ce6f94751d/multipaz-longfellow/rust/.cargo/config.toml)。x86 的 PCLMUL/SSE2 快路徑依編譯 cfg 選取，否則 generic；不能據此斷言預建庫每條路徑皆 x86-64-v1。submodule 自身 `.cargo/config.toml` 設 target-cpu=native，但 Cargo 從 wrapper 目錄呼叫時不會讀 dependency 目錄的 config；必須記錄實際 invocation 與有效 flags，避免不必要地把 host CPU 設定推論成已發佈庫基準。

## 已執行的隔離 PoC

由固定 Multipaz commit 下載 Linux SO，SHA-256 `d7b7a64ea444a268b5bf444fa4f283ddf0f5ae38e7d0a65f10d2dd3dc`。Python runner 先驗 hash，再以 host C compiler 連結，所有 binaries 均在自動清除的暫存目錄。報告保存 compiler／glibc、完整命令、return code、readelf 與 nm 輸出、probe 原始碼 hash；不保存私密輸入。

```sh
python3 tools/native-research/longfellow_probe.py \
  --output /tmp/longfellow-linux-x86_64.json
# 可重用同 SHA-256 的離線庫：加 --library /path/to/libzkp.so
```

實作：[longfellow_probe.c](../../../tools/native-research/longfellow_probe.c)、[longfellow_probe.py](../../../tools/native-research/longfellow_probe.py)；本次證據：[longfellow-linux-x86_64.json](evidence/longfellow-linux-x86_64.json)。測項是 symbol linkage、LP64 layout、已知公開 spec、null pointer 早期拒絕、null free。沒有真正 malloc/free 成功輸出循環；沒有錯誤 proof／有效 proof 的密碼學驗收。每一項界線應原樣帶入總矩陣。

## 來源建置草案與後續成本

以下是下一輪隔離命令草案，**尚未執行**。固定 gitlink，不照上游 README 更新到 main；不執行會建置其他平台並覆寫上游 src 的總腳本。

```sh
git clone --no-checkout https://github.com/openwallet-foundation/multipaz.git /tmp/multipaz-native
git -C /tmp/multipaz-native checkout --detach a015c9d93874fe6e09df1354006353ce6f94751d
git -C /tmp/multipaz-native submodule update --init multipaz-longfellow/rust/longfellow-zk
cd /tmp/multipaz-native/multipaz-longfellow/rust
# Upstream does not ship this lockfile. Save and review the first resolution.
cargo generate-lockfile
cargo build --release --locked --target x86_64-pc-windows-msvc
# On a Linux ARM64 host with ARMv8 crypto extensions and C compiler:
cargo build --release --locked --target aarch64-unknown-linux-gnu
# On the matching macOS toolchain:
cargo build --release --locked --target x86_64-apple-darwin
```

Windows 命令須在適當 Visual Studio developer environment 執行；這不是宣稱 Linux 預設能連到 MSVC。交叉編譯需另外設定 linker、SDK、C compiler，不只安裝 Rust target。首份新 lockfile 必須註明為「本輪解析」，不能冒稱與既有預建庫完全相同。

粗估為一位熟悉 Rust/FFI 工程師的研究人日，未含產品驗收：header parity 與 Windows size_t 問題整理 1–2 日；Windows x86_64 原生 compile/link/C smoke 2–5 日；Linux ARM64 1–3 日；Intel macOS 預建 C smoke 0.5–1 日；Windows ARM64 3–7 日；32-bit／riscv64／musl 每組 3–10 日且受 memory／toolchain 影響。每個平台之後另需公開合成 mdoc 的正反向 proof 驗證、跨架構雙向驗證與 memory／thread 壓力測試，未估入上述 smoke 工期。

優先向上游提交 header／exports 一致性、size_t/JNA mapping、可重現 Cargo.lock／toolchain／產物 provenance 議題；有具體 compiler error 且上游短期無法修補時才評估最小 fork。避免為移植改動 proof 格式、ZK spec、金鑰與參數。

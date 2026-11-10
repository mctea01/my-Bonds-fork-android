# R01：Barretenberg 6.0.0／zkPDF 原生可移植性

**第三輪更新**：[公開 proof PoC](bb-windows-proof-poc.md) 已在 Wine 完成單一固定 fixture 的正反向驗證；前兩輪的 proof 未測描述保留為歷史紀錄。

**第二輪更新**：[Windows GNU 連結與 Wine PoC](bb-windows-link-poc.md) 已完成；本文件以下保留第一輪來源研究的歷史結論。「未連結／未執行」描述的是第一輪，最新狀態與限制以第二輪報告及矩陣為準。

研究日期：2026-11-09。專案基準 `3428b8ee12ac5e644f478d4c6e43854376202fa4`；BB 固定為 `0219f11d8133970df3974fe5ae65e006bf8c193a`，Noir 為 `5a7ee9bf5ed8973076df7bb0d2b723024db09ae7`。用途為 `runtime-conditional`（`zkpdf`，同時服務 zkPassport 證明／驗證）；CLI 的資產產製屬 build-only。此報告沒有變更正式來源、電路、金鑰或證明格式。

## 本輪結論與證據界線

**Windows x86_64 已有同標籤的官方原生靜態庫，缺口主要在專案接合與 ABI 驗證，不能再以「上游僅有 POSIX」解釋全部阻塞。** 官方 `v6.0.0` tag 的 GitHub ref 直接指向上述固定 commit；release 提供 `barretenberg-static-amd64-windows.tar.gz`。本輪實際下載、核對 GitHub SHA-256、檢查 archive 與符號，但沒有編譯、連結或執行 Windows PoC。

- 壓縮檔 SHA-256：`27653ef44281c79cc92ab724d2c2dba63e70a8692c88d16c9737e1d8f6751af3`。
- 內容只有 `libbb-external.a`；SHA-256：`f401bb3a644d5be1163d1df95a2968f33fa053d4e2c7b065f16f436cbb644699`。這是 PE/COFF x86-64 objects 的靜態 archive，不是 DLL，也不是 CLI。
- `bbapi` 為 C symbol；同時有 C++ `CircuitProve::execute`／`CircuitVerify::execute`，名稱採 Itanium mangling、標準庫為 `std::__1`。不可把它當成能直接接上 MSVC C++ ABI／MSVC STL 的 `.lib`。
- release 的 `target_commitish` 是 `next`；**鎖版證據採 tag ref，不能使用這個 branch 名證明二進位來源**。下載 digest 能驗證檔案一致，未完成簽署 provenance 或可重現建置比對。
- 所有本輪架構結論最多為 `source-reviewed`；build/link/load/function 皆為 `not-tested`。下載既有 archive 不列為本輪 `object-produced`。

實際輸出：[release metadata 與來源雜湊](evidence/bb-release-inspection.json)、[Windows archive 檢查](evidence/bb-windows-static-inspection.txt)。正式 App 支援及跨架構互通皆不在本輪已驗證事項。

## 固定上游來源與專案落差

以下連結全部固定在本次 BB commit：

| 證據 | 已核對內容 | 對後續實作的影響 |
|---|---|---|
| [CMakePresets.json](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/CMakePresets.json#L544) | `amd64-windows` 使用 Zig `x86_64-windows-gnu`、`BB_LITE=ON` | 先重現 GNU/Zig 路線，再評估 MSVC；不必先重寫 RNG |
| [CMakeLists.txt](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/CMakeLists.txt#L137) | Windows 連結 `ws2_32 bcrypt psapi`；C++20；最低 CMake 3.24 | 專案 `build.rs` 的通用 `stdc++`／`pthread` 不能直接照搬到 MSVC |
| [engine.cpp](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/src/barretenberg/numeric/random/engine.cpp) | `_WIN32` 用 `BCryptGenRandom`；Android 用 `/dev/urandom`；Linux 用 `getrandom` | README 列出的 `sys/random.h` 已不是 Windows 分支的直接阻塞 |
| [mem.hpp](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/src/barretenberg/common/mem.hpp) | Windows `_aligned_malloc/_aligned_free`；Apple/Android `posix_memalign` | allocator 成對使用；不能跨 CRT 釋放 |
| [backing_memory.hpp](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/src/barretenberg/polynomials/backing_memory.hpp) | `sys/mman.h`／mmap 部分排除 `_WIN32` | 仍須測記憶體路徑，但不能宣稱 Windows 無 guards |
| [src/CMakeLists.txt](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/src/CMakeLists.txt#L236) | `bb-external` 包含 core、env、vm2_stub；`barretenberg` 排除 env | 官方 archive 與 DIW 現有三個 archive 組合不同；env hooks 必須核對，不能直接換檔名 |
| [arch.cmake](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/cmake/arch.cmake) | x86_64 無條件 `-march=skylake` | **`DISABLE_ASM=ON` 不表示 x86-64 v1；AVX2 等 compiler-generated instructions 仍可能出現** |

專案 [`build_bb.py`](../../../native/zkpdf-prover/tools/build_bb.py) 僅接受 Linux x86_64、macOS arm64、Android arm64/x86_64；其他 target 一律退出 `bb_windows_port_required`，此訊息也會誤涵蓋 Linux aarch64／macOS Intel。它傳入 `TARGET_ARCH=x86-64`，但本次檢查的 pinned 上游 CMake 不讀此變數；不能據此聲稱最低 CPU 為 x86-64 v1。應先保留 verbose compile commands，檢查最後實際 `-march`，再做 baseline machine／CPU mask 測試。

[`build.rs`](../../../native/zkpdf-prover/build.rs) 假定 GNU style `-fPIC`、`-pthread`、`ar crs` 與 archive 命名，Windows 會走 `stdc++`／`pthread` 分支；沒有 MSVC 選項、DLL export 策略或 Windows 專屬 system libraries。這是專案 build integration 限制，不是整個 BB 原始碼不可移植的證明。

[`native/zkpdf-prover/NOTICE`](../../../native/zkpdf-prover/NOTICE) 仍寫 BB 2.1.9／Noir beta.15 及舊 msgpack/libdeflate pins。這是現有文件漂移，本輪只登錄，應在日後正式原生整合前修正。既有 `p4-benchmarks.md` 主要量測 BB 2.1.9，不可當作 BB 6.0.0 的建置時間、記憶體或功能通過證據。

## 依賴與 runtime 契約

固定上游 build dependencies：msgpack-c `c0334576ed657fb3b3c49e8e61402989fb84146d`（header templates，BSL-1.0 的授權敘述需對新版本再次核對）、Tracy `5d542dc09f3d9378d005092a4ad446bd405f819a`（headers；正式配置未啟用 profiling）、libdeflate `v1.24`（C runtime library，tag 尚未在本輪展開 commit）。CMake 以 `sh`／Git 抓 msgpack 和 Tracy；Windows 原生命令提示字元不能直接承接全部建置。BB_LITE 排除 lmdb/world_state/ipc/nodejs_module；不應為 zkPDF 加入那些 server-only 套件。

BB 主體 [Apache-2.0](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/LICENSE) 已核對；本輪未新增或散布二進位依賴。正式引入預建庫仍需確定其編譯選項、全部靜態組件授權及供應鏈來源。Windows archive 實際 unresolved symbols 包含 `BCryptGenRandom`、libdeflate、C++ exception runtime、WinSock 與 `_aligned_malloc/_aligned_free`；這是 archive imports，不等於完成連結後的 DLL imports。

現行 DIW [`bridge.cpp`](../../../native/zkpdf-prover/cpp/bridge.cpp) 已是非 JVM C ABI：

| C symbols | 所有權與前置條件 | Native 主程式缺口 |
|---|---|---|
| `zkpdf_bb_init`, `zkpdf_bb_init_verifier` | 前者輸入 G1 134,217,792 bytes、G2 128 bytes；呼叫端驗證資產；全域 CRS 先初始化者生效 | 必須沿用 Rust `Session` 的全域鎖與 verifier/full 狀態，不能在 verifier 初始化後無條件升級 prover |
| `zkpdf_bb_prove`, `zkpdf_bb_verify` | 輸入借用；呼叫端配置輸出、傳容量；同步；`size_t` 為目標 pointer width；0 成功、1 失敗 | 需共享 C header、長度與 null pointer 前置條件、符號匯出表；不要直接呼叫裸 bridge 繞過 Rust 資產驗證及欄位約束 |
| `zkpdf_bb_vk` | 同樣由 caller 配置輸出；僅產製資產時使用 | 不需設為 App 正式 runtime API |

Bridge 把 C++ 例外攔在 `noexcept` 邊界內、固定 workers=2、禁止低記憶體落盤、抑制 diagnostics。這些 hooks 是 DIW 語義的一部分。現有符號是內部靜態連結入口；不能由原始碼宣告推定已由 `libdiw_zk` 動態匯出。未來 Native 主程式可走相同 Rust API 或受控 C facade，毋須 JVM，但尚無完成驗證、版本化的公開 C SDK。

上游另有 [C `bbapi`](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/src/barretenberg/bbapi/c_bind.cpp)：以 MessagePack 命令／回應、`uint8_t**`／`size_t*` 傳出配置結果，使用全域 `BBApiRequest`。它確實存在於 Windows archive，名稱中的 `WASM_EXPORT` 巨集也會產生 native `extern "C"`；不能因此誤判只支援 WASM。但其 allocator／scratch buffer 契約、錯誤訊息敏感性、thread serialization、CRS 與 schema 版本皆須另審；不能用它無聲取代 DIW bridge。

## 每個目標的可行性與下一個最小驗證

下列工時是單一熟悉 C++/Rust 工程師、工具鏈可用後的研究估計，不是交期。各列皆 `source-reviewed`，本輪未做 build/link/load/function；官方產物欄「列出」指 release metadata，只有 Windows x86_64 static 已實際解包。

| Target / Android ABI | 官方同版原生產物 | 原生路線、CPU／系統及 blockers | 下一個 PoC／估計 |
|---|---|---|---|
| `x86_64-pc-windows-gnu` | static + CLI 列出，static 已解包 | Zig/GNU 路線已在上游；Skylake compile option；libc++/exception runtime、bcrypt/ws2_32/psapi；正式腳本拒絕 | 先同 compiler 建 DIW bridge 與三個 archives，C executable 驗 verifier init + 合成 valid/invalid proof；2–5 工日 |
| `x86_64-pc-windows-msvc` | 沒有確認 MSVC 專用庫 | 官方 GNU archive 不能直接假設 C++ ABI 相容；需全部源用 clang-cl/MSVC 重建，或將 GNU C++ 封在 DLL 的 C ABI 後，同 DLL 配置釋放 | 先 DLL export／CRT ownership smoke，再合成證明；5–10 工日，較高風險 |
| `x86_64-unknown-linux-gnu` | static + CLI 列出 | 現有腳本路線；上游 Zig 預設 glibc 2.35，專案 native GCC build 不自動保證同門檻；Skylake 風險 | 重建 BB6、readelf imports/version-info、C bridge smoke；1–3 工日 |
| `aarch64-unknown-linux-gnu` | static + CLI 列出 | 上游 arm64-linux preset；專案 allowlist 缺失；原生 ARM64 host 優先，交叉用 sysroot；baseline aarch64，未檢查每個 crypto object 指令 | archive + bridge 同工具鏈，ARM64 runner 合成 verify；2–4 工日 |
| `aarch64-apple-darwin` | static + CLI 列出 | 專案 deployment target 14.0；上游 Zig arm64-macos 用 apple_a14；應以目標 Mac 原生 clang 重建以確認最低 OS/CPU | otool imports + C bridge smoke；1–3 工日 |
| `x86_64-apple-darwin` | static + CLI 列出 | amd64-macos preset 另有 baseline 參數但 arch.cmake 加 Skylake，不能預設支援全部 Intel Mac；專案 target allowlist 缺失 | 原生 Intel host／macOS SDK、同部署版本重建；2–4 工日 |
| `aarch64-pc-windows-msvc` | 未列出 ARM64 Windows | 既有 `_WIN32` guard 有利；上游沒有相應 preset；需 Windows ARM64 SDK、全套 C++/Rust 連結，不能把 x86_64 archive 轉檔 | 先 RNG/allocator/thread object，再完整 archive／C executable；5–12 工日 |
| `aarch64-linux-android` / `arm64-v8a` | static 列出 | 現有 NDK API29、c++_static/c++abi；自行重建可維持 DIW hooks；上游 prebuilt 與 NDK libc++ ABI 需核對 | NDK 全庫 + emulator/device synthetic verify；1–3 工日 |
| `x86_64-linux-android` / `x86_64` | static 列出 | 現有 API29；Skylake 編譯選項與 emulator CPU 特徵不保證相容 | 先 disassembly／最低 CPU emulator 再 valid/invalid proof；1–3 工日 |
| `armv7-linux-androideabi` / `armeabi-v7a` | 未列出 | 32-bit size_t、原子／alignment、C++ uint128 路徑、address space；固定 G1 約128 MiB尚未含 polynomials | verifier-only 先分離原生 link probe；3–8 工日，prover 可能不可行，尚無失敗證據 |
| `i686-linux-android` / `x86` | 未列出 | 同上；不能用 x86_64 編譯選項；需移除不適用 march/asm | object／archive／verifier-only 三階段；3–8 工日 |
| `riscv64gc-unknown-linux-gnu` | 未列出 | generic C++、DISABLE_ASM/ADX、RV64GC sysroot，特定 intrinsics 與原子仍需逐個編譯 | 純量 crypto object 起步；5–10 工日 |
| `x86_64-unknown-linux-musl` | 未列出 | 自建 musl + 相同 C++ runtime；避免混 glibc .a；TLS/thread/entropy；Skylake 需調整 | 獨立靜態 executable 後 shared library；3–6 工日 |
| `aarch64-unknown-linux-musl` | 未列出 | 同上加 aarch64 sysroot；不用 GNU glibc 預建庫 | 相同 verifier-only probe；3–6 工日 |

上游清單另有 iOS artifacts；只記錄存在，不做可行性評分或研究。

## 後續隔離 PoC 指令草案

以下**沒有在本輪執行**，不是成功建置指令的保證。需在獨立 source/build 目錄執行；不要改正式 `build_bb.py`。先確認 CMake ≥3.24、Ninja、C++20、Git、Zig 版本並留存版本；實際依賴版本由固定 CMake 決定。

```sh
git clone --filter=blob:none --no-checkout https://github.com/AztecProtocol/aztec-packages.git bb-source
git -C bb-source sparse-checkout set barretenberg
git -C bb-source checkout --detach 0219f11d8133970df3974fe5ae65e006bf8c193a
# Copy the project-pinned aztec_constants.hpp into this isolated checkout;
# verify its SHA-256 against build_bb.py before configuring.
cd bb-source/barretenberg/cpp
cmake --preset amd64-windows -DAVM=OFF -DBB_LITE=ON -DDISABLE_ASM=ON \
  -DENABLE_PIC=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build-amd64-windows --target barretenberg vm2_stub libdeflate_static --parallel 2
```

下一步應以同一 Zig 及 target 編譯未改動的 DIW bridge、建立 `vm2_stub` archive，然後由最小 C main 靜態連結三個 archives；需要 msgpack/Tracy headers、相同宏定義、C++ exception/runtime 與 Windows system libraries。若選官方 `libbb-external.a`，須另處理 env objects 與 libdeflate unresolved symbols；**不能將官方庫重新命名為 `libbarretenberg.a` 就宣稱接合成功**。

Linux ARM64 可先用 `arm64-linux` preset；macOS Intel 用 `amd64-macos`。這些是來源建置起點；正式腳本尚未接受 target，Rust `build.rs` 也未適配全部 archive/runtime 差異。Windows ARM64／32-bit／RISC-V／musl 尚無現成適用 preset，應建立研究用 toolchain file，依表中先做 object probe；不提供假裝已能使用的 preset。

每次結果應記錄完整 command、exit status、compiler、flags、source/asset hashes、artifact size、compile peak RSS、nm/objdump/otool/dumpbin 輸出。PC 直接 FFI 驗收再加：合成有效 proof／錯誤 proof、容量不足、例外 redaction、並行序列化、verifier/full CRS 初始化順序、allocator 釋放與跨平台雙向驗證。隨機 proof 不要求位元組完全一致。

本輪沒有真正 runtime WASM-only 的 BB 依賴，因此不需要 wasm2native 或 Perry。優先順序為 Windows GNU 靜態鏈接 PoC及 CPU baseline 查證，接著 Linux ARM64、macOS Intel，再評估 MSVC DLL 邊界與 Windows ARM64。

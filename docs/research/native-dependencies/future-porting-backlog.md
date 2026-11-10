# R12：後續原生移植實作清單

**P1 進度（2026-11-10）**：Windows x86_64 GNU 的第一個里程碑已完成：[C executable 連結與 Wine 子集測試](bb-windows-link-poc.md)，涵蓋 verifier 初始化、錯誤長度及 redaction hooks。有效 proof、原生 Windows、最低 CPU、DLL／MSVC 與正式整合仍未完成；下列工時為原始工作包估計，未重新估算剩餘工時。

此清單是下一階段建議，不代表本輪修改正式產品的授權或完成度。優先維持所有演算法、電路、CRS、金鑰與 proof 格式；先在研究目錄取得可重現證據，再進行各自的正式整合階段。工時是單一熟悉專案工程師的研究人日，不含完整 UI/App 驗收。

| 優先／目標 | 要處理的 native 來源／build system | 可審查交付與驗收 | 估計／風險 |
|---|---|---|---|
| P0 基準修正 | `native/rust-toolchain.toml`、`native/openac-age/build.sh` 的 pin/MSRV 差異；版本與 NOTICE 文字 | 選定一致工具鏈後，在乾淨環境以原 lock 重建；逐項核對 BB6/Noir/snow 與靜態依賴授權；不能為通過而降版 | 1–2 日；中 |
| P0 CPU 基準 | BB `cmake/arch.cmake` 與 DIW `build_bb.py` 的實際 flags | 保存 compile_commands；以指定最低 CPU 重建並跑合成 verify；測 Longfellow ARM64 crypto capability。最低 CPU 未通過前不宣告平台相容 | 1–3 日；高 |
| P1 Windows x86_64 BB | 隔離 Zig/GNU toolchain、DIW C++ bridge、archive/env hooks；再設計 `build.rs` 的 target-specific linker/runtime | 先同 compiler 的 C executable；驗 CRS 初始化、公開有效／無效 proof、容量錯誤、輸出 redaction；之後再驗 C DLL 邊界供 MSVC host。不得單純把 libbb-external.a 改名 | GNU 2–5 日；MSVC 邊界另 5–10 日；高 |
| P1 Windows x86_64 Longfellow | 上游 Rust header/exports parity；固定 source gitlink、首份可審查 Cargo.lock、zstd/sha2 C/asm toolchain | C caller struct/size_t/ownership smoke，再正反向 proof；先向上游報 header 與 JNA size_t 問題。舊 JVM wrapper 修正屬後續整合，不在本研究分支改 | 2–5 日；header 另 1–2 日；中高 |
| P1 FFI 契約 | UniFFI matching header/schema、object/callback lifetime；RustBufferByReference 生成流程 | 用公開合成 callback + sanitizer/guard allocator 重現大小問題；版本/checksum 拒絕、錯誤 buffer 回收、重入／取消／卸載；不手改生成 Kotlin | 2–4 日；高，涉及記憶體安全 |
| P2 Linux ARM64 | BB target allowlist/toolchain、Longfellow crypto flags、ring/BLAKE3 C compiler、host protoc/libclang | 原生 ARM64 runner 各 feature 建置→連結→載入→向量；保留最低 glibc 與 ISA；與 Linux x64 雙向驗證 | BB 2–4、Longfellow 1–3、其他 Rust 2–5 日；中高 |
| P2 macOS Intel | BB target branch／C++ flags、相符 SDK/deployment target；使用已存在 Longfellow Intel 預建先驗 | Intel runner C smoke、otool imports、最低 CPU/OS、與 arm64 雙向 proof；無需先因缺產物而 fork | BB 2–4、Longfellow 0.5–1、其他 Rust 2–4 日；中 |
| P3 Windows ARM64 | ARM64 SDK/MSVC、C++ target flags、Longfellow AES/PMULL、vendor token DLL | runtime/OPRF 小向量起步，再 Longfellow/BB；逐庫明確 CRT 與 imports；不能借 x64 模擬通過冒稱原生 | BB 5–12、Longfellow 3–7、其他 Rust 4–8 日；高 |
| P4 Android 32-bit | OpenAC graph u64→usize checked conversion、worker/heap budgets、原子／alignment、BB uint128 路徑 | 先 verifier-only 可拆分性與輸入長度；armv7/x86 真正 runner 量測 peak memory，不改 proof/key；無 verifier-only feature 時先做 dependency split 研究 | 4–8 日起；prover 成本未知 |
| P5 Linux RISC-V | Rust RV64GC sysroot、ring/BLAKE3 target support、BB generic C++／asm guards | OPRF/metadata→crypto objects→archives→合成 proof；分開編譯可行性與可用效能 | 3–10 日起；高 |
| P5 Linux musl | 全部 C/C++ archives 改用同 musl sysroot；static executable 與 cdylib flags | 不重用 glibc SO；驗 entropy/thread/DNS/allocator；確認動態插件與 PKCS#11 使用方式 | 3–6 日起；中高 |

## 各功能下一步

- **OPRF**：目前 Rust 公開合成向量已通過；補版本化 C adapter 或 UniFFI C serialization 的公開向量，驗錯誤 proof 拒絕。最終跨 target 比較 finalize 語義，不要求隨機 proof 位元組相同。
- **OpenAC**：固定 18 個 bundle 檔案 hash 後驗 witness／Prepare／Show；授權與資料散布分開處理；Windows ACL、32-bit offsets、64 MiB worker stacks 與 heap 都需要量測。protoc/libclang 僅在 host。
- **TLSn**：先 compile/link，再 callback close/unblock，再合成 CA/localhost 雙端 Noise/MPC；測取消、超時、截斷與揭露上限。核心可編譯不是網路協定互通。
- **zkPassport/Noir**：維持兩組 arkworks／Poseidon2 版本；metadata 檢查不能代替 BB proof callback。公開 CRS/asset hash 認證與 driver 狀態機不能在直接 C 呼叫時省略。
- **其他 native binaries**：為每個正式發行 target 解析 Gradle artifacts、最終包與 JDK native imports；Skia C++ 不等同 Compose UI 替代，SQLite/PCSC/PKCS#11 需獨立 C consumer 與資料／裝置測試。

## 正式平台支援前的共同完成條件

每個 `(library, feature, target, ABI)` 保存固定版本、工具鏈、命令、flags、exit code、hash、imports/exports、CPU/OS floor 與授權。接著分別通過有效／無效合成向量、所有權與 panic/error 邊界、執行緒／取消、跨架構雙向 proof verification。只有這些依賴證據充分後，才另案修改 App 平台辨識、loader、CI、打包及 UI。

本輪沒有指定 PC Native framework，也沒有規劃 iOS；兩者不能由此清單自動推導。wasm2native/Perry 沒有合格的觸發依賴，維持不引入。

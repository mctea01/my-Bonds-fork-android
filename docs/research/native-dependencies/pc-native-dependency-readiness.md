# R11：PC Native 依賴就緒度

**Longfellow 更新**：[Windows GNU source-build／C proof](longfellow-windows-poc.md) 已在研究 patch 下通過 Wine；原版來源仍受 sha2-asm 阻塞。DLL 使用 GNU/MSVCRT，不能與 BB 的 UCRT 跨庫 free；v7 資產路徑、正式 wrapper、原生 Windows 與 MSVC host 仍待處理。

**第三輪補充**：[Windows GNU 公開 proof](bb-windows-proof-poc.md) 已在 Wine 通過固定 fixture 與三個負向案例；僅限 fixture 自帶 key 的直接 C verifier，尚未測錢包資產／registry 政策、prover 或原生 Windows。

**第二輪補充**：[Windows GNU BB](bb-windows-link-poc.md) 已取得不經 JVM 的 PE 連結與 Wine 下 C caller 子集證據。範圍只含公開 hash、buffer ownership、verifier 初始化與 DIW hooks；原生 Windows／完整 proof／DLL／MSVC host 仍待驗證。

PC 整體 Native 化仍是長期目標，本輪沒有選擇主程式／UI 技術。既有 `tools/desktop-native.sh` 的 GraalVM 實驗只能作歷史背景，不能代替各依賴的直接 FFI 驗證，也不代表 Kotlin/Native、GraalVM、Rust/C++ 或 Compose 可互換。

**已取得兩條不依賴 JVM 的 Linux x86_64 證據**：本輪從固定來源編譯的 DIW runtime 由 C 動態載入並通過合成測試；固定 Multipaz commit 的 Longfellow 預建庫由 C 連結並完成 ABI 子集測試。這是依賴呼叫可行性，不是 PC Native App 可建置的證明。

| 依賴 | 現行產物／未來介面 | 尚需完成 |
|---|---|---|
| DIW runtime / UniFFI | `cdylib`、`rlib`；版本化 UniFFI C ABI；Rust API | C SDK/header 與版本握手、完整序列化、callback、取消、錯誤及生命週期；目前未設定 `staticlib` |
| OPRF / OpenAC / TLSn | 併入 DIW cdylib 或同工具鏈 Rust API | OPRF Rust 測試已通過，C OPRF 呼叫仍未測；OpenAC 大型 graph/heap；TLSn channel callback 與雙端協定另驗 |
| zkPDF / BB | 靜態 archives + 私有 C bridge + Rust wrapper | Windows GNU/MSVC C++ ABI、CRT、CPU flags；bridge 不一定公開到最終 SO；沿用 CRS 鎖與隱私 hooks |
| Longfellow | manifest 宣告 `cdylib`/`staticlib`、六個 C exports | 修正上游 header、產物 provenance/lock、非 Linux x64 C smoke、正向 proof；Windows JNA size_t 問題屬現有 wrapper 缺口 |
| SQLite | JNI 內含 native SQLite；底層有公開 C API | 新 native consumer 的 build options、schema、threading 與檔案互通；不把 JNI artifact 當已驗證 C SDK |
| PC/SC / PKCS#11 | 平台或 vendor C API | 各 OS scalar/struct ABI、服務與驅動、reader/token 實機；Windows ARM64 需相同架構 vendor DLL |
| JNA | 現行 JNI dispatch | 直接原生 caller 不需它；它本身不是無 JVM API |
| Skiko / JDK native / Compose | 現行 JNI/Java 相依；Skia 有 C++ 源 | UI 與 JDK 功能依賴另案技術選型，不能宣稱已有直接替代品 |

[pc-native-ffi-matrix.csv](pc-native-ffi-matrix.csv) 逐一列出六個 PC OS/CPU 目標及 Windows GNU 額外 ABI。欄位分別表示 `native-library-build`、`direct-native-ffi-ready`、`jvm-wrapper-required`、`unknown`；未知不當作否定。底層 Rust/C 可不經 JVM，不代表錢包的 mdoc policy、信任、資產認證、網路 callback 等上層責任自動存在。

所有平台需遵守 allocator 所有權與同一庫 free；Windows 不跨 CRT 釋放；C++ exception/Rust panic 不可穿越未定義的邊界。Longfellow release 為 panic abort，不能承諾所有輸入錯誤都可恢復。UniFFI callbacks 必須保持 vtable/context 存活並處理重入；詳見 [native-abi-contracts.md](native-abi-contracts.md)。

本輪沒有證明任何新平台 App 支援。依賴移植優先序為 Windows x86_64 → Linux ARM64 → Intel macOS → Windows ARM64；Android 32-bit、RISC-V、musl 是後續條件式研究。工時依各庫報告估算，沒有把來源分析、交叉編譯或預建檔存在當成功載入。

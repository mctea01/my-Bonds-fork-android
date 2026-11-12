# R06：原生 ABI 契約

基準：`3428b8ee12ac5e644f478d4c6e43854376202fa4`，2026-11-09。以下為 `source-reviewed`，除各實驗報告明列者外，載入、連結、功能及跨架構互通均為 `not-tested`。路徑行號均對應此 commit。公開來源可用 `https://github.com/mctea01/my-Bonds-fork-android/blob/3428b8ee12ac5e644f478d4c6e43854376202fa4/<path>#L<line>` 查核。

## 現有 JVM 路徑與未來 Native 路徑

現行路徑為 Kotlin → JNA 5.19.1 → UniFFI 0.29.4 產生的 C ABI → Rust，或 Multipaz → Longfellow JNA → `libzkp`。JNA 是呼叫端的選擇，不是這些 Rust 函式庫必須啟動 JVM 的證據。`ZkNative.kt:18–25` 的平台白名單屬 App 載入政策，也不是 Rust target 可編譯性的證明。

未來 Native 主程式可以研究兩條依賴介面：與同版 Rust 一起建置的 Rust API，以及保留精確版號與序列化契約的 C ABI。現有 `diw-zk-ffi/Cargo.toml:8–19` 只輸出 `cdylib`、`rlib`；`rlib` 不能當成跨編譯器穩定的 C 靜態庫。新增 `staticlib` 或獨立 public C adapter 是後續工作。本輪不選主程式/UI 技術。

本輪後續實測：以固定 Rust 1.99.1、原始 Cargo.lock、`--no-default-features` 建出 Linux x86_64 debug cdylib；純 C caller 通過 contract/checksum、SHA-256 `abc` 與 native_info buffer 讀取／釋放，沒有啟動 JVM。證據見 [runtime/result.json](evidence/runtime/result.json)。此產物最高非 weak GLIBC 符號為 2.34，僅在本機 glibc 2.41 執行；不是舊 Linux 的相容性驗收。OPRF 另有 Rust 測試通過，但尚未測其 C 呼叫／callback。

## diw_zk / UniFFI

證據：`native/Cargo.toml:13–21`、`native/diw-zk-ffi/src/lib.rs:28–34,62–115`；以下 binding 行號位於 `core/src/jvmCommonMain/kotlin/diw/wallet/core/zk/native/generated/diw/wallet/core/zk/native/bindings/diw_zk.kt`。

| 契約 | 研究結果 |
|---|---|
| 入口 | `ffi_diw_zk_uniffi_contract_version`、`uniffi_diw_zk_checksum_*`、`uniffi_diw_zk_fn_func_*`、object clone/free、callback init、rustbuffer helpers。宣告在 binding:892–1210；實際 dynamic exports 必須以產物確認，不能只從原始碼推定全部保留。 |
| 版本配對 | contract 為 29（1214–1221）；每函式 checksum 亦須檢查，例如 `self_test=49179`、`native_info=9623`（1234、1267）。不是永不變動的 public C SDK。 |
| 結構與序列化 | `RustBuffer={u64 capacity,u64 len,pointer data}`（42–50），`RustCallStatus={i8 code,RustBuffer error_buf}`（222–227）。自然 ABI padding 依 target，不能 packed；buffer 內容使用 big endian（82–86），不等於結構欄位的 host endianness。`ForeignBytes` 長度為 i32（129–134），不是 `size_t`。 |
| 所有權 | 傳給 Rust 的 owned buffer 應由該 library 的 alloc/from_bytes 建立，依該函式的 consuming 契約轉移；回傳 buffer 解碼後用同一 library 的 `ffi_diw_zk_rustbuffer_free` 釋放（59–79）。不可 C `free`、跨 DLL/CRT 或跨不同版本 free。物件 handle 必須配對 clone/free。 |
| 錯誤與 panic | status 0/1/2 分別成功、typed error、unexpected error；error buffer 也必須消費/釋放（218–220、267–302）。release 為 `panic="unwind"`；worker join 把 panic 轉固定 Internal code，worker panic hook 不輸出私密輸入（lib.rs:15–25、113）。不能據此保證所有 allocator failure、FFI pointer UB 或 foreign callback exception 都會安全回傳。 |
| 執行緒 | `run_worker` 為同步呼叫，內部啟動並 join 執行緒，取消為合作式，不能提早返回並丟掉 worker。stack 範圍 1–256 MiB（lib.rs:88–115）。呼叫者不能在 callback 存活期間卸載 DLL。 |
| callback | TLS channel 必須 `Send+Sync`、允許同時 send/receive，close 必須解除兩端阻塞（`src/zktls.rs:7–22`）。進度、揭露選擇、回執也是外部 callback。未來 C adapter 須管理 vtable/handle lifetime、錯誤轉換及重入；不能在持有同一非重入鎖時等待 callback 回來。 |
| 非同步 ABI | binding 中有 future poll/complete/free helpers；存在 helpers 不代表目前所有 exported API 都是 async。現行 zktls exported fn 以 worker 包住同步回傳（zktls.rs:76–97）。 |
| 系統 imports | Rust std 的 thread、entropy、allocator、動態 loader/OS runtime 及 feature 引入的原生依賴；精確 imports/glibc 最低版只能從每個產物觀測。本輪不能用主機 glibc 2.41 當產品最低需求。 |

**更正（2026-11-11）**：下述類別在生成的 Kotlin 裡只有定義、沒有任何使用處（UniFFI 0.29.4 的樣板固定輸出），不構成風險，也不需要重現；見 [follow-up-implementation.md](follow-up-implementation.md)。原文保留如下。

**具體待驗證缺口**：binding 的 `RustBufferByReference : ByReference(16)`（97）在 offset 16 寫入 pointer（106），讀回時還以 `getLong(16)`（117）存入 pointer 欄位。在 64-bit 下前兩個 u64 已用滿 16 bytes，另需 pointer；32-bit 下也不能假設 pointer 是 64-bit。這是來源可見的大小／型別不一致，須以 callback 路徑與記憶體檢查重現，再向生成器或生成流程修正；本輪不手改 generated Kotlin，也不宣稱已觀察到當機。直接 C PoC 應依原生型別 `sizeof/offsetof` 建立契約，不能照抄這個配置。

## zkPDF / Barretenberg bridge

證據：`native/zkpdf-prover/cpp/bridge.cpp:43–110`、`src/backend.rs:15–109`、`build.rs:101–118`。

- C 入口為 `zkpdf_bb_init`、`zkpdf_bb_init_verifier`、`zkpdf_bb_prove`、`zkpdf_bb_verify`、`zkpdf_bb_vk`。最後一項用於建置驗證金鑰，不能藉移植變更既有金鑰。`extern "C"` 只解決名稱與呼叫 ABI，不保證這些內部 bridge symbols 在最終 `diw_zk` shared library 中公開。
- 輸入為借用的 `const uint8_t* + size_t`，輸出為呼叫端配置的 buffer/capacity 與 `size_t* written`，同步返回前保持存活；沒有跨 CRT 回傳 malloc 物件。`size_t` 在 32-bit 為 32-bit，Windows x64 也是 64-bit，不能用 Windows `unsigned long` 代替。
- 回傳 0 表示成功，1 包含失敗、驗證不通過或 exception；`noexcept` + `catch (...)` 阻止 C++ exception 穿越這些邊界。非法指標是 UB，不是 exception 可兜底的輸入驗證。
- 全域 CRS 與 worker 設定由 Rust `BACKEND` mutex 序列化；C bridge 本身沒有 mutex。直接主程式必須實作相同序列化與 CRS 認證，不得只看到 C 函式便併發呼叫。verifier-only CRS 先初始化後不能升成 full CRS（backend.rs:74–75）。
- 原生靜態鏈為 bridge + barretenberg + vm2_stub + deflate；Android 使用 c++_static/c++abi，macOS libc++，其他目前硬編碼 stdc++/pthread。這不是 MSVC 可直接接受的 link 設定。C++ object 和標準函式庫 ABI 必須配套，不能把 GNU `.a` 當 MSVC `.lib`，或混用 libstdc++ 與 libc++。
- 最小驗證順序為 archive symbol → C host 連結 → verifier init → 固定公開證明 verify（含負向）→ proving/雙向互通。只做到 init 不算 proof 功能通過。各 target 問題見 [R01](barretenberg-native.md)。

## 其他 Rust API 與 vendored C 入口

OpenAC、TLSNotary、Noir/ACVM、arkworks/OPRF 的來源 API 可被同版 Rust 主程式使用；C 主程式仍需 UniFFI schema 或經審核的新 C adapter。Rust `Vec`、`String`、trait object、`Result` 不能直接當 public C struct。feature 關閉時函式名稱仍可能存在而回 Unsupported，`nm` 找到 symbol 不等於對應引擎可用。

zkPassport **已有部分來源層 C exports**，不可一概標成「沒有 C ABI」：`native/vendor/zkpassport/zkpassport-ffi/src/lib.rs:260–483,737–740` 包含 URL/input/session 函式與 `zkpassport_free_string`、`zkpassport_session_free`；bridge 的 `src/ffi.rs:31–89` 包含 `zkbridge_pubkey/connect_url/encrypt/decrypt/free`。字串是 NUL 結尾 UTF-8，回傳字串由對應 free 釋放，session 是不透明指標；session `next/provide` 會取得 mutable reference，呼叫端須避免併發與 use-after-free。部分錯誤採 JSON，部分 null；有 `CString::new(...).unwrap()`，未見全面 `catch_unwind`，不可將 panic 當穩定錯誤碼。這些 crate 在本專案以 Rust dependency 使用，獨立動態產物、symbol retention 和 C consumer ABI 均未驗證。

Longfellow 的實際 exports、buffer 生命週期、最低 libc 與實驗結果集中於 [R02](longfellow-native-matrix.md)；原生 API 的可行性與 Multipaz Kotlin 層的 mdoc policy、parameter checking、credential conversion 是不同責任。脫離 JVM 仍須重建上層協議語義。

## JVM 包裝與平台系統介面

| 現有元件 | 非 JVM 介面研究 | 契約／檢查界線 |
|---|---|---|
| SQLite JDBC | SQLite public C API 可作候選；JDBC JNI symbols 不是 SQLite SDK 的替代 | sqlite3_open/close、prepared statement finalize、sqlite3_malloc/free、thread mode；需查 bundled SQLite build options 與 exports。本輪未測 native SQLite consumer。 |
| JNA dispatch | 現有 JVM 呼叫橋接，不是未來 Native host 的必要依賴 | `jnidispatch` 需要 JNI；改用 native linking 即不需它，但 native 功能仍需各自驗證。 |
| Skiko / Compose Desktop | Skia 有原生來源，但 Skiko JNI 和 Compose UI 不能直接成為無 JVM 的 UI | JNI entry 需要 JVM/JNIEnv；Skia C++ ABI、圖形／字型／窗口執行緒與系統 imports 另案研究，無直接 UI 替代的宣稱。 |
| PC/SC | 平台 C API，Linux pcsclite、Windows winscard、macOS PCSC framework | handle/context release、OS-specific scalar layout、card reader service；`PcscReaders.kt:79–109` 是現有 JDK 路徑，不能證明所有 target 系統庫已安裝。 |
| PKCS#11 | vendor module 的 C_GetFunctionList / function table | `CK_ULONG` 與 packing/calling convention 依平台/vendor header，C_Initialize/Finalize、session lock、PIN lifetime；Windows ARM64 不能載入 x64 vendor DLL。`DesktopKeys.kt:26–86` 現為 SunPKCS11 包裝。 |

## 日後可重現檢查

Linux 用 `readelf -h -d -Ws --version-info LIB`、`nm -D --defined-only LIB` 記錄架構、NEEDED、exports、GLIBC/GLIBCXX；macOS 用 `file`、`otool -L -l`、`nm -gU` 查架構／deployment target／install name；Windows 用 `dumpbin /headers /imports /exports` 或 LLVM 對應工具查 machine、CRT、exports。每次同時保存產物 SHA-256、source revision、target、feature、compiler/linker version、完整指令與 exit status。用 sanitizer/guard allocator 驗證 ABI 的錯誤路徑、double-free、callback lifetime，測試只用公開合成向量；最終再做跨架構雙向 proof verification。

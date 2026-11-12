# 後續查證與實作（2026-11-11）

前七輪是純研究，沒有改產品。這一輪把其中可以落地的部分做進正式建置，並補上研究當時沒有量測的項目。這裡只記錄結果與限制；建置方式寫在 [`native/README.md`](../../../native/README.md) 與 [`native/zkpdf-prover/README.md`](../../../native/zkpdf-prover/README.md)。

所有執行都在 x86_64 Linux 容器內：其他架構以 QEMU user 模擬，Windows 以 Wine 9.0 執行。**沒有任何一項在實體 ARM、實體 32 位元裝置或真正的 Windows 上跑過**，這些要由 CI 與實機補上。

## 結果總覽

| 項目 | 結果 | 尚未驗證 |
|---|---|---|
| x86_64 CPU 基準 | 量測證實原本的 Barretenberg 需要 AVX2 與 BMI2，舊 CPU 一載入就當掉；改為 x86-64-v2 後通過 | 改基準後的效能差異 |
| Android 32 位元 | Barretenberg 無法建置；只含 runtime 的函式庫可建置，測試在 ARMv7 與 x86 模擬下通過，已加入建置 | 32 位元實機 |
| Windows x86_64 zkPDF | 由 Linux 交叉建置成功；公開證明驗證、Barretenberg 5、完整 zkPDF 證明與驗證都在 Wine 下通過 | 真正的 Windows、JVM 經 JNA 載入 |
| Linux ARM64 | Barretenberg 由專案腳本交叉建置；公開證明驗證在 QEMU 下通過 | 實體 ARM64、桌面版封裝與 CI |
| 文件與工具鏈漂移 | NOTICE、README 與 OpenAC 建置檢查已與釘選版本一致 | |

## x86_64 CPU 基準

研究指出上游 `cmake/arch.cmake` 對 x86_64 無條件加上 `-march=skylake`，但沒有量測。對修正前的 Linux x86_64 `libbarretenberg.a`（v6.0.0）量測的結果：

- 185 個編譯命令全部帶 `-march=skylake`。
- 反組譯有 538,039 道使用 ymm 暫存器的指令與 436,494 道 `mulx`。
- 連結出的測試程式在 `qemu-x86_64 -cpu Nehalem` 下連 `--list` 都以 SIGILL 結束，也就是靜態初始化階段就執行到新指令。對 App 來說，沒有 AVX2／BMI2 的 CPU 一載入原生函式庫整個行程就會當掉，不是只有 zkPDF 不能用。`-cpu Haswell` 正常。
- 以 `-march=x86-64-v2` 重建後，ymm 與 `mulx` 都是 0，Nehalem 下通過公開 UltraHonk 證明的驗證。

正式修正在 zkPassport 整合的分支（`native/zkpdf-prover/tools/portable_x86_64.cmake` 加 `-march=x86-64-v2`，Barretenberg 5 與 6、Linux 與 Android x86_64 都套用）。Windows 的建置沿用同一個機制，`build.ninja` 內沒有 `-march=skylake`。

## Android 32 位元（armeabi-v7a、x86）

現況：App 裝得上 32 位元裝置，因為 base 帶有相依套件（JNA、Tesseract、CameraX）的 32 位元函式庫，但沒有 `libdiw_zk.so`。結果是所有零知識功能回報不支援，電子護照的 JPEG 2000 相片也解不出來（`Jpeg2000.decode` 回傳 null）。

| 元件 | 32 位元結果 |
|---|---|
| runtime（含 JPEG 2000 解碼）與 OPRF | `cargo ndk` 對兩個 ABI 都建置成功。`cargo test -p diw-zk-ffi --features oprf` 在 `armv7-unknown-linux-gnueabihf`（qemu-arm）與 `i686-unknown-linux-gnu`（qemu-i386）各 11 項通過 |
| TLSNotary、OpenAC | 編譯與連結成功（去除符號後約 12 至 20 MB）。沒有執行：證明所需記憶體超過 32 位元行程的定址空間，也沒有對應的 `ZkCapabilities` 分級 |
| Barretenberg（zkPDF、zkPassport） | 無法建置，見下 |
| Longfellow | Multipaz 沒有 32 位元預建庫 |

Barretenberg 的阻礙有兩層，都在上游原始碼：

1. 32 位元的 clang 沒有 `__int128`。上游為 `__i386__` 留的 `uint128_t` 替代類別已經失修，`ecc/fields/bernstein_yang_inverse.hpp` 直接使用 `__int128`／`__uint128_t`。
2. 以強制引入的標頭把 `__int128` 換成 clang 的 `_BitInt(128)` 之後可以繼續編譯，但 `eccvm_verifier.cpp` 在 `small_subgroup_ipa.hpp` 出現 `FF(size_t)` 的多載歧義：程式假設 `size_t` 是 64 位元的獨立型別。建置在 209 步中的第 126 步停止，後面是否還有同類問題沒有看完。

要支援就得自己維護一份改過算術與型別的 Barretenberg，而上游完全不測這條路。結論是不做。

已實作：`native/build.sh android` 建 `arm64-v8a` 時順便建 `armeabi-v7a`、建 `x86_64` 時順便建 `x86`，只含 runtime（約 1.0 與 1.4 MB）。32 位元裝置因此能解碼 JPEG 2000；`ZkCapabilities` 對 32 位元 ABI 原本就回報不支援，證明功能的畫面不變。CI 不需要修改。

## Windows x86_64：zkPDF 與 Barretenberg 5

研究以官方預建的 Windows 靜態庫（zig、libc++）證明可行，但那個庫同樣以 Skylake 為基準，不能拿來發佈。這一輪從固定的原始碼建置，來源不修改。

| 嘗試 | 結果 |
|---|---|
| Ubuntu 的 MinGW GCC 13 | 65 個編譯單元出現編譯器內部錯誤（`check_noexcept_r`，`mega_circuit_builder.hpp:251`），放棄 |
| clang 18 加 lld，使用 Ubuntu 的 MinGW-w64 標頭、執行階段與 libstdc++ | 成功，需要下列三項調整 |

三項調整都不改上游檔案：

- `common/container.hpp` 用到 `int64_t` 卻沒有引入 `<cstdint>`（libc++ 會間接引入，libstdc++ 不會）。
- libstdc++ 在 MinGW 上以函式初始化 `std::mutex`（libstdc++/59807），建構式不是 constexpr，上游 `constinit` 的產生器表無法編譯。winpthreads 的靜態初始值是常數，以它定義 `__GTHREAD_MUTEX_INIT` 即可。代價是這種 mutex 沒有解構呼叫，用過再銷毀會留下 winpthreads 延遲配置的小塊狀態；Barretenberg 的 mutex 不是單例就是每次證明少數幾個。前兩項寫在 `native/zkpdf-prover/tools/mingw_libstdcxx.h`，編譯每個 C++ 檔案前強制引入。
- libstdc++ 在 MinGW 上的執行緒區域變數用模擬 TLS，clang 預設用原生 TLS，連結時找不到 `std::__once_callable`。編譯時加 `-femulated-tls`。

另一個只在執行時才看得到的問題：**Barretenberg 的工作池是 `thread_local`，解構時會 join 工作執行緒。** Windows 在呼叫端執行緒結束時、持有載入器鎖的狀態下執行這個解構，而工作執行緒要結束也需要載入器鎖，於是死結。Wine 下的現象是驗證本身完成、測試執行緒卻永遠結束不了，連除錯器都附加不上。這與編譯器或標準函式庫無關，上游的 Windows 建置只在主執行緒使用所以沒遇到。本專案每次呼叫都在新的工作執行緒上執行，JVM 的執行緒也會回收，所以一定會遇到。修正是 `native/zkpdf-prover/src/bbthread.rs`：在 Windows 上所有進入 Barretenberg 的呼叫都轉到一條與行程同壽命的執行緒，其他系統直接呼叫。Barretenberg 5 的函式庫共用同一個模組。

以當時的 `native/build.sh x86_64-pc-windows-gnu`（`DIW_ZK_FEATURES=openac,tlsn,zkpdf,bb5`，Ubuntu 的 MinGW-w64 與 libstdc++）建出的結果；工具鏈之後已更換，見本節最後：

| 檢查 | 結果 |
|---|---|
| 產物 | `diw_zk.dll` 60 MB、`diw_bb5.dll` 20 MB（已去除符號）；只引入 Windows 系統 DLL（kernel32、ntdll、msvcrt、advapi32、bcrypt、bcryptprimitives、ws2_32、userenv） |
| C 載入測試（`tools/native-research/runtime_probe.c`，以 `LoadLibrary`） | UniFFI contract 29、checksum 相符、自檢通過；`native_info` 列出 runtime、openac、tlsn、zkpdf、oprf；`FreeLibrary` 正常 |
| 公開 UltraHonk 證明（zkPassport 的 `outer_count_4_disclose.json`，bb 6.0.0） | 接受原證明、拒絕改過的公開輸入，行程正常結束 |
| `cargo test -p zkpassport-bb5 --features bb` | 3 項通過，包含偽造證明被 Barretenberg 5 拒絕 |
| 合成文件的 zkPDF 證明（`synthetic_bench student`，`zkpdf-v1-desktop`，2 個工作執行緒） | 6 段全部證明並驗證通過，證明合計 151.8 秒。各段：sha_content 17.7、sha_opaque 13.7、inflate0 25.0、lex 41.2、claim 11.8、pred 16.2 秒 |

時間是 Wine 加上 4 核心容器的數字，只能說明功能正確，不代表 Windows 上的效能。

限制：

- 含 zkPDF 的 Windows 函式庫只能在 Linux 上交叉建置，而且是 GNU ABI。Windows 主機照舊可以建不含 zkPDF 的 MSVC 版。
- 沒有經過 JVM 與 JNA 載入，也沒有在真正的 Windows 上執行。CI workflow 的修改稿讓 Windows runner 載入交叉建置的 DLL 並跑 `ZkNativeTest` 與 `ZkPdfCircuitTest`，要由這一步確認。
- Windows 產生的證明沒有拿到其他平台驗證（反方向有：公開 fixture 不是 Windows 產生的）。
- Longfellow 的 Windows 版不在這一輪：研究列出的 `sha2-asm`、電路嵌入與 Multipaz JNA 的 `NativeLong` 問題都要改上游或 Multipaz，沒有動。

### 2026-11-12：改用 llvm-mingw，不再連結 GCC 執行階段

上面的結果是用 Ubuntu 的 MinGW-w64 與 libstdc++ 建出來的。那樣的 DLL 靜態連結了 libstdc++ 與 libgcc（GPL-3.0-or-later 加 GCC Runtime Library Exception）。例外條款允許這樣散布，但專案規則是隨 App 散布的原生程式碼不含 GPL 家族元件，所以改掉。

現在的 Windows 目標是 `x86_64-pc-windows-gnullvm`，工具鏈是 llvm-mingw（`native/zkpdf-prover/tools/llvm_mingw.py` 下載以 SHA-256 固定的版本）：clang、lld、libc++、libunwind、compiler-rt 與 mingw-w64 UCRT，授權都是寬鬆授權，與上游用 zig 建 Windows 的組合相同。影響：

- 上面針對 libstdc++ 的三項調整（`mingw_libstdcxx.h`、`-femulated-tls`）不再需要，已移除。
- 工具鏈的 clang 比上游使用的新，Windows 目標不帶 `-Werror`。
- DLL 改為引入 UCRT（`api-ms-win-crt-*.dll`，Windows 10 起內建），不再引入 `msvcrt.dll`。
- `native/build.sh` 建完後檢查兩件事：只引入 Windows 系統 DLL；檔案內沒有 GCC 編譯的目的檔。這類目的檔帶有 `GCC: (` 字串，原本的兩個 DLL 各有約兩百個。
- 執行緒結束死結與 `bbthread.rs` 和標準函式庫無關，照舊。

曾評估改走 MSVC ABI（xwin 加 clang-cl），沒有採用：Barretenberg 無條件引入 `<cxxabi.h>` 與 `unistd.h`；64 個檔案使用 `unsigned __int128`，MSVC 的函式庫沒有 128 位元除法的輔助函式，微軟的 STL 也不把它當整數型別，`serialize.hpp` 的 `std::integral auto` 多載會編譯失敗或選到別的版本；連結進 DLL 的會是微軟專有授權的 CRT。

**驗證狀況：** 這個容器無法取得 llvm-mingw，新工具鏈沒有在容器內建置，也沒有以 Wine 執行。它由 CI 驗證：`native-windows` 工作建置並執行上述兩項檢查，Windows 桌面版工作在真正的 Windows 上載入 DLL 並跑 `ZkNativeTest` 與 `ZkPdfCircuitTest`。

## Linux ARM64

`build_bb.py` 新增 `aarch64-unknown-linux-gnu`：ARM64 主機原生建置，x86_64 主機以發行版的 `g++-aarch64-linux-gnu` 交叉建置。GCC 13 的 aarch64 版會把 `hash_to_curve` 裡的 `vector::push_back` 誤報為 `-Wstringop-overflow`（x86_64 版不會），上游以 `-Werror` 建置，所以對這個目標把該警告降級。

| 檢查 | 結果 |
|---|---|
| Barretenberg 6.0.0 從原始碼交叉建置 | 成功（先前幾輪只連結官方預建庫） |
| 公開 UltraHonk 證明（qemu-aarch64） | 接受原證明、拒絕改過的公開輸入 |
| 完整函式庫（`native/build.sh aarch64-unknown-linux-gnu`，`openac,tlsn,zkpdf`） | 建置成功，54.8 MB；C 載入測試在 qemu-aarch64 下通過（contract、checksum、自檢，`native_info` 列出 runtime、openac、tlsn、zkpdf、oprf）。在 Ubuntu 24.04 上交叉建置時需要 glibc 2.38 與 GCC 13 的 libstdc++（動態連結，與 Linux x86_64 版相同做法） |
| App 端 | `ZkNative`、`DesktopPlatform`、`ZkCapabilities` 與 Gradle 認得 `linux-aarch64` |

沒有做的部分：Barretenberg 5 的 ARM64 建置（同一支腳本，未執行）、OpenAC 與 TLSNotary 在 ARM64 上的實際證明、桌面版的 ARM64 封裝與 CI 工作、Longfellow（Multipaz 沒有 Linux ARM64 預建庫，研究已證明可從原始碼建）、實體機器。

## 對先前研究的更正

- **UniFFI `RustBufferByReference` 不是記憶體安全風險。** 研究指出這個類別的配置大小與指標讀取不一致，列為高風險待驗證項目。生成的 Kotlin 裡這個類別只有定義，沒有任何地方使用（UniFFI 0.29.4 的樣板固定輸出它），因此不需要處理。[native-abi-contracts.md](native-abi-contracts.md) 與 [future-porting-backlog.md](future-porting-backlog.md) 的相關段落以此為準。
- **「Windows 被上游 POSIX 相依擋住」已不成立。** v6.0.0 與 v5.0.0 的原始碼都能以 MinGW-w64 目標編譯，擋住的是編譯器與標準函式庫的組合，以及上面的執行緒結束死結。
- 證據目錄刪除了 83 個空的記錄檔與兩份被線上版取代的離線 Gradle 報告。

## 後續清單的變動

[future-porting-backlog.md](future-porting-backlog.md) 的項目狀態：P0 兩項完成；P1 Windows x86_64 Barretenberg 完成到「Wine 下通過」，剩 CI 與實機；P1 FFI 契約的 `RustBufferByReference` 部分取消；P2 Linux ARM64 的 Barretenberg 完成建置與驗證，剩封裝；P4 Android 32 位元結論為只提供 runtime。其餘（Windows Longfellow、macOS Intel、Windows ARM64、RISC-V、musl）沒有變動。

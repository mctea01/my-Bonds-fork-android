# Longfellow Windows GNU：來源建置、DLL 與 proof PoC

日期：2026-11-10。延續 BB 的 Windows 研究，這輪將 Multipaz 0.102.0 的固定 Longfellow 來源建成 Windows GNU `zkp.dll`，以直接 C caller 在 Wine 驗證 ABI、電路資料配置／釋放，以及公開 v7／1 attribute proof。**成功路徑需要隔離研究 patch；原版來源的 Windows 建置會失敗。** 正式 App、Kotlin、Gradle、CI、native build scripts 與密碼學參數沒有修改。

## 原版阻塞與最小 patch

固定 Multipaz commit 為 `a015c9d93874fe6e09df1354006353ce6f94751d`，Longfellow gitlink 為 `d5e6be77336933d50bf7f25a954f8ec273eb51ce`。原版依賴圖在 Windows 啟用 `sha2/asm`；`sha2-asm 0.6.4` 明確 `compile_error!("crate does not support Windows targets")`。這不是只缺 linker；它同樣會阻塞尚未實測的 Windows MSVC 路線。

[研究 patch](../../../tools/native-research/longfellow-windows-sha2.patch) 只修改 repo 外 Longfellow 的六份 Cargo manifests：保留同版 `sha2`，僅在 `cfg(not(windows))` 啟用 `asm`。需要涵蓋六條依賴邊，因 Cargo feature 會合併，不能只改頂層 runtime。Windows feature graph 已確認不含 sha2-asm；Linux graph 仍包含它。沒有刪掉 compile guard、改動演算法、降版或修改電路／proof 格式。

Zig 交叉工具鏈另遇到 Rust triple 格式、dlltool 搜尋及 GNU linker `.def` 參數相容性問題；最終成功建置使用 **Rust 1.99.1、MinGW GCC 14.2.0、binutils 2.44、mingw-w64 12.0.0**。工具套件解開至使用者目錄，未安裝系統套件。版本／下載 SHA 見 [mingw-packages.json](evidence/longfellow-windows/mingw-packages.json)，探索失敗見 [attempts.json](evidence/longfellow-windows/attempts.json)。這不代表 Zig 永遠無法使用，只表示本輪成功路徑採 MinGW。

上游未附 lockfile；本輪第一次解析保存為 [longfellow-windows.Cargo.lock](../../../tools/native-research/longfellow-windows.Cargo.lock)，之後全部用 `--locked`。這份鎖檔不代表 Multipaz 預建 SO 當時的解析結果。重要 registry 版本包含 sha2 0.10.9、zstd 0.13.4、zstd-sys 2.1.2+zstd.1.5.7、getrandom 0.3.4、libc 0.2.191。Rust 1.99.1 是本研究選用工具鏈，不是上游宣告的最低版本。

## 已執行範圍

| 項目 | 證據與結果 |
|---|---|
| source build | release `zkp.dll`、`libzkp.dll.a`、`libzkp.a` 產出；staticlib 尚無獨立 consumer 測試 |
| DLL C ABI | 六個 exports 全部連結並呼叫，不經 JVM／JNI／JNA；成功 proof generation 未測 |
| LLP64 | `long=4`、`size_t=8`；Spec 112 bytes、Attribute 184 bytes；高 32 bits 的 count/version 正確拒絕，不被截成合法小值 |
| v7／1 spec | system、hash、version、attribute count、block encoding 值與既有 Linux smoke 相符 |
| circuit materialize | 成功輸出配置，逐 byte 比對固定 `.lfa2`，用 DLL 的 `free_circuit_bytes` 釋放 |
| 公開 proof | 接受上游既有 v7／1 proof，拒絕修改 attribute／transcript／proof，還原後再接受 |

完整命令、來源／工具／產物雜湊與結果見 [result.json](evidence/longfellow-windows/result.json)，實際輸出見 [wine-probe.log](evidence/longfellow-windows/wine-probe.log)。開頭沿用 ABI 子測試的 `proof correctness not tested` 訊息，只描述該子測試；後續 proof markers 才是本輪的正反向驗證結果。

fixture 來自同一 Longfellow commit 的 `BIRTHDATE_1971_09_01_MDOC_3` 公開測試向量、`prior_zk.rs` 的第一個 requested attribute，及 `artifacts/proofs/8d079…2121.bin`。runner 固定完整 source／circuit／proof SHA，僅從向量取公開 verifier metadata，不把 mdoc body 或 disclosure 原文寫入記錄。測試使用上游測試公鑰，不驗發證機構信任或錢包政策，也未重新產生 proof。

DLL imports 包含 KERNEL32、msvcrt、ntdll、bcryptprimitives／ProcessPrng 及同步 API set；見 [imports／exports](evidence/longfellow-windows/zkp.dll-imports-exports.log)。這條 GNU/MSVCRT 路線與 BB 的 Zig/UCRT 路線不同；各庫的 allocation 必須各自配對 free，不能因都是 Windows DLL 就跨 CRT 釋放。MSVC host 邊界沒有測試。

## 新確認的部署缺口

`generate_circuit(v7,1)` 會經 provider 讀取 `env!("CARGO_MANIFEST_DIR")/circuits/<hash>.lfa2`；這是**編譯時來源目錄路徑**。本次 Wine 的 Z: mapping 讓該目錄可讀，因此配置成功不代表搬移 DLL 到乾淨 Windows 仍會成功。固定來源的檔案載入在資料缺失時會 panic，而 release 設定為 `panic=abort`。後續需設計可部署的資產供應方式並測隔離安裝，不能把此結果當成可直接發佈的 DLL。

現有 JVM wrapper 的 `NativeLong`／`usize` LLP64 錯配、Windows loader 缺口與舊 C header 不一致仍存在；本輪直接 C caller 避開它們，未修改產品整合。詳細 ABI 契約見 [原研究](longfellow-native-matrix.md)。

## 重現

在 repo 外 checkout 上述 Multipaz commit，初始化固定 submodule。先複製研究鎖檔並套用 patch；`/research-repo` 代表本研究分支 checkout：

```sh
git -C /external/multipaz submodule update --init multipaz-longfellow/rust/longfellow-zk
git -C /external/multipaz/multipaz-longfellow/rust/longfellow-zk apply --unidiff-zero \
  /research-repo/tools/native-research/longfellow-windows-sha2.patch
cp /research-repo/tools/native-research/longfellow-windows.Cargo.lock \
  /external/multipaz/multipaz-longfellow/rust/Cargo.lock
python3 tools/native-research/probe_longfellow_windows.py \
  --multipaz /external/multipaz \
  --cargo /external/cargo/bin/cargo --cargo-home /external/cargo \
  --rustup-home /external/rustup \
  --gcc /external/mingw/usr/bin/x86_64-w64-mingw32-gcc-posix \
  --out /external/new-empty-longfellow-probe --wine /path/to/wine64
```

預先安裝 Rust 1.99.1 的 `x86_64-pc-windows-gnu` target；GCC 同一 bin 目錄需有 MinGW ar／dlltool，並備齊 headers、runtime libraries 與 host shared libraries。隔離 Wine 可再指定 `--wine-prefix`、`--wineserver`、`--wine-dll-path`，設定沿用 [BB 工具記錄](evidence/bb-windows-link/toolchain.json)。runner 驗證兩個 git HEAD、完整 patch、鎖檔與 fixture，輸出必須在 repo 外空目錄；省略 Wine 只記為 `linked`。

仍未完成：原生 Windows、最低 OS／CPU、MSVC、prover、跨架構雙向 proof、效能／記憶體壓力、可搬移資產與完整 App 驗收。[交付檢查](evidence/longfellow-windows/validation.json) 不增加這些覆蓋範圍。

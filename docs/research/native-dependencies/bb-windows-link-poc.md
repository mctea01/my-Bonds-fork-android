# Barretenberg Windows GNU：連結與 Wine PoC

**後續進度**：[第三輪公開 proof PoC](bb-windows-proof-poc.md) 已補上 Wine 下單一 fixture 的正反向驗證。本文的 `positive_proof=not-tested` 是本次連結實驗當時的範圍，原始證據不改寫。

第二輪整理日期：2026-11-10。沿用第一輪固定版本，以 Zig 0.15.1 將官方 Windows BB archive 與**未修改的 DIW bridge.cpp** 連成兩個 x86_64 Windows PE executable，並在 Linux 上的 Wine 10.0 通過下列子集。這已超過來源檢查，但不等同原生 Windows 驗收、完整 zkPDF 功能或 MSVC 支援。

完整命令、exit code、來源與產物雜湊見 [result.json](evidence/bb-windows-link/result.json)。34 個命令皆 exit 0；產物保留在 repo 外。此輪沒有修改正式 App、loader、Rust/Cargo、Gradle、CI、native build scripts、電路、CRS、金鑰或證明格式。

[交付檢查](evidence/bb-windows-link/validation.json) 通過保留產物／工具雜湊、獨立 Blake2s 向量、矩陣與文件一致性，以及輸出目錄／錯誤 archive 的拒絕測試。環境重啟後原 `/tmp` archive 已不在，該檔僅保留成功執行時的驗證記錄；交付檢查沒有宣稱重新核對它。

## 固定輸入

| 輸入 | 版本／驗證 |
|---|---|
| BB source headers | `0219f11d8133970df3974fe5ae65e006bf8c193a`，v6.0.0 |
| Windows `libbb-external.a` | SHA-256 `f401bb3a644d5be1163d1df95a2968f33fa053d4e2c7b065f16f436cbb644699` |
| Zig | 0.15.1，與固定 BB build image 相同；Linux tar SHA-256 `c61c5da6edeea14ca51ecd5e4520c6f4189ef5250383db33d01848293bfafe05` |
| msgpack-c | `c0334576ed657fb3b3c49e8e61402989fb84146d` |
| Tracy | `5d542dc09f3d9378d005092a4ad446bd405f819a` |
| libdeflate | v1.24，解析為 `96836d7d9d10e3e0d53e6edb54eb908514e336c4`；本輪交叉編譯 11 個 C units |
| DIW bridge／constants | 與專案基準相同；runner 驗 SHA-256，再將 constants 複製到外部 include overlay |

四個來源 checkout 必須在指定 HEAD 且無未提交／未追蹤檔；runner 另驗 archive、bridge、constants 雜湊。下載 archive 的 digest 一致不代表完成 BB 全庫 source-build、簽署 provenance 或可重現建置。

## 實際測試

| 呼叫／檢查 | 結果與邊界 |
|---|---|
| 純 C `bbapi`，MessagePack Blake2s(`abc`) | 回傳完整 bytes 符合公開 hash `508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982` |
| caller 提供 scratch buffer | pointer 保持不變、長度與內容相符 |
| library 配置 output buffer | 內容相符，透過同庫 `bbfree` 釋放；未做壓力測試 |
| 無效 MessagePack `0xc1` | 回傳 `ErrorResponse`；不是密碼學 proof 拒絕測試 |
| DIW verifier 初始化 | `zkpdf_bb_init_verifier` 連續兩次成功；錯誤 CRS／proof 長度回傳錯誤 |
| DIW environment hooks | worker 數為 2、low-memory 關閉、RSS hook 為 0；直接呼叫原 throw hook 只得到 `bb_failure` |
| 診斷隱私 | 合成 log/error canary 未出現在輸出；僅驗列明路徑，未涵蓋所有失敗模式 |

執行記錄：[純 BB](evidence/bb-windows-link/bbapi-wine.log)、[DIW bridge](evidence/bb-windows-link/diw-bridge-wine.log)。C++ helper 只用來檢查原 bridge 的內部 hooks；主要 caller 為 C。兩個 executable 都不經 JVM、JNI 或 JNA。

## ABI 與連結觀察

使用 `x86_64-windows-gnu`、libc++／Itanium C++ ABI。這不是 MSVC C++ 互通測試，亦未建 Rust cdylib 或公開 DLL。橋接物件放在官方 archive 前，使用一般 lazy extraction，沒有 `whole-archive`；避免把 archive 中的預設環境 hooks 強制拉入。

[純 BB imports](evidence/bb-windows-link/bbapi-imports.log) 包含 PSAPI；[DIW imports](evidence/bb-windows-link/diw-bridge-imports.log) 沒有 PSAPI，且 hook 行為測試符合 DIW 實作。其餘依賴包括 Windows UCRT API sets、KERNEL32、WS2_32、bcrypt。imports 差異只是輔助證據，不能單獨證明所有隱私行為。

主 runner 依既有依賴鏈提供 libdeflate archive；另做[不提供 libdeflate 的對照](evidence/bb-windows-link/without-deflate-control.json)，同一子集也能連結並在 Wine 通過。archive 全部物件的 unresolved symbols 聯集不等於每個 consumer 都需要的符號。本結果不能用來刪除正式 libdeflate 依賴，也沒有測到其解壓縮功能。

## 重現方式

準備上述固定 commit 的乾淨 checkout：BB 為 `AztecProtocol/aztec-packages`（可只 sparse checkout `barretenberg/cpp`）、msgpack 為 `AztecProtocol/msgpack-c`、Tracy 為 `wolfpld/tracy`、libdeflate 為 `ebiggers/libdeflate`。從 [BB release](https://github.com/AztecProtocol/aztec-packages/releases/tag/v6.0.0) 取得 `barretenberg-static-amd64-windows.tar.gz`，依[第一輪 metadata](evidence/bb-release-inspection.json) 驗壓縮檔與 archive 雜湊。工具原始碼在 [tools/native-research](../../../tools/native-research/README.md)。

```sh
python3 tools/native-research/probe_bb_windows.py \
  --zig /external/zig-x86_64-linux-0.15.1/zig \
  --bb-source /external/aztec-packages \
  --bb-archive /external/libbb-external.a \
  --msgpack-source /external/msgpack-c \
  --tracy-source /external/tracy \
  --deflate-source /external/libdeflate \
  --out /external/new-empty-bb-probe \
  --wine /path/to/wine64
```

需要 Python 3.11+、Git 與 binutils；輸出必須在 repo 外且為空目錄。省略 `--wine` 只會記為 `linked`。可選 `--wine-prefix`、`--wineserver`、`--wine-dll-path` 支援隔離 Wine。實測在使用者目錄解開 Debian Wine 套件，未安裝系統套件；版本、SHA 與 relocated NLS/server/zlib 調整記在 [toolchain.json](evidence/bb-windows-link/toolchain.json) 和 [wine-packages.json](evidence/bb-windows-link/wine-packages.json)。已安裝的 Wine 不一定需要這些 relocation 修正。

## 尚未完成

原生 Windows、最低 CPU／OS／CRT、BB 全庫重建、有效／無效合成 proof、prover、跨架構雙向驗證、DLL 與 MSVC host、Rust wrapper 均為 `not-tested`。上游 `-march=skylake` 風險仍在；本機 Wine 成功不能證明通用 x86-64 相容。下一步先建立有效 proof fixture 與最低 CPU／原生 Windows 的可重現驗證，再評估正式 build.rs／DLL 邊界整合。

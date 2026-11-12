# Barretenberg Linux ARM64：C bridge 與公開 proof PoC

日期：2026-11-10。依 P2 Linux ARM64 規劃，將官方 BB 6.0.0 ARM64 靜態庫接上**未修改的 DIW bridge**，交叉建出三個 AArch64 ELF executable，在 x86_64 Linux 的 QEMU user `max`、`cortex-a53` 兩個模型通過 C API 與公開 proof 正反向測試。此結果補上[前輪 runtime／Longfellow](linux-arm64-poc.md) 之外的 BB 子集，不代表實體 ARM64 或正式錢包支援。

## 固定輸入與連結方式

BB source 維持 `0219f11d8133970df3974fe5ae65e006bf8c193a`（v6.0.0），msgpack、Tracy、libdeflate 均沿用 [Windows PoC](bb-windows-link-poc.md) 的固定 revision；runner 在編譯前確認四份 checkout 乾淨、HEAD 相符，以及 bridge、constants、archive、fixture 的 SHA-256。所有下載與產物在 repo 外，正式 build script 的 target allowlist 未修改。

| 項目 | 本輪證據 |
|---|---|
| 官方 archive | `barretenberg-static-arm64-linux.tar.gz`，下載 SHA-256 `1e66295cd42ebaa62112c13ae9e689b1818d493deff7fea63a14408a7044fa19`，符合先前保存的 GitHub release digest |
| 解包靜態庫 | `libbb-external.a`，93,393,426 bytes，SHA-256 `332e6bde4d9c040e83035aafb4cd817fb8b1c2e28b19587ed46ff30cdc13d1a1`；191 個 ELF member headers 均為 AArch64 |
| compiler／C++ runtime | Zig 0.15.1，C 與 C++ 都用 `-target aarch64-linux-gnu.2.35 -mcpu=baseline`；與官方同版 Zig 路線配合 |
| 本輪 source-build | 固定 libdeflate 1.24、DIW bridge、C callers 與 hooks；**未重建 BB 主體** |
| 執行工具 | QEMU user 10.0.13、Debian ARM64 glibc 2.41 sysroot，沿用前輪[套件與 SHA](evidence/linux-arm64/packages.json) |

原 constants 透過研究輸出目錄中的 include overlay 提供；不改上游 source。連結順序先放 C caller、DIW hooks／bridge，再以 lazy extraction 取用官方 archive，最後接 source-built libdeflate 與 pthread。未使用 whole-archive，也沒有把官方庫改名當成正式腳本預期的三份 archives。

下載記錄：[download.json](evidence/bb-linux-arm64/download.json)。digest 只驗證檔案一致；tag 對應 commit 不等於已獨立驗證二進位 provenance，官方 archive 的完整編譯選項及可重現建置比對仍未完成。

## 實測結果

三個 executable 分別測裸 `bbapi`、原 DIW bridge 子集及公開 UltraHonk proof。下列測項在兩個 QEMU 模型均通過：

| 測項 | 結果 |
|---|---|
| Blake2s `abc` | 固定已知 digest 相符；caller scratch 與 library allocation／`bbfree` 兩條路徑通過 |
| 非法 MessagePack | 回傳 ErrorResponse；必要時以同庫 `bbfree` 釋放 |
| DIW 初始化／長度 | verifier 初始化可重複；錯誤 CRS 長度及未對齊 proof 長度拒絕 |
| DIW hooks | workers=2、low-memory off、peak RSS hook=0；例外文字固定 `bb_failure`，log/error canary 未洩漏 |
| 有效公開 proof | 接受固定 key、proof、public inputs |
| 三種修改 | 拒絕 public input 修改、proof field 修改、截掉完整 32-byte field |
| 拒絕後恢復 | 還原資料並重複初始化後再次接受原 proof |

使用與 Windows 相同的 [zkPassport 公開合成 fixture](bb-windows-proof-poc.md#fixture-與信任邊界)：SHA-256 `a7470d4c4e71a24da90cfed8ec026cae24d4c7adbbd6f905bfffecad5655067d`，115 個 key fields、458 個 proof fields、9 個 public inputs；每 field 編為 32-byte big-endian。使用 fixture 自帶 key 與原 bridge 的 verifier CRS 常數，不下載完整 proving CRS，不代表 registry、發證機構信任或錢包政策驗證。

完整 **45 個命令**、exit code、工具／來源／產物 SHA 見 [result.json](evidence/bb-linux-arm64/result.json)；proof 輸出見 [max](evidence/bb-linux-arm64/diw-proof-qemu-max.log)、[cortex-a53](evidence/bb-linux-arm64/diw-proof-qemu-cortex-a53.log)。沿用的 C callers 檔名含 `windows`，其中 `native_windows_execution=not-tested` 是原有訊息；它們本輪由 ARM64 compiler 編譯，ELF metadata 和 QEMU 命令記錄才是執行架構證據。ABI caller 的 `positive_proof=not-tested` 僅描述該子測試，proof 由獨立 caller 驗證。

## CPU、libc 與尚未覆蓋的範圍

三個 executable 的 `DT_NEEDED` 均只有 `libc.so.6`，最高需求符號為 **GLIBC 2.34**；本輪使用 Zig 的 glibc 2.35 連結目標，實際執行的 sysroot 為 2.41。這是 C++ runtime 靜態接入的 executable，不是已交付的 C shared library，也不是在 glibc 2.34／2.35 系統上驗收。詳見 [inspection.json](evidence/bb-linux-arm64/inspection.json)。

本輪 source-built 元件明確指定 baseline CPU，但官方 archive 未重建。QEMU `cortex-a53` 通過僅增加所測路徑的模擬指令覆蓋，不能推論全部 archive paths、實體 Cortex-A53、任意 ARMv8 CPU、最舊 kernel 或效能已通過。

同一公開 proof 現在可由 Windows x86_64／Wine 與 Linux ARM64／QEMU verifier 接受，並拒絕相同修改；**未在兩個架構生成新 proof，不宣稱雙向 proof 生成／驗證完成**。尚缺 BB 全庫 source-build、prover、完整 zkPDF 流程、Rust wrapper、動態庫 export／載入、並行／取消與實體硬體驗收。`smoke-tested` 限於上述 C 子集，App 支援仍為 `deferred`。

## 重現

依 [Windows 工具準備](bb-windows-link-poc.md#重現方式)取得固定的 Zig 與四份乾淨 source checkout，改下載[官方 ARM64 static archive](https://github.com/AztecProtocol/aztec-packages/releases/download/v6.0.0/barretenberg-static-arm64-linux.tar.gz)，核對上述 hash 後只取 `libbb-external.a`。公開 fixture 來源及 hash 沿用 [Windows proof 報告](bb-windows-proof-poc.md)。QEMU 與 sysroot 依[前輪 ARM64 準備](linux-arm64-poc.md#重現)。

```sh
python3 tools/native-research/probe_bb_arm64.py \
  --zig /external/zig-0.15.1/zig \
  --bb-archive /external/arm64/libbb-external.a \
  --bb-source /external/bb-source --msgpack-source /external/msgpack \
  --tracy-source /external/tracy --deflate-source /external/libdeflate \
  --proof-fixture /external/outer_count_4_disclose.json \
  --qemu /external/arm64-toolchain/usr/bin/qemu-aarch64 \
  --sysroot /external/arm64-toolchain/usr/aarch64-linux-gnu \
  --out /external/new-empty-bb-arm64
```

runner 會拒絕 repo 內／非空輸出、source/output 重疊、不符固定 revision 或有修改的 checkout、錯誤 archive／fixture。QEMU 執行時清除繼承的 `QEMU_*`、`LD_LIBRARY_PATH`、`LD_PRELOAD`，並明確指定 CPU 與 loader 路徑。無需安裝 binfmt 或改 host loader。[交付檢查](evidence/bb-linux-arm64/validation.json)另核對來源、hash、輸入拒絕與矩陣範圍。

P2 下一項可進入 Linux ARM64 的 OPRF 與其他 Rust feature 建置／向量；BB 則仍需全庫重建及實體 runner。正式平台整合依共同完成條件另案處理。

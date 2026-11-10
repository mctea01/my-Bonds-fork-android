# Linux ARM64：Longfellow 與 DIW runtime 原生 C PoC

日期：2026-11-10。本輪開始 Windows 以外的 CPU／OS 驗證：將固定 Longfellow 與 DIW runtime-only 交叉編譯為 `aarch64-unknown-linux-gnu` ELF 動態庫，以 ARM64 C caller 在 x86_64 Linux 上的 **QEMU user、`-cpu max`** 執行。兩條路徑均不經 JVM／JNI／JNA；這是 ARM64 指令模擬證據，不是實體 ARM64 或完整 App 支援。

## 固定來源與工具鏈

Longfellow 使用 Multipaz `a015c9d93874fe6e09df1354006353ce6f94751d` 與原 gitlink `d5e6be77336933d50bf7f25a954f8ec273eb51ce` 的**乾淨、未修改來源**。Windows SHA-2 patch 與電路嵌入 patch 都未套用。沿用[前輪研究 Cargo.lock](../../../tools/native-research/longfellow-windows.Cargo.lock) 的相同 dependency resolution；檔名保留歷史命名，不代表只能用於 Windows，也不是上游發行時的鎖檔。

DIW 使用原 `native/Cargo.lock`，只建 `diw-zk-ffi --no-default-features`，沒有啟用 OpenAC／TLSn／zkPDF／OPRF。正式來源與建置設定保持不變，所有產物在 repo 外。

| 工具／設定 | 本輪版本與用途 |
|---|---|
| Rust | 1.99.1，另安裝 ARM64 GNU std target |
| C compiler／linker | Debian GCC 14.2.0、binutils 2.44；使用者目錄解開交叉套件 |
| target sysroot | Debian ARM64 glibc 2.41、Linux headers 6.12.38 |
| emulator | QEMU user 10.0.13；只取 `qemu-aarch64`，不安裝 system emulator／binfmt |
| Longfellow Rust flags | `-C target-feature=+aes,+sha2`，與固定 Multipaz target config 相符 |
| DIW runtime flags | 未額外啟用上述 Longfellow CPU features |

工具套件與 SHA 見 [packages.json](evidence/linux-arm64/packages.json)。初次交叉建置遇到的是解開工具鏈後的 host libbfd／libopcodes 路徑，以及 GNU linker script 的絕對 sysroot 路徑；設定 compiler wrapper 的 host library path 與 `--sysroot` 後解決，沒有為此修改原生依賴來源。探索失敗記錄見 [attempts.json](evidence/linux-arm64/attempts.json)。

## 實測結果

| 元件／測項 | 結果與範圍 |
|---|---|
| DIW runtime | release ARM64 cdylib 與 C caller 成功建置；`dlopen`、UniFFI contract 29／checksums、SHA-256 `abc`、native_info 讀取及 free 通過 |
| runtime 錯誤路徑 | 缺少庫及錯誤庫皆以非零退出，分別回報 load failure／missing symbols |
| Longfellow ABI | 六個 exports、LP64、64-bit size_t 高位拒絕、既有 v7／1 spec 通過 |
| Longfellow circuit | v7／1 配置成功，與固定 `.lfa2` 逐 byte 相符，經同庫 free 釋放 |
| Longfellow proof | 接受公開 v7／1 proof；拒絕修改 attribute／transcript／proof；還原後再次接受 |
| ARM64 CPU 能力 | C caller 檢查 QEMU 回報 AES、PMULL、SHA2 HWCAP；動態庫反組譯確有 PMULL 與 SHA-256 指令 |

完整 29 個命令與 hashes：[result.json](evidence/linux-arm64/result.json)。執行輸出：[runtime](evidence/linux-arm64/runtime-qemu.log)、[Longfellow](evidence/linux-arm64/longfellow-qemu.log)；另附 [runtime 負向檢查](evidence/linux-arm64/negative-runtime.json)。Longfellow 開頭的 `proof correctness not tested` 僅是沿用的 ABI 子測試訊息，後續 proof markers 才描述本輪密碼學驗證。

使用的 proof／circuit／public metadata 與前輪 Windows GNU 相同，runner 固定其 SHA。這提供**同一公開 proof 在兩個架構 verifier 上的結果一致性**；尚未在兩個架構產生新 proof，不宣稱跨架構雙向 proving／verification 已完成。測試公鑰也不代表完成發證機構信任或錢包政策驗證。

## CPU、libc 與部署界線

`libzkp.so` NEEDED 為 libgcc_s、libm、libc；`libdiw_zk.so` 為 libgcc_s、libc。兩個庫和兩個 caller 的最高 GLIBC 符號版本均為 **2.34**，實測 loader 是 glibc 2.41。這不是在 glibc 2.34 系統上的驗收，更不能套用先前 Linux x86_64 預建 Longfellow 的 GLIBC 2.17 結論。詳見 [inspection.json](evidence/linux-arm64/inspection.json) 與 readelf 記錄。

Longfellow 的 ARM64 algebra 在缺少 `aes` target feature 時直接 compile_error；此 feature 同時啟用該路徑需要的 PMULL，不能把本輪庫宣稱為任意 ARMv8 CPU 可用。反組譯計數只證明指令存在，QEMU HWCAP 只描述模擬模型；沒有測真機 CPU gating、舊核心、記憶體峰值或效能。

本輪未套用嵌入 patch，因此 `generate_circuit(v7,1)` 仍讀取編譯時來源路徑；QEMU user 可讀 host checkout 才能完成此測試。已有的[隔離嵌入方案](longfellow-relocation-poc.md) 可作後續 ARM64 搬移驗證候選，但本輪未在 ARM64 測搬移。Prover、current-version 電路、BB ARM64、其他 DIW proof features、macOS、musl 與實體 ARM64 runner 仍待後續工作。

## 重現

在 repo 外準備乾淨的上述 Multipaz／submodule checkout，複製研究鎖檔至 `multipaz-longfellow/rust/Cargo.lock`。準備 Rust ARM64 GNU target，以及 [packages.json](evidence/linux-arm64/packages.json) 所列 Debian 套件解開的目錄；QEMU binary 位於相同目錄的 `usr/bin/qemu-aarch64`，GCC 與 ar 也在 `usr/bin`。此 runner 面向 x86_64 Linux host 和該套件目錄配置。

```sh
python3 tools/native-research/probe_linux_arm64.py \
  --multipaz /external/multipaz-clean \
  --toolchain-root /external/arm64-toolchain \
  --cargo /external/cargo/bin/cargo --cargo-home /external/cargo \
  --rustup-home /external/rustup \
  --out /external/new-empty-arm64-probe
```

runner 先檢查版本、乾淨來源、鎖檔及公開 fixture hash，再編譯兩個庫和 C caller、保存 ELF metadata，最後透過 QEMU 執行。QEMU 的 `-L` 指向 ARM64 glibc 目錄；不依賴系統 binfmt 或修改 host loader 設定。[交付檢查](evidence/linux-arm64/validation.json) 保存額外的來源／產物核對與輸入拒絕測試，不增加實體硬體覆蓋。

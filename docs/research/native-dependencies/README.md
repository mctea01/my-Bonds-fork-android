# 原生依賴跨平台研究

性質：研究紀錄（2026-11-09 至 2026-11-11）。前七輪是 Codex 的純研究與隔離 PoC，沒有改產品；第八輪把可落地的部分做進正式建置。原始證據保留原貌，不回頭改寫。

**只想知道現況：** 讀 [follow-up-implementation.md](follow-up-implementation.md) 的結果總覽，以及建置說明 [native/README.md](../../../native/README.md)、[native/zkpdf-prover/README.md](../../../native/zkpdf-prover/README.md)。各平台目前有哪些證明後端見 [專案現況](../../STATUS.md#35-平台)。

## 結論

- x86_64 的 Barretenberg 基準由上游的 Skylake（AVX2、BMI2）改為 x86-64-v2，舊 CPU 不會一載入就當掉。
- Android 32 位元（armeabi-v7a、x86）只有 runtime（相片解碼），沒有任何證明後端；Barretenberg 需要 128 位元整數與 64 位元 `size_t`。
- Windows x86_64 的 zkPDF 與 Barretenberg 5 由 Linux 以 llvm-mingw 交叉建置，不含 GCC 的執行階段（專案要求隨 App 散布的原生程式碼不含 GPL 家族元件）。所有 Barretenberg 呼叫都要經 `zkpdf-prover/src/bbthread.rs`。
- Linux ARM64 的原生函式庫可交叉建置，還沒有桌面安裝檔與 CI。
- Windows 沒有 Longfellow：上游來源在 Windows 建置失敗，PoC 需要隔離的研究 patch，沒有採用。
- 不需要 wasm2native 或 Perry：所有 PC 必需的密碼學依賴都有原生來源。
- 沒有任何一項在實體 ARM、實體 32 位元裝置或真正的 Windows 上以 PoC 驗證；正式建置由 CI 與實機補上。

## 文件

| 文件 | 內容 |
|---|---|
| [follow-up-implementation.md](follow-up-implementation.md) | 第八輪：落到正式建置的項目、量測與對先前研究的更正 |
| [research-summary.md](research-summary.md) | 前七輪總結：固定版本清冊、工具鏈與 ABI 矩陣、缺口與後續清單 |
| [dependency-graph.md](dependency-graph.md) | 用途分類與依賴圖（清冊為同資料夾的兩份 CSV） |
| [native-abi-contracts.md](native-abi-contracts.md) | 原生 ABI 契約 |
| [pc-native-dependency-readiness.md](pc-native-dependency-readiness.md) | PC Native 依賴就緒度 |
| [future-porting-backlog.md](future-porting-backlog.md) | 後續移植工作清單 |
| [barretenberg-native.md](barretenberg-native.md) | Barretenberg 6.0.0 與 zkPDF 的可移植性 |
| [bb-windows-link-poc.md](bb-windows-link-poc.md)、[bb-windows-proof-poc.md](bb-windows-proof-poc.md) | Windows GNU 的 Barretenberg 連結與公開 proof 驗證（Wine） |
| [bb-linux-arm64-poc.md](bb-linux-arm64-poc.md)、[linux-arm64-poc.md](linux-arm64-poc.md) | Linux ARM64 的 Barretenberg、Longfellow 與 runtime（QEMU） |
| [longfellow-native-matrix.md](longfellow-native-matrix.md)、[longfellow-windows-poc.md](longfellow-windows-poc.md)、[longfellow-relocation-poc.md](longfellow-relocation-poc.md) | Longfellow 的原生依賴、Windows 建置與電路資產搬移 |
| [rust-backends.md](rust-backends.md) | Rust 證明依賴（Noir、OpenAC、TLSNotary、zkPassport、OPRF） |
| [fallback-tools.md](fallback-tools.md) | 不啟動 wasm2native 與 Perry 的理由 |
| [evidence/](evidence/README.md) | 原始證據（版本、雜湊、建置與執行紀錄）；驗證工具在 [tools/native-research](../../../tools/native-research/README.md) |

# R03–R05：Rust 原生證明依賴研究

**ARM64 runtime 補充**：[Linux ARM64 PoC](linux-arm64-poc.md) 已用原 lock／未修改來源建置 `diw-zk-ffi --no-default-features`，QEMU 下通過 C ABI、SHA-256 與 native_info/free。這不增加 OPRF／OpenAC／TLSn／zkPDF 的 ARM64 驗證範圍。

研究基準：`3428b8ee12ac5e644f478d4c6e43854376202fa4`；日期：2026-11-09。本文的編譯／執行結論限於本工作包：所有候選 target 均為 `source-reviewed`，`experimental_result=not-tested`。沒有宣稱跨架構互通或錢包支援；沒有修改電路、資產、正式建置腳本與 App。iOS 不在本輪研究範圍。

## 已確認的依賴邊界

| feature／元件 | 實際原生依賴 | 不需要的執行環境 | 未來 PC Native 介面 |
|---|---|---|---|
| `diw-zk-ffi` default | UniFFI、sha2、標準函式庫；後端函式存在但未啟用時回 Unsupported | JVM 是現行呼叫端，不是 Rust 計算的必要條件 | `cdylib` + `rlib`；UniFFI 契約非任意版本穩定 C API |
| `openac` | patched witnesscalc、ecdsa-spartan2、Spartan2、circom-scotia、halo2curves、rayon、OS entropy/files/threads | 不載入 Circom WASM、Wasmer、GMP 或 C++ witnesscalc | `openac_age` Rust API；C 呼叫端需 UniFFI adapter 或另定契約 |
| `tlsn` | TLSn alpha.15、MPZ、ring、RustCrypto、Tokio、snow、OS sockets/threads | 無 Node／瀏覽器 WASM 計算需求 | `zktls` Rust API + Channel trait；非 Rust 呼叫端需 callback ABI |
| `oprf` | taceo-oprf-core、arkworks 0.6、BabyJubJub、Poseidon2、rand；傳遞 BLAKE3 含原生編譯路徑 | 無 Barretenberg、CRS、Noir、JS | 現有 UniFFI exports；不是已發佈的簡單 C header |
| `zkpdf` | Noir ACVM/blackbox/ABI、BB C++ bridge、zkpassport-verify、三個 vendored zkPassport crates，並自動開啟 `oprf` | 不需 bb.js／Noir WASM runtime | Rust API + BB C bridge；最終可連結性取決於 R01 |
| `zkpassport-verify` 單獨 crate | Noir field/blackbox、純 Rust 結構、承諾與 policy 檢查 | 不直接依賴 BB | `verify` 接受外部 proof verifier callback；它不是完整無 BB 證明器／驗證器 |
| vendored zkPassport core/bridge/ffi | Rust JSON、field、ECDH/AES-GCM、session driver | 上游 WASM crate 沒有 vendored；不需要 npm utils | Rust API，並有 `extern "C"` exports；目前 manifest 只產生 Rust library，獨立動態庫未測 |

證據：`native/diw-zk-ffi/Cargo.toml:9–19`、`native/openac-age/Cargo.toml:7–24`、`native/zktls/Cargo.toml:7–23`、`native/zkpassport-verify/src/lib.rs:527`。完整錢包 `zkpassport_verify` 在 `native/diw-zk-ffi/src/zkpassport.rs:63–70` 以 `zkpdf_prover::verify_ultrahonk` 實作 callback；不能把只解析 public inputs 的成功當作 cryptographic verification。

## 固定版本與供應鏈證據

所有本地路徑均相對研究基準 repository；可用 `git show 3428b8e:<path>` 重讀。Cargo.lock 的指定套件、完整 git SHA 與 registry checksum 擷取於 [rust-lock-extract.json](evidence/rust-lock-extract.json)。此擷取是 workspace lock 的聯集，不能取代按 feature/target 的 Cargo resolution。

| 依賴 | 釘選基準 | 用途／授權來源 |
|---|---|---|
| OpenAC／zkID | `b395e09c225ff45b003f0087c28e2e208e22f944` | `native/openac-age/VERSIONS.json:3`，MIT；保留既有 overlay 歸屬 |
| ecdsa-spartan2 | vendored 0.0.1，專案基準 commit 固定其內容 | `native/openac-age/vendor/ecdsa-spartan2/Cargo.toml:1`，MIT |
| Spartan2 | 0.4.0，`d687dbb639eccbdd21e62fecec97c5826bc4dbbf` | pinned upstream manifest 已讀；Edition 2024，MIT（NOTICE） |
| circom-scotia | 0.2.0，`bd39c019dba20d32ce5727e2408632dbca269e82` | pinned manifest 已讀；MIT OR Apache-2.0 |
| circom-witnesscalc | 0.3.0，`d48eb7c97857d46b8a75c94ab96f769207263245` + secq256r1 patch | VERSIONS 記錄 patch SHA-256；MIT OR Apache-2.0 manifest，NOTICE 記錄 MIT 選項 |
| TLSn | 0.1.0-alpha.15，`47aee45b53e06648c1b2ad3689b367b8c923fdec` | `native/zktls/Cargo.toml:8`；MIT/Apache-2.0（NOTICE） |
| MPZ／clmul | 0.1.0-alpha.6，lock resolved `6ebfe619490c3155a589fc6a3be83b0976de19dc` | TLSn upstream 以 tag rev 引用，Cargo.lock 提供不可變 SHA |
| snow | 0.10.0 | 原生 Noise；NOTICE 仍列 0.9.6，屬日後應修正的版本文字 |
| ring | 0.17.14 | C／組語／Rust、平台 entropy；Apache-2.0 AND ISC（NOTICE），不是純 Rust 的可攜性保證 |
| Noir acvm／bn254_blackbox_solver／noirc_abi | 1.0.0-rc.3，`5a7ee9bf5ed8973076df7bb0d2b723024db09ae7` | `native/zkpdf-prover/Cargo.toml:19–21`；本輪未改演算法或版本 |
| zkPassport core／ffi／bridge | 0.1.0，`dae2129a0722e9391a4a243c6d53df0a134a74f8` | vendored README 與 Cargo manifests 宣告 MIT；未取得額外授權保證 |
| taceo-oprf-core | 0.6.3 | `native/diw-zk-ffi/Cargo.toml:35`，MIT/Apache-2.0（NOTICE） |
| Poseidon2／arkworks | zkPassport core 用 0.2.1／0.5；OPRF 用 0.3.1／0.6 | 兩組同時存在；不可為縮減相依而直接統一版本或序列化 |

固定上游 URL、抓取結果與內容 hash 在 [rust-upstream-sources.json](evidence/rust-upstream-sources.json)。初次猜測的兩個 MPZ 路徑回 404，已改用 workspace 實際 `crates/core` 路徑並取得 200；不把 404 當作來源不存在。

## R03：OpenAC 原生路線

`ecdsa-spartan2/build.rs:1–7` 已關閉舊 native-witness 路徑，沒有編譯 C++ witnesscalc。`circom-scotia` 上游預設 `witness-calculator` 會啟用 Wasmer，但 vendored ecdsa manifest 對它設定 `default-features=false`；Spartan2 的 wasm getrandom dependency 是 target-specific。lock 中出現 wasm-bindgen 並不表示桌面執行時必須 WASM。

`circom-witnesscalc/build.rs:8–10` 在 **host** 執行 `prost_build::compile_protos`，需要 protoc；`:22–32` 用 bindgen 讀 header，需要 host libclang。Android 分支另讀 target compiler/linker 設定。這些是建置依賴，不能列成裝置執行時 libclang/protoc。Header 只 allowlist `gw_status_t`，未看到此腳本編譯 C 實作。Rust `ark-ff` 的 `asm` feature 是明確啟用項，但是否在特定 CPU 啟動要檢查解析後 dependency cfg 與編譯指令，不能直接推定所有 CPU 需要 ADX/BMI2。

`native/openac-age/VERSIONS.json` 的 runtime bundle 18 個檔案均以 SHA-256 核對相符，記錄見 [rust-openac-bundle-check.json](evidence/rust-openac-bundle-check.json)。這只驗證供應來源一致，不是 proof 功能測試。

32-bit 優先風險是位址空間與索引轉換：Prepare graph 檔案 93,459,128 bytes，但解碼成節點、witness、prover key 後必然大於檔案本身；不能拿壓縮或磁碟大小當峰值記憶體。`openac-age/src/lib.rs:30–32,133–162` 使用 64 MiB worker stack 與最多 8 個各 64 MiB 的 Rayon workers，還不包含 heap。`storage/proto_deserializer.rs:33–39,109–119` 將 u64 offset／witness indices 轉 usize，未逐一檢查截斷。須以固定 graph 做 32-bit 範圍檢查、allocation failure 與小量 verifier-only 測試。

`graph.rs:354` 的 `Node::SIZE` 取決於 usize，但實際 `calc_witness_graph` 經 protobuf decoder 產生 VecNodes（`lib.rs:191–205`），因此不能僅憑內部 mmap node layout 宣稱公開 graph 格式已不相容。verifier-only 目前沒有獨立 Cargo feature；現有 openac 仍編進 witness calculator，未來若拆分需保留相同 proof/key 格式。

Windows 需 host protoc/libclang 配置與 MSVC 或 GNU 一致的 linker；現有 Rust code 不是 POSIX-only 的證據。敏感檔案權限另需處理：`openac-age/src/lib.rs:280–290` 的 0600 設定只在 Unix 執行，Windows 不能把編譯成功視作 ACL 等價。這是未來整合驗收條件，本輪不改寫 storage。

## R04：TLSNotary 原生路線

TLSn alpha.15 → MPZ alpha.6 → `clmul`/AES/BLAKE3、TLS forks → ring；加上本地 Tokio/snow，沒有證據需要 OpenSSL 動態庫。Cargo.lock 未列 `openssl-sys`/`aws-lc-sys`；此為本次 lock 範圍的發現，不是所有 feature 的永久保證。ring、BLAKE3 的 C／組語 target compiler 和 archive 是交叉編譯檢查重點；snow lock 有 ring 項目亦不能直接推定選中的 resolver，需 `cargo tree -e features`。

已閱讀固定 MPZ `crates/clmul/src/{lib.rs,backend.rs}`：x86/x86_64 有 runtime detection 與 software fallback；64-bit 採 soft64、其他採 soft32；AArch64 PMULL 要 opt-in `clmul_armv8`，該版本有 `feature(stdsimd)` 條件。初始研究應保留 default，不加 `target-cpu=native` 或強制 ARM crypto flags。此結論只涵蓋 clmul，未完成所有 crypto crate 的最低 ISA 審查；不能據此承諾整條 TLSn 在 RISC-V 上編譯成功。

三層驗收須分開：

1. **核心編譯**：`cargo check/build -p diw-zk-ffi --features tlsn`，確認 target linker、ring/BLAKE3、MPZ；不需要連外伺服器。
2. **平台網路與 callback**：`native/zktls/src/channel.rs:12–16` 要 `Channel: Send + Sync`，`close()` 必須解除進行中的 send/receive；`:73–137` 建 reader/writer threads 和 Tokio current-thread runtime。Native caller 要提供能關閉的 callback/context，不可把 trait object 直接當 C ABI。
3. **協定端到端**：固定合成 CA、localhost TLS server、雙端 Noise 與 Proxy/MPC，測取消、超時、截斷、揭露限制；只有此層通過才可報相應功能 smoke-tested。跨架構仍需雙向互驗。

32-bit 不是已確認失敗：`protocol.rs:75–88` 限送出 4096／接收 262144 bytes，因此 `:419–420` 的乘 64 + 65536 在此上限下不會自行溢出 32-bit usize；真正風險是 MPZ 的中間記憶體、依賴組語／原子支援、socket callback 生命週期與持續時間。不要只搜尋到 `as usize` 就判 incompatible。Noise `MAX_WIRE=1 GiB`（`noise.rs:10`）是累計上限，不代表一次配置 1 GiB。

## R05：Noir、zkPassport 與 OPRF

Noir ACVM、blackbox solver 和 noirc_abi 已經是 Rust library；編譯電路的 nargo／研究用 bb.js 不是 App runtime。`zkpdf-prover` 的 `bb` feature 才啟用 C++ bridge：不啟用它仍可研究 `execute_public_inputs`，但不提供 `prove_ultrahonk`／`verify_ultrahonk`。本專案的 `diw-zk-ffi/zkpdf` 將 bb、zkPassport 與 oprf 綁在同一 feature，因此需要 BB 的平台問題會影響整個 feature。

`zkpassport-verify` 單獨可以檢查 manifest tree、public inputs 和 parameter commitments；完整 `verify` 仍需要可靠 proof callback。不能給 callback 固定 `Ok(())` 後宣稱驗證成功。`zkpdf-prover/src/lib.rs:38–42` 有 verifier 專用初始化；完整 proving 需要認證 CRS（`:45–55`）。是否需要完整 CRS 檔案與目前 verifier 最小資料，交 R01／ABI 研究核對；不能把無大 CRS 的 verifier 當作無 C++。

vendored `zkpassport-ffi/src/lib.rs:430–485` 已有 session C exports：create 回 opaque handle，next/provide 回 JSON C string，必須以 `zkpassport_free_string` 釋放，session 以 `zkpassport_session_free` 釋放。`zkpassport-bridge/src/ffi.rs:31–90` 另有 stateless C exports 與 `zkbridge_free`。兩者皆可脫離 JVM 的來源方向，但尚未輸出／檢查實際 shared library exports；Rust dependency dead stripping 與 export visibility 待驗證。它們沒有通用 `catch_unwind` 外層；多處 `unwrap` 與 unsafe pointer 前置條件必須遵守，不可把 malformed C pointer 的 UB 當作可回復 JSON error。session 接受可變引用，呼叫端要序列化同一 handle 的操作，不能並行 next/provide/free。專案目前經 Rust API 包裝這些 crate，不能把新增 C adapter 視作已實作。

OPRF 是較小的第一個跨平台 PoC 候選：`oprf.rs:7–9` domain separator 固定 1,330,664,006，field parsing 檢查 modulus；使用公開合成密鑰與固定 query 比較公鑰／hash，blinding/evaluation 的隨機輸出不要求逐位相同，應驗證有效 DLogEqualityProof、finalize 結果以及錯誤 proof 拒絕。`oprf` 不引入 BB／Noir／CRS，但 BLAKE3 原生編譯與 OS entropy 仍須確認。

## 各目標評估與工作量

下列均是來源分析後的候選路線，非已編譯的支援聲明；工時是熟悉專案工程師的研究估計，不含完整 App、UI 或產品驗收。每格涵蓋對該依賴的下一個可交付 PoC。

| Target | OpenAC | TLSn | OPRF／Noir／zkPassport Rust 部分 | 建議投入 |
|---|---|---|---|---|
| `x86_64-unknown-linux-gnu` | 基準；protoc/libclang、64 MiB stacks；測固定 graph | ring/C compiler、MPZ soft/hardware、localhost 協定 | 先 runtime/OPRF；zkpdf 另等 BB | 1–3 人日建立各 feature 可重現基準 |
| `x86_64-pc-windows-msvc` | 原生 Cargo 候選；host tools、檔案 ACL、路徑與 tempfile | ring/MSVC archiver、Winsock、close unblock | OPRF 與純 Rust metadata 優先；zkpdf 被 BB 阻擋 | 3–6 人日；FFI ownership 另 1–3 日 |
| `x86_64-pc-windows-gnu` | 不與 MSVC .lib／CRT 混用；MinGW tools | ring/BLAKE3 compiler 指定與 socket 行為 | 同上；不因 GNU 能編譯 Rust 就視為 BB 可連結 | 2–4 人日另驗 ABI |
| `aarch64-unknown-linux-gnu` | 原生 ARM runner 或交叉 linker/sysroot；bindgen 是 host | 預設 clmul soft64；ring ARM compiler；網路另測 | Rust default CPU baseline，避免 host `native` flags | 2–5 人日 |
| `aarch64-apple-darwin` | 現有腳本列目標，仍須本輪重測 | 系統 sockets/entropy、ring ARM | xcrun SDK；目前主腳本 minimum macOS 14.0 | 1–3 人日 |
| `x86_64-apple-darwin` | 正式 wrapper 未列目標，隔離直接 Cargo | ring Intel、minimum OS、Intel runner | Rust Intel target 不等於現有 wrapper 支援；BB 另案 | 2–4 人日 |
| `aarch64-pc-windows-msvc` | LLVM/libclang host 與 ARM64 target 需分開 | ring ARM64 MSVC、Windows thread/socket 最不確定 | 先 OPRF；靜態／動態 exports 待查 | 4–8 人日，工具鏈成功後再估 |
| `aarch64-linux-android` / `x86_64-linux-android` | 既有兩 ABI；cargo-ndk/linker、固定 graph baseline | ring NDK、Thread callback；device loopback 測 | 既有 NDK 28.2.13676358／API29 路線；本輪未跑裝置 | 2–4 人日復驗 |
| `armv7-linux-androideabi` / `i686-linux-android` | graph offsets、heap、stack，沒有現成 verifier-only feature | soft32 只是 clmul 局部證據；原子、ring、MPC memory 待查 | OPRF 小 vector 優先；不承諾 zkpdf prover | 4–8 人日研究，prover 成本未知 |
| `riscv64gc-unknown-linux-gnu` | soft math 候選、protoc host、資產證明時間未知 | clmul soft64；ring target 和 BLAKE3 是優先查證點 | 先 OPRF／metadata；BB 各自處理 | 3–7 人日可行性，不含修 port |
| `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl` | target libc/linker；不可重用 glibc archive | ring/musl、entropy、DNS/socket 行為 | 靜態 host 可行性與 `cdylib` 不同；PIC、crt-static 必須獨立設計 | 3–6 人日 |

共同 CPU／OS 最低門檻仍 `unknown`，除腳本指定的最低值及上文 clmul 局部源碼證據；binary 檢查與實機最小 CPU 測試才能確定。所有候選平台的 `wallet-app-support` 留待未來階段。

## 可重現的下一步指令與驗收界線

本工作包開始時 `rustc`/`cargo` 不在 PATH，所以沒有把任何 Cargo 命令記成 build-attempted。`native/rust-toolchain.toml:2` 固定 **1.99.1**；workspace `rust-version=1.95` 是最低要求，README/AGENTS 說 1.95.0；`native/openac-age/build.sh:7` 更硬性拒絕非 1.95.0。這是現有 reproducibility 衝突，本輪不改正式腳本。MPZ pinned manifest 確實宣告 MSRV 1.95；不要因此偷偷降級專案工具鏈。

整合階段已在 repo 外安裝固定 1.99.1，完成 runtime-only cdylib/C smoke，並以 `--features oprf --lib` 跑過 10 項 Rust 測試，其中 3 項覆蓋 OPRF 正反向合成輸入、公鑰 hash、proof/key binding。完整命令及結果見 [baseline.json](evidence/baseline.json)、[oprf-tests.log](evidence/oprf-tests.log)。OpenAC/TLSn 在此組合中關閉，相關測試只檢查取消／Unsupported／長度；不能把 10 項通過報為這些引擎功能通過。Noir/BB-backed disclosure circuit 與跨架構 OPRF 互通仍未測。

在具備固定工具鏈的原生 target runner，使用獨立暫存 source snapshot、CARGO_TARGET_DIR，保留 Cargo.lock。命令草案（未執行）：

```bash
# In a disposable copy of native/ at the recorded baseline, with host tools installed.
# TARGET must be a triple from the matrix; use its native runner or configured linker.
export CARGO_TARGET_DIR=/tmp/diw-native-research-target
cargo +1.99.1 tree --locked --target "$TARGET" -p diw-zk-ffi --no-default-features --features openac -e features
cargo +1.99.1 build --locked --release --target "$TARGET" -p diw-zk-ffi --no-default-features --features openac
cargo +1.99.1 build --locked --release --target "$TARGET" -p diw-zk-ffi --no-default-features --features tlsn
cargo +1.99.1 build --locked --release --target "$TARGET" -p diw-zk-ffi --no-default-features --features oprf
# Execute tests only on a matching target runner; do not mistake cross compilation for execution.
cargo +1.99.1 test --locked --release --target "$TARGET" -p diw-zk-ffi --no-default-features --features oprf
cargo +1.99.1 test --locked --release --target "$TARGET" -p openac-age
cargo +1.99.1 test --locked --release --target "$TARGET" -p zktls
```

每次分別記錄 resolution、build、link、load、最小向量與雙向跨架構驗證。OpenAC 的 ignored 全流程測試需要額外固定資產；`native/openac-age/README.md` 已列安裝與驗證命令，不可把沒有 assets 的預設單元測試當作完整 Prepare/Show。TLSn 要額外確認 Rust tests 真正覆蓋網路協定，App callback 路徑的既有 `ZkTlsLoopbackTest` 不在本輪執行。

後續 native build files 調整候選是 OpenAC wrapper 版本檢查與目標白名單、witnesscalc bindgen target 設定、32-bit checked conversion、必要的 C adapter 與 symbol/ownership tests；只有具體編譯錯誤或 ABI evidence 出現才 patch。Noir/BB/Spartan2 密碼學、proof/key 格式與電路一律保持原釘選。

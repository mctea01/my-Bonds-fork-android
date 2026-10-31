# P4 桌面效能量測（Round 3）

基準：`552204f4132839c1a63ac3fe7b3b3ad234dd8862`。本輪範圍是桌面；
D1 實機與 App 量測頁由使用者／Claude 接續。所有輸入都是合成資料。

## 環境與方法

Linux x86_64 managed cloud container，cgroup 配額 **2 vCPU、8 GiB RAM**。
不是獨占實體桌面，也不能拿這些數字替代 D1 手機數據。工具為 Rust
1.95.0、TLSn alpha.15 commit `47aee45b53e06648c1b2ad3689b367b8c923fdec`、
Noir 1.0.0-beta.15、bb 2.1.9。TLSn 測量來源為 WP5 `b474f43`，當時以隔離副本測試；之後整合分支已改用 Rust 1.95.0 並更新鎖檔。

每個 case 執行 first 與 warm 各一次，**不是統計中位數**。first 是該程序
第一次呼叫，不代表清空 OS page cache 的真正冷機；SRS 已下載。Noir 的
兩次證明各啟動新 bb 程序，warm 主要反映檔案快取。量測期間暫停其他
電路編譯；proof 與 witness 資產不提交。

RSS 用 Linux `getrusage(RUSAGE_CHILDREN).ru_maxrss`，每個 case 由獨立
Python child 收集，避免跨 case 累積高水位。Noir 是 bb 程序，TLSn 是同一
Rust 程序內 prover + verifier + HTTPS fixture 的合計；**不是每個角色的
原生 heap**。同機傳輸沒有 RTT、丟包或手機熱降頻。

## SHA-256 aligned window

公開 8-word mid_in、8-word mid_out，私密 bytes 不加 padding。此處量測
M3a component main，並非完整 PDF proof。bb 使用 UltraZKFlavor（下一節）。

| 區塊 | Gates | First s | Warm s | Peak RSS MiB | Proof bytes | Verify ms |
|---:|---:|---:|---:|---:|---:|---:|
| 65 | 272,481 | 18.642 | 17.781 | 833.4 | 16,256 | 36.2 |
| 130 | 542,101 | 34.271 | 32.442 | 1656.1 | 16,256 | 19.8 |
| 260 | 1,081,341 | 67.458 | 68.014 | 3256.7 | 16,256 | 26.0 |

每組另有 512 bytes public inputs。獨立 `bb verify` 全部通過，修改一個
公開 midstate field byte 後驗證失敗。完整 numeric records 與 ACIR/VK
hash 放在 M3a 分支 `native/circuits/validation`、`VERSIONS`。

## bb 零知識設定

bb 2.1.9 的 `--disable_zk` 預設 false。使用
`-s ultra_honk --oracle_hash poseidon2`，prove、VK、verify 都不帶該旗標。
已核對 v2.1.9 的 `api/api_ultra_honk.cpp` 與
`bbapi/bbapi_ultra_honk.cpp`：此組合選 UltraZKFlavor；disable_zk=true
才選 UltraFlavor。不能沿用舊版預設設定的推論，或只因 verify 通過就稱為 ZK。
完整固定 tag 連結與指令見 M3a `IMPLEMENTATION.md`。

同一個 65-block 電路的非 ZK proof 為 14,624 bytes；ZK 為 16,256 bytes，
增加 1,632 bytes（約 11.2%）。非 ZK 首次 prove + self-verify 為 14.484 秒，
峰值 840.1 MiB；只作旗標比較，不納入可用後端或正式資產。

## TLSNotary

每個 case 新建 localhost TLS 1.2 PKI，以 Noise 包覆 alpha.15 protocol。
回應 body 為合成 bytes，揭露並以 TLSn SHA256 salted commitment 綁定
`status=OK` 9 bytes；request 揭露 method/path 與 Host，query 保持私密，回傳未揭露 bytes 為零。`max_sent=4096`，`max_recv=body_size+1024`。
驗證欄是互動式 `accept()` 加補充憑證驗證的時間，含等待 peer，並非純
CPU verify。session 時間包含 TLS、Noise、proving、verification 與收尾。

| 模式 | Body KiB | First ms | Warm ms | Combined peak RSS MiB | Prover→Verifier MiB（warm） | Verifier→Prover MiB（warm） | Verify phase ms（warm） |
|---|---:|---:|---:|---:|---:|---:|---:|
| proxy | 1 | 732 | 506 | 138.2 | 0.516 | 0.986 | 11 |
| proxy | 16 | 491 | 487 | 138.9 | 0.517 | 1.001 | 14 |
| proxy | 200 | 671 | 692 | 142.9 | 0.527 | 1.640 | 92 |
| mpc | 1 | 2289 | 1902 | 488.0 | 59.067 | 3.243 | 16 |
| mpc | 16 | 1921 | 1806 | 459.9 | 59.091 | 3.250 | 14 |
| mpc | 200 | 1996 | 1814 | 498.0 | 59.277 | 3.245 | 16 |

傳輸量包含 Noise 與 segment framing，只計雙方協議通道，不計連到目標
HTTPS server 的 socket。TLSn 是交互式協議，沒有可與 Noir 比較的獨立
離線 proof 檔；請以雙向傳輸量衡量。MPC 基礎成本約 62 MiB，LAN／中繼
的 latency 與吞吐量仍須實機測量。本地單次數據的非單調差異屬啟動與
排程變動，不可宣稱較大回應一定更快。

## OpenAC

本環境未提供 `DIW_OPENAC_DATA`，按需求 **SKIPPED**，沒有以其他 ZK
後端代替。`OpenAcZkBenchmark` 會透過 `OpenAcAgeNativeProver` 產生合成
TWDIW-shaped credential，分別記錄 Prepare、Show、兩次 reblind 合計、
verify_linked、自驗後 proof 大小與 first/cached-warm。phase 邊界取自
prover 的進度 callback；包含該 phase 的 input preparation／cache 工作。
RSS 是 JVM 程序高水位，不能標成隔離的 native heap。

## 重現

```sh
# Install/pin the native toolchains first; use the relevant M3a/WP5 checkouts.
export DIW_CIRCUITS=/path/to/m3a/native/circuits
export DIW_NARGO=/path/to/nargo
export DIW_BB=/path/to/bb
export DIW_BB_CRS=/path/to/local/crs
export DIW_TLSN_TEST_BINARY=/path/to/release/deps/loopback-<hash>
# Optional: verified OpenAC assets under this directory's zk-assets/.
export DIW_OPENAC_DATA=/path/to/openac-data
./gradlew :test-servers:test --tests '*ZkBenchmark*' -Pbench=true
```

不帶 `-Pbench=true` 時不跑昂貴量測；缺少必要環境變數會明確 SKIP。
OpenAC 還需要整合分支可用的 `-Pdiw.zkFeatures=openac` 原生 library。
TLSn executable 是 `cargo test --release -p zktls --no-run` 產生的 loopback
測試程式；目前先用 WP5 的隔離驗證環境。所有數字輸出在
`test-servers/build/reports/zk-bench/`，不寫入使用者文件或真實查詢內容。

## 門檻建議與估計式

- SHA gate count 在本三組是 `G(B)=4148*B+2861`。本機證明時間約
  `0.26*B` 秒，可用 `0.29*B` 秒作這組環境的粗略保守估計；不是跨裝置
  保證。RSS 約 `1.7 KiB * 2^ceil(log2(G(B)))`，記憶體會在 proving domain
  擴大時跳級，不能只對 byte count 線性估算。
- 260-block SHA 單項已約 68 秒／3.17 GiB，尚未加入 inflate 或 PDF lexer。
  在這台環境無法支持「完整 zkPDF 一分鐘內」的宣稱；手機 A 級
  兩分鐘／3 GiB 的目標也尚無 D1 數據支持。等級門檻先保留待量測狀態。
- TLSn 可先顯示這台桌面的 session 時間與傳輸量，網路額外下限可估為
  `outbound_bytes/uplink_bytes_per_second + inbound_bytes/downlink_bytes_per_second`；
  實際可能全雙工重疊，也受互動 RTT 影響，不能用它作精確 ETA。
- OpenAC、inflate 全 profile、M3b 完整 PDF 及手機數據未充分量測前，
  不應由這些 component 結果設成硬性禁止本機運算的條件。沿用既有
  估計提示與使用者選擇，後續由 Claude 接到 `ZkCapability`。

## 完整 zkPDF 電路（Round 4 前置測量，尚未完成）

本節基準為 `24f32af39d605c92ee3f038ced1263ddbff3c6ff`，與上方
Round 3 環境不同：Linux x86_64、AMD EPYC 9V74，cgroup 配額
**4 vCPU／32 GiB RAM**。工具仍為 nargo 1.0.0-beta.15（noirc
`83245db91dcf63420ef4bcbbd85b98f397fee663`）、bb 2.1.9。

**完整 `pdf_text_v1_1p` 尚未實作；以下是完整容量 inflate 元件的
編譯預檢，不是完整 PDF 電路的 gate／prove／verify 測量。**
完整容量固定為 8,192 compressed bytes、40,960 plain bytes、20,480
tokens、8 blocks，沒有縮小。每次建立新的獨立 temporary package，
沒有 ACIR 快取；編譯器保留全部約束檢查。RSS 為該子程序的 Linux
峰值，24 GiB 是為雲端工作階段保留餘裕而設的 **RLIMIT_AS 位址空間
預算**，不是 RSS 上限，也不是第 3.7 節的證明記憶體門檻。

| inflate 實作 | 編譯時間預算 | 結果 | 經過時間 | 峰值 RSS |
|---|---:|---|---:|---:|
| 原 M3a | 600 s | timeout，無 ACIR | 600.42 s | 17,328,776 KiB（16.53 GiB） |
| 平坦 Huffman 表 | 600 s | timeout，無 ACIR | 600.89 s | 14,300,592 KiB（13.64 GiB） |
| 平坦 Huffman 表 | 1,800 s | allocation failure，SIGABRT，無 ACIR | 783.45 s | 24,139,060 KiB（23.02 GiB） |

延長預算的編譯器訊息為 `memory allocation of 1080 bytes failed`。
尚不知道不設此預算時所需的總記憶體；不能把 23.02 GiB 當成完成
編譯的成本，也不能由編譯失敗推定 prove 時間或手機可用性。完整
gate、prove、verify、proof 大小與完整 ACIR／VK SHA-256 均 **未取得**。
原始數據在 `native/circuits/validation/m3b-full-inflate-*.json`。

重現優化版預檢：

```sh
cd native/circuits
python3 -I tools/compile_profile.py --nargo /path/to/nargo \
  --seconds 1800 --address-space-gib 24 --output target/full-profile.json
```

同一修改另以小容量 `inflate_probe` 驗證：128 compressed／128 plain／
32 tokens／1 block，gate 從 782,382 減為 **680,210（減少 13.06%）**，
296,094 ACIR opcodes。以 UltraZKFlavor（`-s ultra_honk --oracle_hash
poseidon2`，不帶 `--disable_zk`）產生兩次 proof，first／warm 為
22.29／17.33 秒、峰值 1,795,500／1,782,852 KiB；獨立驗證 17.15 ms，
proof 16,256 bytes，public inputs 0 bytes。first 包含首次 CRS 下載，
同時有上述完整容量編譯；只作 correctness probe，不是隔離桌面的
正式效能基準。數據與 ACIR／VK hash 見
`native/circuits/validation/m3b-inflate-probe.json` 及 `VERSIONS`。

供 Claude 評估的第 3.7 節方案（**未採用**）：

| 方案 | 可量化的局部估計 | 尚不能推論之處 |
|---|---|---|
| `MAX_PLAIN` 40,960 → 32,768 | 輸出與逐 byte lexer 的固定迴圈少 20%；其餘容量不變 | 不是總 gate／RSS 少 20%；20,480-token 解碼與兩個 SHA 視窗沒有縮小 |
| `MAX_PLAIN` 40,960 → 16,384 | 上述迴圈少 60%，但無法容納規格中最大 31,582-byte 樣本 | 不滿足現有樣本覆蓋要求，不能直接作為目前 profile 的替代 |
| 解壓與文字拆成兩個 proof，再遞迴合併 | 順序執行時元件記憶體不需同時保留；完整容量 inflate 仍須單獨編譯 | 本次 inflate 編譯限制仍存在；需增加私密內容一致性綁定與遞迴驗證成本，不能將兩份獨立 proof 直接視為等價 |

優先可繼續研究保留容量的編譯／約束最佳化，或在較大建置環境完成
ACIR 後量測。以上是迴圈容量比例與架構上的估計，並非完整電路
效能預測；沒有以小 probe 線性外推完整 gate 數，沒有改動 profile
或替代正式完整電路的驗收。

### Round 5 容量、分維度基準與最佳化（2026-10-25）

整合分支 `b35710616411428c93769c0bf8ee7d132eb797c8` 已包含在
工作分支；容量基準為 `f79397c`，位元讀取最佳化為 `9717d17`。
完整容量依第 3.7 節改為 **8,192 compressed／40,960 plain／
6,144 tokens／4 blocks**；沒有進一步縮小容量。

實際環境為 Linux x86_64、AMD EPYC 9V74、**2 vCPU／8 GiB cgroup
RAM**，與 Round 4 的 4 vCPU／32 GiB 不同。工具仍為 nargo
1.0.0-beta.15（noirc `83245db91dcf63420ef4bcbbd85b98f397fee663`）、
bb 2.1.9。各組以獨立程序、新 temporary package 依序執行，沒有 ACIR
快取。`nargo info` 包含完整編譯；成功後另跑 `bb gates`。
預算均為 `--seconds 1800 --address-space-gib 24`；24 GiB 是
RLIMIT_AS 位址空間上限。實體容器先受到 8 GiB 限制，**不能把本次
OOM 寫成 24 GiB 預算下的失敗，也不能據此推定 prove 成本**。

所有組合 N=8,192；B=區塊、T=記號、P=輸出位元組容量：

| B | T | P | 最佳化前結果 | 編譯時間 | 峰值 RSS（KiB） | ACIR opcodes | gates |
|---:|---:|---:|---|---:|---:|---:|---:|
| 4 | 6,144 | 40,960 | cgroup OOM，SIGKILL，無 ACIR | 257.40 s | 8,302,960 | 未取得 | 未取得 |
| 1 | 6,144 | 40,960 | cgroup OOM，SIGKILL，無 ACIR | 205.75 s | 8,307,004 | 未取得 | 未取得 |
| 4 | 512 | 1,024 | 編譯與 gates 完成 | 242.89 s | 3,700,048 | 1,735,520 | 5,840,513 |
| 1 | 6,144 | 1,024 | cgroup OOM，SIGKILL，無 ACIR | 218.20 s | 8,307,964 | 未取得 | 未取得 |
| 1 | 512 | 40,960 | cgroup OOM，SIGKILL，無 ACIR | 202.77 s | 8,307,364 | 未取得 | 未取得 |

第五組的最終 JSON 已在環境恢復後找回；上表取代先前四組的中斷
檢查點。原始紀錄是 `native/circuits/validation/m3b-round5-baseline-*.json`；
`m3b-round5-checkpoint.json` 彙整全部五組。成功組 gate 工具另耗時
15.46 s，ACIR SHA-256 為
`bd0605ff682e47453c31d1c09bec720c3b49dd7c7398dce099b42f32eba1f723`。

單區塊時，6,144-token／1,024-byte 與 512-token／40,960-byte
兩組都耗盡此容器，表示記號解碼與輸出迴圈都需處理，區塊表不是
唯一瓶頸。由失敗紀錄仍不能精確排名兩者總成本，沒有線性外推
完整 gates、prove 或 RSS。

#### 同容量候選比較

每個候選**分別**套用到容量基準，沒有混合變更。下表固定
N=8,192／B=4／T=512／P=1,024；候選另設 6 GiB RSS 保護線，
三組均完成且未觸及保護線。時間是單次觀察值，不是統計信賴區間。

| 實作 | 編譯時間 | 峰值 RSS（KiB） | ACIR opcodes | gates | 決定 |
|---|---:|---:|---:|---:|---|
| 容量基準 | 242.89 s | 3,700,048 | 1,735,520 | 5,840,513 | 比較基準 |
| 必要欄位投影後查表（scalar） | 244.22 s | 3,567,476 | 1,723,726 | 5,817,272 | 不採用；gates 僅少 0.40%，時間未改善 |
| 固定 Huffman 表移至編譯期（fixed） | 246.58 s | 3,460,408 | 1,735,520 | 5,840,513 | 不採用；opcodes／gates 相同 |
| 三 byte 直接位元讀取（bits） | 95.17 s | 2,559,160 | 1,408,180 | 5,265,212 | 採用 |

採用版本 gates 減少 **9.85%**，本次編譯時間少 60.82%、峰值 RSS
少 30.83%。`bits()` 的 width 上限是 16、位移上限是 7，最多讀
23 bits，第四個 byte 不影響遮罩後結果。所有正式呼叫的 limit 是
`(data_len-4)*8`，且 `data_len<=N`、`pos<=limit`，因此
`offset<=N-4`；包含 limit 位置的零寬度讀取，三個索引都在陣列內。
移除冗餘的索引夾限與第四次讀取，保留 width／limit 斷言及陣列
邊界約束，沒有 unconstrained 路徑。新增最大寬度跨三 byte、零寬度
尾界與越界拒絕測試。各候選的 patch、來源 hash 及量測 JSON 均在
`validation/m3b-round5-{scalar,fixed,bits}*`；patch 分別適用於 `f79397c`。

#### 最佳化後完整容量重測

| B | T | P | 結果 | 經過時間 | 峰值 RSS（KiB） | ACIR／gates／proof |
|---:|---:|---:|---|---:|---:|---|
| 4 | 6,144 | 40,960 | 6 GiB RSS guard 主動中止 | 113.70 s | 6,292,780 | 未取得 |

此組仍設 1,800 秒／24 GiB RLIMIT_AS。為避免再次使 8 GiB 執行環境
離線，另以 `--rss-limit-gib 6` 保護工作階段；這是**保護性中止**，
不是 OOM、不是完成編譯所需 RSS，也不是 24 GiB 預算失敗。紀錄為
`validation/m3b-round5-optimized-full.json`。完整容量尚未完成編譯，
完整 prove／verify／proof 大小均未量得，因此尚未滿足桌面 1 分鐘／
3 GiB 的先決條件，沒有開始剩餘 M3b 或自行採用切分方案。

小容量 correctness probe（N=128／P=128／T=32／B=1，合成 dynamic
Huffman）已重新產生兩次 UltraHonk ZK proof 並獨立驗證：234,992
opcodes、571,668 gates；first／warm prove 26.65／22.33 s、峰值
1,745,944／1,744,828 KiB；verify 19.48 ms；proof 16,256 bytes，
public inputs 0 bytes。first 包含 CRS 首次下載；compile 可能使用快取。
方法為 `-s ultra_honk --oracle_hash poseidon2`，沒有 `--disable_zk`。
這是元件正確性測量，不能替代完整容量驗收。完整紀錄與新 hash 見
`validation/m3b-round5-inflate-probe.json`、`VERSIONS`；Round 4
環境不同，兩輪 prove 時間不作直接優化比較。

#### UltraHonk ZK 遞迴 verifier 成本

bb 2.1.9 原生 `gates` 的 `CircuitStats` 以 `UltraCircuitBuilder`
呼叫期待 flavor 的 `_create_program_metadata`，使 `honk_recursion=0`，
遇遞迴 opcode 時拒絕。量測工具保留此失敗，再用**同版本**
`@aztec/bb.js` 的既有 WASM API
`acirGetCircuitSizes(bytecode, false, true)`；沒有修改 bb 原始碼。
兩條路徑都 finalize UltraCircuitBuilder 並讀 finalized gate count。
WASM 固定一個 thread；下列時間／RSS 是 gate 建構成本，非 prove。

| verifier 數 | 每份 application public inputs | gates（實測） | dyadic size | gate 建構時間 | 峰值 RSS（KiB） |
|---:|---:|---:|---:|---:|---:|
| 1 | 32 | 704,869 | 1,048,576 | 3.23 s | 487,044 |
| 2 | 32 | 1,471,929 | 2,097,152 | 5.25 s | 872,660 |

Noir 編譯分別 0.156／0.156 s、60,080／60,376 KiB。使用 proof
type 7（UltraHonk ZK）、508 proof fields、115 VK fields；32 個
應用公開輸入是量測選項，**不是正式邊界 ABI**。程式與結果為
`tools/recursion_profile.py`、`tools/recursion_gates.mjs`、
`validation/m3b-round5-recursion-{one,two}.json`。bb.js 2.1.9 是 MIT
授權的外部開發量測工具，不打包進 App，見 `native/circuits/NOTICE`。

這些 harness 只量 verifier black box，使用 backend 的 dummy
assignments；沒有有效遞迴 proof、可信 VK 綁定或段間狀態檢查。
具體切分提案在 `native/circuits/IMPLEMENTATION.md` 與 PR #21，
仍待 Claude 決定。n 個葉的二元樹有 n-1 個內節點、2(n-1) 次子證明
驗證，這是呼叫數，不能把上表倍乘當作整體實測。Merkle 視窗、
承諾、SHA、lexer、可信 VK 與狀態連接成本都須另測。

Round 5 最終檢查：`nargo test` 36 passed；ACIR regressions 11／11、
`--multiblock` 4／4（合計 5 正向、10 約束拒絕負向）；要求的三個
Gradle tasks 成功，362 tests、0 failures／errors、29 skipped。
兩個 round-trip 測試均執行通過；無 cargo 導致既有 native build
自動略過，relay 時序測試亦 skipped，不能視為該原生路徑驗收。
沒有 Rust 修改，沒有執行 cargo test。


### Round 6 不可變提示與邊際成本（2026-10-25）

本節取代 Round 5 的當前狀態，歷史量測保留。基準整合 commit
`b35710616411428c93769c0bf8ee7d132eb797c8`，開始前已 merge。
環境為 AMD EPYC 9V74、2 vCPU、8 GiB cgroup；nargo beta.15
（noirc `83245db9`）、bb 2.1.9。每筆 fresh `nargo info` 編譯後由
`bb gates` 取 `circuit_size`，以 1,800 秒、24 GiB RLIMIT_AS、
6 GiB RSS guard 逐組執行。數據是實測 gate count；時間是單次觀察，
不代表統計分布。所有 main 只涵蓋 inflate，沒有公開 PDF statement。

#### 分維度實測

階段來源：Round 5=`4414b57`；immutable hints=`b365f47`；
反轉碼／延後 Adler=`15d25c5`；最終 packed header/token=`f96a903`。
後續 fixture 修正沒有改變 inflate 原始碼。單位為 gates，破折號表示
該階段未量測。原始 JSON、容量、時間、RSS、source/ACIR hash 在
`native/circuits/validation/m3b-round6-matrix.json`，重現指令見 circuits README。

| N | B | T | P | Round 5 | immutable hints | 反轉碼／Adler | 最終 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 512 | 1 | 32 | 128 | 574,900 | 540,034 | 409,284 | 307,667 |
| 512 | 2 | 32 | 128 | 1,021,897 | 987,017 | 772,743 | 583,247 |
| 512 | 3 | 32 | 128 | — | — | — | 857,780 |
| 512 | 1 | 256 | 128 | 1,099,486 | 1,057,026 | 614,132 | 399,003 |
| 512 | 1 | 512 | 128 | 1,700,126 | 1,647,874 | 848,244 | 503,387 |
| 512 | 2 | 256 | 128 | 1,549,609 | 1,510,337 | 983,919 | 680,911 |
| 512 | 1 | 32 | 1,024 | 2,726,196 | 621,794 | 465,807 | 360,830 |
| 512 | 1 | 32 | 2,048 | 9,117,862 | 716,116 | 531,286 | 421,587 |
| 512 | 1 | 32 | 8,192 | — | — | — | 790,003 |
| 8,192 | 1 | 32 | 128 | 643,366 | 608,500 | 477,749 | 372,979 |
| 8,192 | 4 | 512 | 2,048 | — | — | — | 1,522,748 |

不可變明文提示在 P=2,048 將 gates 由 9,117,862 降至 716,116，
最終為 421,587。回頭複製不再讀正在寫入的陣列；每個 byte 仍在
常數索引驗證，copy 嚴格引用更早位置，故 overlap 由歸納唯一決定。
詳細健全性、packed window 整數範圍與 Adler 無溢位證明見
`native/circuits/IMPLEMENTATION.md` 的 Round 6 節。

| 維度（其他參數固定） | 差分區間 | 邊際 gates | 目標與判讀 |
|---|---|---:|---|
| T；N512/B1/P128 | 32→256 | 407.750 | <=600，達標 |
| T；N512/B1/P128 | 256→512 | 407.750 | 同斜率 |
| T；N512/B2/P128 | 32→256 | 436.000 | <=600；存在 B×T 交互作用 |
| P；N512/B1/T32 | 128→1,024 | 59.334 | <=60，達標 |
| P；N512/B1/T32 | 1,024→2,048 | 59.333 | 近似線性 |
| P；N512/B1/T32 | 2,048→8,192 | 59.964 | <=60；大區間略增，無平方成長 |
| B；N512/T32/P128 | 1→2 | 275,580 | 未達200,000 |
| B；N512/T32/P128 | 2→3 | 274,533 | 近似線性，有首槽差異 |
| B；N512/T256/P128 | 1→2 | 281,908 | 與 T 交互，不能硬套完全可加模型 |
| N；B1/T32/P128 | 512→8,192 | 8.504/byte | 總增65,312 gates |

最終小基準編譯 35.11 s／598,232 KiB；P8192 組 61.82 s／
4,021,240 KiB；N8192/B4/T512/P2048 組 123.03 s／1,792,504 KiB。
記憶體也受編譯器中間表示影響，不能由 gate 斜率推估 RSS。

區塊目標未達：每槽仍需承擔私密 dynamic 路徑，包括 19/288/32
symbols 的 15 層 canonical prefix 檢查，以及最多 320 個 expanded
length positions。下表在 N512/B1/T32/P128 比較候選；它們由
`15d25c5` 演進，各 patch **獨立**套至該 commit，不能累加套用。

| 候選 | gates | 編譯秒數 | 決定 |
|---|---:|---:|---|
| Field count，逐 symbol 累加15層 canonical code | 443,851 | 131.39 | 不採用 |
| u16 count，同逐層選取 | 447,962 | 129.93 | 不採用 |
| 不可變 prefix，逐層選取 canonical code | 448,288 | 88.13 | 中間比較 |
| 不可變 prefix 與 first code 查表 | 450,589 | 35.74 | 保留查表以降低編譯成本 |
| 加 packed header window | 324,219 | 34.20 | 採用，後續再合併 token window |

原始結果與重現 patch 在 `validation/m3b-round6-candidates.json`
及同前綴 patch。這些是完整候選的 gate 差異，不能歸因為單一函式的
獨立成本。沒有以信任提示、放寬 Huffman 合法性或 unconstrained
路徑換取較低 gates。

#### 完整容量估算（不是實測）

使用較大 P 區間斜率與觀察到的 B×T 交互作用，選擇下式作架構估算：

```
G(N=8192,B,T,P) ≈ 307667 + 65312
  + 274533*(B-1)
  + (407.75 + 28.25*(B-1))*(T-32)
  + 59.9635417*(P-128)
```

B=4/T=6144/P=40960 得 **約6,655,169 inflate gates（665.5萬）**。
這是延伸小容量斜率，不能當上限或完整 ACIR 實測。以沒有參與擬合的
N8192/B4/T512/P2048 檢查，預估1,548,108，實測1,522,748，
高估25,360（1.67%）；表示槽數交互作用與編譯器門檻未被完全描述。
此誤差不能當成完整容量的保證誤差範圍。完整 T6144 與 P40960 的
斜率尚未直接量得，不能從此預測證明時間／RSS。

依本輪要求，把兩個視窗都以已量得的130-block SHA元件估算：
2×542,101=**1,084,202 gates**。詞法掃描尚未實作／量測，僅沿用
規格第3.7節的 **30–60 gates/byte 假設**，40,960 bytes 對應
**1,228,800–2,457,600 gates**。三者相加的完整 PDF 架構預算約
**8,968,171–10,196,971 gates（897–1,020萬）**。此為指定三部分
的估算總和，尚未計入未量測的連接、錨點／claims／predicates 等
額外約束，不能當成正式 `pdf_text_v1_1p` gate count 或完整上限。

Claude 已否決每 byte 驗兩條15層 Merkle路徑的方案。若決定分段，
方向改成每段對整個32 KiB視窗做一次 Poseidon2 sponge承諾
（約1,060 packed fields），段內用不可變私密陣列。此方案仍待
架構決定，本輪沒有實作 lexer、錨點、PUBLIC_SPEC 或分段電路。

#### 完整容量嘗試與 ZK proof

完整 N8192/B4/T6144/P40960 fresh 編譯在 **112.50 s**、
**6,292,032 KiB** RSS 觸及6 GiB guard，狀態為 `rss_guard`。
沒有產生 ACIR，故完整 gates／prove／verify／proof bytes 皆未量得。
這是8 GiB工作階段的保護性中止，並非cgroup OOM，也不是完成所需
RSS或24 GiB預算失敗；cgroup OOM counters與編譯前相同。直接觀察
不能證明桌面1分鐘／3 GiB門檻成立。紀錄：`m3b-round6-full.json`。

另外以 N512/B1/T32/P128 的合成重複字元填滿128-byte輸出，驗證新增
`compile_profile.py --prove` 的受限流程：307,667 gates、159,245
opcodes，fresh compile 36.09 s／557,228 KiB；witness 1.37 s／
273,332 KiB；first／warm prove **11.65／11.39 s**、
**896,820／896,176 KiB**；獨立 verify成功（52.45 ms，含50 ms
polling粒度）；proof **16,256 bytes**、public inputs **0 bytes**。
各階段都受24 GiB AS／1,800 s／6 GiB RSS guard限制，個別計算子程序
RSS。first是此電路的第一個程序，CRS cache已存在，不能稱冷快取。
使用 bb 2.1.9 `ultra_honk --oracle_hash poseidon2`，未傳
`--disable_zk`；ZK設定依前述版本原始碼核對。JSON為
`m3b-round6-proof-small.json`。小容量proof不能替代完整容量驗收。


本輪最終檢查：`nargo test` **69 passed**；標準 ACIR regressions
**41/41**、`--multiblock` **4/4**、`--adler` **3/3**，合計
**7個正向、41個約束拒絕負向**。每個新增提示陣列有對應篡改案例；
包含保持Adler不變的錯誤複製明文，以及有界的prefix/suffix篡改。
不把解析／編譯失敗當負向通過。合成資料產生器與完整結果一併提交。

要求的三個 Gradle tasks 成功，另以 `:test-servers:test --rerun`
強制重新執行測試（Kotlin compile未變，為UP-TO-DATE），1m9s完成：
**362 tests、0 failures/errors、29 skipped**。兩個 signed round-trip
均執行通過；環境無cargo，既有native auto build略過，relay案例
亦skipped，不能視為其原生路徑驗收。本輪沒有Rust變更，未跑cargo
test。完整命令及JUnit摘要見 `validation/m3b-round6-gradle.json`。


最終合成 dynamic correctness probe（N=P128/T32/B1）亦重新產生
兩次ZK proof並由獨立程序verify：**304,435 gates、156,770 opcodes**；
first／warm **11.99／11.91 s**，RSS **877,116／876,796 KiB**；
verify **17.69 ms**，proof **16,256 bytes**、public inputs **0 bytes**。
compile 0.74 s使用既有快取，不與fresh profile編譯時間混比。
JSON為 `m3b-round6-inflate-probe.json`，`VERSIONS`已更新其ACIR/VK
hash，仍只是component測量資產，並非正式M3b資產釘選。

## Round 7：以 Poseidon2 承諾串接 inflate 段

基準整合分支 `b2c412c`，已先 merge。這一輪實作 `pdf_inflate_seg_v1`、
共用加鹽承諾、SHA 內容視窗 XOR 後的 C_z，以及 Python 參考切段器；
沒有做遞迴、詞法掃描、錨點、欄位承諾或 PUBLIC_SPEC。
健全性論證與需要 Claude 決定的編碼細節見
`native/circuits/IMPLEMENTATION.md` 的 Round 7 節。

### 環境與量測方法

2026-10-26，Intel Xeon Platinum 8370C 2.80 GHz、Linux x86_64，
**2 vCPU／8 GiB cgroup**。nargo 1.0.0-beta.15、noirc
`83245db91dcf63420ef4bcbbd85b98f397fee663`、bb 2.1.9，bb 自動選 3 threads。
不是 Round 6 的 AMD 主機，也不是實際手機測試。

以 `tools/compile_profile.py --segment` 為每個容量建立新包，執行
`nargo info`、`bb gates`、pedantic witness、ZK first／warm prove 及獨立
`bb verify`。每個 child 限 1,800 秒、24 GiB RLIMIT_AS、5 GiB RSS guard；
實體 cgroup 仍是 8 GiB。證明命令均使用
`-s ultra_honk --oracle_hash poseidon2`，不傳 `--disable_zk`。
見證是填滿本段的合成重複字元串流，第一／最後段、歷史視窗全零；
不是實際文件，也不是整個 PDF 陳述。

首次記錄與必要 Gradle／回歸共用 CPU；first 包含 CRS 下載或擴充。
因此另在背景工作結束、CRS 已快取後，逐一量兩組獨立 warm。
兩份 warm 的 VK 與原量測完全相同；手機使用相同 bytecode 的合成
第一／非最後段見證，電腦使用原第一／最後段見證。這些時間包含
建 proving key、CLI 啟動；verify 以 1 ms 監測粒度重測，並非純曲線核心時間。
原始 profiler 的 50 ms verify 監測結果也保留於 JSON，未混稱精密計時。

### 結果與選定容量

共同參數 `MAX_COMPRESSED=8192`、`SEG_BLOCK_STARTS=1`，
`W=ceil(32768/SEG_PLAIN)`。token 預算依 P/11 的約 1.5 倍取整。

| 用途 | SEG_PLAIN / SEG_TOKENS / W | gates（dyadic） | compile 秒／峰值 GiB | prove first／warm 秒（共用 CPU） | prove 峰值 GiB（所有量測最大） |
|---|---|---:|---:|---:|---:|
| 等級 A 手機 | 2048 / 288 / 16 | 974,643（2^20） | 427.41／1.78 | 140.80／194.10 | 1.77 |
| 電腦 | 4096 / 576 / 8 | 1,275,375（2^21） | 647.92／2.04 | 115.11／96.66 | 3.32 |

| 用途 | 獨立 warm 秒 | warm 峰值 GiB | 獨立 verify ms | proof bytes | public input bytes |
|---|---:|---:|---:|---:|---:|
| 等級 A 手機 | 44.18 | 1.77 | 41.39 | 16,256 | 800 |
| 電腦 | 65.51 | 3.29 | 65.39 | 16,256 | 544 |

手機組符合每段 dyadic ≤2^20；電腦組符合 ≤2^21。4096 能把樣本段數減半，
且已在此環境完整編譯／證明，故選為本輪電腦參數。編譯時間是開發端
成本，不能當成手機使用者每次產生證明的時間。所有 prove／verify 均成功。

另外嘗試 `8192 / 1120 / W=4 / B=1 / N=8192`，在 **314.08 秒**觸發
5 GiB RSS guard，觀察到 **5,272,396 KiB（5.03 GiB）**；工具主動 kill，
`memory.events` 的 oom／oom_kill 都是 0。未產生 ACIR，沒有 gates、
prove 或 verify 數據。這不是 OOM、24 GiB 位址空間失敗，也不能說它
超過 2^21；觀察到的 RSS 只是中止前峰值，不是完整編譯所需記憶體。
因此未選用此候選。本輪的兩組已選容量均有完整數據，不以外推取代實測。

重現選定容量：

```sh
python3 -I tools/compile_profile.py --segment --plain 2048 --tokens 288 --blocks 1 \
  --compressed 8192 --nargo /path/to/nargo --bb /path/to/bb --prove \
  --bb-js /path/to/bb.js/dest/node/index.js --crs /path/to/crs \
  --rss-limit-gib 5 --output target/segment-2048.json
# 電腦組改為 --plain 4096 --tokens 576。
```

數據與精確量測 main 快照在
`native/circuits/validation/m3b-round7-segment-{2048,4096}.*`，
獨立 warm 在 `m3b-round7-isolated-{2048,4096}.json`；8192 保護中止另存
`m3b-round7-segment-8192-guard.*`。JSON 含實際編譯來源雜湊、ACIR／VK
SHA-256、逐程序 RSS、退出狀態及 cgroup。測試來源更新若觸發 metadata
重編譯，另保留 pre-witness ACIR 雜湊，並核對量測／證明 bytecode 完全相同。
ACIR 路徑與 debug metadata 會影響檔案雜湊；這些是量測快照，非正式資產凍結。

### 最大樣本的估算（不是實測）

樣本聚合資料：31,582 bytes 明文、2,829 tokens、1 個動態區塊。
固定大小切段需要手機 **16 段**、電腦 **8 段**。下表僅將本次獨立 warm
乘上段數，假設各段 token 密度在所選預算內，且後續段成本與合成見證近似：

| 容量 | 估計段數 | 估計串行 inflate prove | proof＋public inputs |
|---|---:|---:|---:|
| 2048 / 288 | 16 | 16×44.184 = 706.95 秒（11.8 分鐘） | 272,896 bytes |
| 4096 / 576 | 8 | 8×65.509 = 524.07 秒（8.7 分鐘） | 134,400 bytes |

沒有實際文件或逐段 token 分布，總 token 數不能保證每個固定明文段都能裝入
288／576 個 token；M3c 必須預檢局部密度，不足時明確拒絕該 profile。
單一動態區塊的 block-start 預算則足夠。估算不含見證產生、SHA、未實作的
詞法段、IO 或實際手機差異，不能宣稱已達舊的手機 2 分鐘／電腦 1 分鐘
整體門檻。沒有用 Claude 的 4 vCPU 數字混算本機總時間。

### 約束測試與交接

- `nargo test`：**76 passed**，含既有 Brillig 語意測試，不稱為 76 份 ACIR proof。
  新增標準 Poseidon2 已知答案、31-byte 大端打包、SHA XOR／C_z、HDIST 30 control
  與 31／32 拒絕；HDIST 負向同步修改合法 code-length repeat 與 lookahead。
- `python3 -I tools/regressions.py`：**44/44**；`--multiblock`：**4/4**。
- `--segments --bb-js ...`：**49 個 constrained ACIR 案例**（33 接受、16 拒絕），
  另有 1 個電路外串接換序拒絕，共 50 個 runner 結果。包含 17 段的遠距離
  32,768-byte copy（可辨識前綴）、跨段 copy、fixed／dynamic 多段、混合三種區塊、
  stored 跨段與空串流。負向涵蓋歷史明文、索引、表／表承諾、pending 長度／距離、
  首段 zlib header、末段 Adler、C_z、明文、S_out／C_p、首尾旗標與網域。
  Adler 攻擊同步更新未消耗 lookahead，確實測 checksum 約束。
- 合計 **97 個 ACIR 案例：40 接受、57 約束拒絕**，負向只接受
  `Cannot satisfy constraint`；解析／編譯錯誤不計入通過。
- 兩組各 first、warm、獨立 warm，共 **6 份 UltraHonk ZK proof** 成功；
  每組的兩份原始 proof 共用相同見證，warm 重測使用上述合成範圍。
  各組 warm proof 都由獨立 CLI verify 通過，精密重測 verify 亦通過。
- 必要 Gradle tasks 全部成功，**368 tests、0 failures/errors、30 skipped**。
  環境無 cargo，既有 native auto build 與相關案例略過；不宣稱 Rust／原生驗收通過。
- `tools/segment_reference.py` 以 `python3 -I` 執行，產生每段 Prover.toml，
  重開所有承諾、核對相鄰狀態與歷史，並以 Python zlib 核對完整結果與最終狀態。
  合成 salt 固定 42，正式 M3c 必須每份證據重新產生至少 248-bit 隨機 salt。
- 規格未改；stored_end、stored 最後區塊沒有 EOB、固定段與區塊切點衝突、
  以及精確 field／空承諾編碼需由 Claude 決定。B=1 用於單區塊樣本；
  混合區塊回歸使用 B=3，stored literal-rich 回歸使用 P=64/T=96。
- 新增第三方元件：無。沿用既有 MIT 的 bb.js 2.1.9 產生獨立承諾向量與見證，
  `native/circuits/NOTICE` 已補述用途。不提交真實文件、私密見證、CRS 或大型 proof 資產。


## WP3a M3b Round 8: first segment and streaming text (2026-10-26)

Round 8 merged integration commit `cfbfde0` before implementation. The first
inflate variant is complete and within the requested bounds. Streaming lex and
claim circuits and synthetic chain tools are implemented, but the production
text profile is **not selected**: full-size compilation did not complete within
the budgets below, and the specified raw TJ record encoding has a date-decoding
soundness issue requiring Claude's decision. This remains a draft.

### Environment and first-segment measurements

Pinned nargo 1.0.0-beta.15 (noirc `83245db91dcf63420ef4bcbbd85b98f397fee663`),
Barretenberg / bb.js 2.1.9, UltraHonk ZK with Poseidon2. Cloud AMD EPYC 9V74,
cgroup 2 vCPU and 8 GiB; these are **cloud measurements of phone/desktop
parameter sets, not measurements on a phone**. Some compilation and regression
work overlapped, so wall time includes shared CPU contention. First and warm
mean two fresh CLI prove processes with the same synthetic witness and cached
CRS; they are not a cold CRS download or an in-process mobile warmup.

All rows use `SEG_BLOCK_STARTS=1`, `MAX_COMPRESSED=8192`. The SHA segment must
pin the same compressed capacity. The W=0 specialization reuses the common
inflate decoder and projects its single validated Huffman table before token
lookup; no second decoder or unconstrained acceptance path was added.

| Profile | SEG_PLAIN / tokens / W | gates | compile seconds / peak GiB | prove first / warm seconds | verify ms | proof / public input bytes |
|---|---|---:|---:|---:|---:|---:|
| Phone first | 2048 / 1024 / 0 | 1,033,678 (2^20) | 107.43 / 2.571 | 45.74 / 40.19 | 18.61 | 16,256 / 288 |
| Desktop first | 4096 / 1536 / 0 | 1,415,190 (2^21) | 232.25 / 4.685 | 63.57 / 49.80 | 21.16 | 16,256 / 288 |
| Phone general | 2048 / 352 / 16 | 1,009,891 (2^20) | 120.08 / 1.854 | 43.02 / 45.44 | 20.46 | 16,256 / 800 |
| Desktop general | 4096 / 576 / 8 | 1,275,071 (2^21) | 121.60 / 2.492 | 100.98 / 99.70 | 23.74 | 16,256 / 544 |

Prove first/warm peak RSS respectively: phone first 1.824/1.824 GiB, desktop
first 3.383/3.357 GiB, phone general 1.776/1.775 GiB, desktop general 3.318/3.318 GiB. Each warm proof verified
with the independent CLI. Choose **1024/352** first/general tokens for phone
and **1536/576** for desktop. The general desktop row was remeasured on
this environment; its two proofs overlapped compiler work, so its wall time
is not an isolated throughput comparison with the other rows. The phone first profile has only 14,898 gates of
headroom, so any subsequent change needs fresh measurement. The capacities
cover Claude's aggregate sample counts; M3c still must reject local density
or block-start overflow before proving.

Exact main snapshots, source/ACIR/VK hashes, process results and peak RSS are
`native/circuits/validation/m3b-round8-{seg0-phone-projected,seg0-desktop,general-phone,general-desktop}.{json,main.nr}`.
Large ACIR, witnesses, CRS and proof files are excluded from version control.

### Lex and claim capacity attempts

Lex attempts use `SEG_PLAIN=2048`, `MAX_OPS=512`, `MAX_ANCHORS=16`,
`MAX_CLAIMS=12`, `MAX_CLAIM_SRC=384`, `MAX_ANCHOR_SRC=64`, with no operator
table hints. The compiler guard is 5 GiB RSS and 1,800 seconds per process.

| Circuit | K / slots | compile seconds | observed peak GiB | result | gates / prove first / warm / verify / proof bytes |
|---|---:|---:|---:|---|---|
| Lex | 1 | 1,800.20 | 4.924 | timeout | unavailable |
| Lex | 2 | 838.15 | 5.006 | RSS guard | unavailable |
| Lex | 4 | 155.38 | 5.000 | RSS guard | unavailable |
| Claim (384 source bytes) | 12 | 1,800.09 | 1.322 | timeout | unavailable |
| Lex, bounded codegen | 1 | 720.13 | 3.983 | timeout | unavailable |
| Claim, bounded codegen (384 source bytes) | slots 0..2 of 12 | 1,800.04 | 1.323 | timeout | unavailable |

The two bounded-codegen rows are additional candidates, not selected profiles.
The lex retry used a 720-second budget; the 3-slot claim used 1,800 seconds.
All compiler checks remained enabled for these reported profiles. Splitting
the SHA outputs alone did not produce a completed claim compilation within
this budget, so no four-proof claim split is approved. The claim main has no
SEG_PLAIN parameter: the old harness recorded 40960 as an unused fixture
setting for the 3-slot attempt; compilation stopped before fixture generation.
The current text harness defaults that setting to 2048.

An RSS guard is a deliberate compiler termination, not an OOM measurement;
its observed peak is not the memory needed for successful compilation. A
timeout is not evidence that a circuit exceeds 2^20 or 2^21 gates. No proof or
verification timing is reported for an uncompiled circuit. Therefore **the
largest qualifying K is undetermined**, for both phone and desktop. Shipping
K=1 as a selected profile would be unsupported by these results.

A smaller diagnostic with P=64, K=1 and all the same text capacities compiles
in 13.10 seconds / 0.636 GiB, at 221,093 gates. It is not a replacement for the
required P=2048 profile. The user-authorized isolated Field-counter candidate
increased an earlier P=64 baseline from 332,871 to 379,136 gates; it was not
adopted. Repository counters and lengths remain u32 with checked updates.
The parser emits deterministic record events; moving aggregation outside mode
branches, packing names, and carrying one active field reduced cost without
adding token-position advice. Further architecture changes require review;
this round does not silently substitute an operator hint table.

Results and source snapshots are `m3b-round8-lex-k{1,2,4}-final.*`,
`m3b-round8-claim-12.*`, `m3b-round8-claim-split3.*`,
`m3b-round8-lex-k1-bounded.*`, and `m3b-round8-lex-single-p64.*` in validation.

### Maximum-stream estimates, with missing terms explicit

For 31,582 plaintext bytes and 232 text operators, fixed inflate segmentation
requires 16 phone or 8 desktop segments. **Estimates only**:

* Phone inflate: 40.1914 + 15 x 45.4436 = **721.84 seconds** (12.03 minutes).
* Desktop inflate: 49.7963 + 7 x 99.7045 = **747.73 seconds** (12.46 minutes).
  This uses the same environment, but its general proofs overlapped compilation;
  it is a shared-load planning estimate, not isolated desktop throughput.
* If K were 1/2/4, lex would require 16/8/4 segments for phone P=2048, or
  8/4/2 for desktop P=4096. Desktop P=4096 lex is not measured here.
* With all 12 claims in one claim proof, total inflate+lex+claim segment
  counts would be 33/25/21 (phone) or 17/13/11 (desktop). With s selected
  claim proofs, replace the final 1 by s. None of these K choices is approved.

Total prove time is `inflate estimate + ceil(inflate_segments/K) * lex_warm
+ sum(claim_warm)`. The lex and claim terms are **unavailable**, so no numeric
full-chain prove estimate can honestly be given yet. These formulas exclude
SHA, witness production, IO, scheduler overhead and actual device differences.

### Design decisions still needed

The authenticated raw record concatenates TJ strings without their individual
boundaries. `[(2020-01-)(\7)(1)] TJ` decodes per string to a separator followed
by day 1, while its raw concatenation ends in `\71` and decodes to day 9.
`[<3><1>] TJ` similarly changes odd-nibble padding. The current date circuit
proves the concatenated-record date, which cannot establish arbitrary PDF
per-string date semantics. Claude must decide on authenticated string lengths
or sufficient boundary restrictions before this draft can be considered sound
for PDF date predicates. The dedicated reproduction also executes two lexical segments and one claim
with pedantic solving: all accept the concatenated-record predicate while the
PDF predicate is false. These three executions are separate from the passing
regression totals below. See IMPLEMENTATION.md for the full argument.

The exact proposed A packing also binds enabled slot endpoints after the
anchor content; ordinal/total outputs are excluded. Numeric date-format and
predicate codes are documented proposals awaiting design confirmation. No
`p4-circuits.md` or PUBLIC_SPEC edits were made. No new third-party component
was added; existing bb.js use remains covered by NOTICE.

### Round 8 validation

* `nargo test`: **83 passed**; `nargo check` passed. Unit tests are not counted
  as independent UltraHonk proofs.
* Standard regressions: **44/44** (5 accept, 39 constraint reject).
* `--multiblock`: **4/4** (2 accept, 2 constraint reject).
* `--segments`: **54/54** (36 accept, 17 constraint reject, one reference-only
  join rejection). Includes first-to-general chaining, one-segment first/final,
  a first segment over the general token capacity, and rejection of general
  circuit index zero.
* `--lex-claims`: **72/72** (55 accept, 16 constraint reject, one reference-only
  join rejection). Includes both layouts, K=2 padded final group, names,
  strings and operators crossing boundaries, a field accumulating multiple
  date records across segments, repeated anchors, WinAnsi escapes, Identity-H
  hex/literal octal, and DATE_LE/DATE_GE controls. All requested attack classes
  are exercised through `nargo execute`; parse/compile errors never pass.
* Total: **172 ACIR executions** (98 accept, 74 constraint reject), plus two
  independent reference join rejections. The known raw-string boundary issue
  is reproduced separately and is not counted as a successful rejection.
* `./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test`:
  **BUILD SUCCESSFUL**, 370 tests, zero failures/errors, 31 skipped. The
  environment has no cargo; native-dependent cases are not claimed to pass.

Case-level results and circuit source hashes are preserved in
`native/circuits/validation/m3b-round8-tests.json`. The two styles also pass
standalone `python3 -I tools/lex_reference.py`, generating ignored synthetic
Prover.toml files and validating the complete inflate-to-lex-to-claim chain.

## WP3a M3b Round 9: v2 records, two-phase lexing and separate predicates

This section supersedes Round 8's unresolved string-boundary issue and text
capacity results. Integration design commit `55cdcd8` was merged first. Circuit
sources are at `3006243`; validation JSONs retain exact per-file SHA-256 hashes,
generated mains, ACIR/VK hashes and process exit status. Inflate code and all
first/general inflate parameters remain unchanged.

Measurements use pinned Noir 1.0.0-beta.15 (`83245db9`) and bb/bb.js 2.1.9,
UltraHonk ZK with Poseidon2, on the same cloud 2-vCPU / 8-GiB environment.
`--bounded-codegen` is used; no constraint or underconstrained safety checks
are skipped. `#[no_predicates]` delays local constrained-function inlining;
all such calls are unconditional and carry explicit active guards. See
IMPLEMENTATION.md for the call discipline and pinned upstream references.
Most measurements overlap regression executions or other profiling work;
first/warm differences include scheduler noise. K=4 is run alone with
RAYON_NUM_THREADS=1 and a 7.6-GiB RSS guard. Its initial default-worker
compile hit the 7-GiB guard after 425.13 s (7.042 GiB peak); that attempt
produced no gates or proofs and is preserved among development diagnostics.
These are not measurements on physical phones or desktop devices.

All text profiles use 16 anchors, 12 claims, 384 bytes per claim and 96 bytes
per full v2 anchor record. Predicate capacity is two with four digit fonts.
The claim fixture enables all 12 slots. The predicate fixture enables one
predicate; two-active-predicate correctness is separately constraint-tested.
Times below are seconds; RSS is GiB. First/warm are separate prover processes
sharing a local CRS cache. K=4 first prove includes an automatic 256-MiB CRS
download to extend that cache; its warm prove reuses the downloaded data. The
other profiles are not cold-network setup benchmarks. Proof bytes exclude
public inputs and the verification key.

| Profile | Gates | Compile s / RSS | Prove first / warm s | Prove first / warm RSS | Verify s / RSS | Proof bytes |
|---|---:|---:|---:|---:|---:|---:|
| Lex P=64 K=1 O=64 | 137,498 | 19.085 / 0.472 | 26.776 / 25.891 | 0.426 / 0.425 | 0.036 / 0.014 | 16256 |
| Lex P=128 K=1 O=64 | 164,427 | 10.735 / 0.572 | 15.655 / 17.237 | 0.439 / 0.439 | 0.039 / 0.014 | 16256 |
| Lex P=256 K=1 O=64 | 218,189 | 16.171 / 0.596 | 21.777 / 23.496 | 0.446 / 0.446 | 0.048 / 0.014 | 16256 |
| Lex P=2048 K=1 O=64 | 972,366 | 143.469 / 1.744 | 105.881 / 106.002 | 1.719 / 1.719 | 0.277 / 0.021 | 16256 |
| Lex P=2048 K=2 O=128 | 1,874,016 | 208.866 / 3.403 | 151.007 / 153.105 | 3.432 / 3.432 | 0.045 / 0.034 | 16256 |
| Lex P=2048 K=4 O=256 | 3,677,278 | 414.670 / 7.513 | 200.288 / 169.179 | 6.839 / 6.838 | 0.047 / 0.070 | 16256 |
| Lex P=4096 K=1 O=128 | 1,873,834 | 302.318 / 3.404 | 169.358 / 165.337 | 3.467 / 3.468 | 0.052 / 0.033 | 16256 |
| Claim start=0 count=12 | 429,943 | 9.577 / 0.436 | 48.870 / 45.953 | 0.865 / 0.866 | 0.054 / 0.014 | 16256 |
| Predicate capacity=2 | 702,339 | 78.560 / 1.657 | 61.604 / 90.267 | 1.676 / 1.676 | 0.151 / 0.040 | 16256 |

Every completed profile has two successful ZK proofs and an independent bb
verification. Witness generation is measured separately in each JSON; it is
not included in the prove columns. Source snapshots and full measurements are
`native/circuits/validation/m3b-round9-final-*`. Intermediate diagnostics are
collected in `m3b-round9-development-profiles.json`; interrupted or deliberately
canceled old-code runs are not treated as compiler capacity failures.

### Cost and selected parameters

At fixed O=64, final P=64/128/256 counts are 137,498 / 164,427 / 218,189.
The two interval slopes are 420.77 and 420.02 gates/byte; the endpoint fit is
420.27 gates/byte with approximately 110,601 fixed gates. Claude's previous
221,093 / 373,124 / 677,070 counts imply approximately 2,375 gates/byte.
The new scan is about 82.3% cheaper per byte, but misses the 200-300 target.
Remaining cost is mode and Word-rule transitions, checked raw length,
escape/depth bookkeeping, name/word values, string/record fingerprints and
constant-index emitted arrays. Anchor counts, ordinals and claim accumulation
now run only in operator slots. A boolean-valued 256-entry classification table
avoids the u8 bitwise-mask overhead. Bounded Field counters preserve the
committed u32 ABI through exact conversion checks and inductive bounds.

For the requested common SEG_PLAIN=2048 comparison, choose K=1 / O=64 for
phone and K=2 / O=128 for desktop. K=1 has 972,366 gates (76,210 below 2^20);
K=2 has 1,874,016 (223,136 below 2^21). The K=4 result above determines its
exclusion. Operator capacity is 64 per 2048-byte covered range, exceeding the
reported sample maxima of 38/2048 and 75/4096 without accepting overflow.

The selected desktop inflate profile produces 4096-byte commitments. Since
C_p commits to the padded capacity, it cannot directly feed the P=2048 lex
variant. The compatible measured desktop lex variant is P=4096, K=1, O=128:
it covers the same 4096 bytes per proof and joins the existing desktop inflate
chain. Keep this distinction in M3c and profile identifiers; do not mix these
verification keys or reinterpret C_p.

With operator capacity growing by 64 slots per 2048 bytes, the measured full
K=1/2/4 slope is about 440 gates/covered byte, including aggregation growth.

Both device tiers select all 12 slots in one claim segment, start=0/count=12:
this is the maximum allowed by MAX_CLAIMS and fits below 2^20. Generic static
partitions remain supported and tested with two distinct ranges. Every claim
part recomputes the complete Pi/r/C_g and only hashes its own slots. The
separate two-predicate circuit also fits below 2^20; omit it when no predicate
is requested.

### Maximum-stream planning estimate

For the supplied 31,582 plaintext bytes / 232 operators, using the measured
per-window sample maxima and up to 12 slots / two predicates:

| Tier | Inflate | Lex | Claim | Pred | Total proofs | Estimated warm prove time |
|---|---:|---:|---:|---:|---:|---:|
| Phone: P=2048, K=1 | 16 | 16 | 1 | 1 | 34 | 2554.10 s (42.57 min) |
| Desktop: P=4096, K=1 | 8 | 8 | 1 | 1 | 18 | 2206.64 s (36.78 min) |

These are **estimates**, not full real-document proofs or device benchmarks.
Phone = 40.1914 + 15 x 45.4436 + 16 x 106.0024 + 45.9525 + 90.2668.
Desktop = 49.7963 + 7 x 99.7045 + 8 x 165.3371 + 45.9525 + 90.2668.
The inflate terms are the unchanged Round 8 first/general warm measurements;
the desktop general run had shared compilation load (Round 7's separate run
was about 66 s). This is a shared-load planning estimate. It excludes witness
production, circuit compilation and additional preparation/orchestration time. Without predicates subtract
one proof and 90.2668 s. The alternate desktop P=2048/K=2 chain would need
16 inflate + 8 lex + 1 claim + 1 predicate = 26 proofs.

### v2 soundness and design clarification

Full v2 anchor records and field records include every string's u16 length.
Per-string octal, continuation, hexadecimal whitespace/odd nibble and Identity-H
pair state reset at the authenticated boundary. The two reported boundary
examples are covered by accepting and constraint-rejecting controls. A record's
formal polynomial and length encode those boundaries uniquely; evaluating at
one r is probabilistic, not injective. The soundness statement includes the
specified C_z/Pi/A-before-r ordering and random-oracle grinding attempts.

Claude clarification: Pi is private in claim/pred and committed inside lexical
Lambda. The specified public interface has no common public Pi equality.
Matching candidate text is bound through C_g and transcript-dependent
fingerprints; literal equality of every Pi opening (including irrelevant
anchor indices) is not independently checked by the external verifier. If
literal equality is intended, the design needs public Pi or an equivalent
explicit link. The implementation follows the current interface and does not
silently change the specification. No new third-party component was added.

### Validation

* standard: **44/44**, 5 accepts, 39 constraint rejections, 0 reference-only rejections.
* multiblock: **4/4**, 2 accepts, 2 constraint rejections, 0 reference-only rejections.
* segments: **54/54**, 36 accepts, 17 constraint rejections, 1 reference-only rejections.
* lex: **115/115**, 85 accepts, 28 constraint rejections, 2 reference-only rejections.
* `nargo test`: **85 passed** on the final circuit source.
* `./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test`:
  **BUILD SUCCESSFUL**, 370 tests, zero failures/errors, 31 skipped. The existing
  native build policy skipped Rust because cargo is unavailable; no native
  execution coverage is claimed.

Constraint regressions use pedantic ACIR solving and require the explicit
constraint-failure diagnostic; parse/compile errors never count as rejections.
They retain Round 8 cases and add omitted/false/duplicate/decreasing positions,
nonzero unused positions, more than 255 strings, odd Identity-H strings, public
slot-range mismatches, predicate C_g mismatch, multi-string anchor matching,
both date boundaries and two active predicates. Off-circuit chain checks also
require complete disjoint claim coverage and matching commitments, public
parameters and beta. Reference-only failures are listed separately.

Only native/circuits and this benchmark document were edited after the initial
integration merge. PUBLIC_SPEC, Rust witnesses and Kotlin verification remain
outside this round; PR #21 remains draft.

## Round 10: SHA segments, signed fixture chains and isolated profiles (2026-10-29)

本輪先合併整合分支 `9810ab7`，完成 SHA 內容／opaque 段、兩項 Round 9
修正，以及 `PUBLIC_SPEC.md` 草稿。兩個 SHA 段重用 `sha256_window`；
head/tail 與金鑰流以 pack31 公開。內容段在 XOR 後輸出與 inflate 相同
容量／長度編碼的 C_z。沒有修改 inflate 或最佳化詞法掃描。

### 簽章合成文件的完整約束串接

`python3 -I tools/pdf_fixture_chain.py --nargo /path/to/nargo`（在
`native/circuits`）只使用標準函式庫與指定的五份 M3d 合成 PDF。文件與
`tools/zkpdf-testdocs/` 均未修改。工具依簽章涵蓋版本解析 xref／xref
stream、壓縮物件、頁面、內容與 QR 串流；自己的 SHA-256 compression
與 hashlib／CMS messageDigest 相符；RC4 V2/R3 以空密碼推導 key 並驗證
U。遮蔽後再次解析所得的視窗與字型資源相同。

| 文件 | SHA | inflate | 詞法 | 欄位 | 述詞 | 結果 |
|---|---:|---:|---:|---:|---:|---|
| student.pdf | 內容 1、opaque 1 | 1 | 1 | 1 | 1 | 全段 nargo execute 接受；姓名揭露與生日述詞；WinAnsi 數字寬度 1 |
| travel-rc4.pdf | 內容 1 | 1 | 1 | 1 | 1 | 全段接受；RC4、姓名揭露與生日述詞；Identity-H 數字寬度 2 |
| student-inline-image.pdf | — | — | 1 | — | — | 真實合成內容在 BI 約束位置拒絕 |
| student-actual-text.pdf | — | — | 1 | — | — | 真實合成內容在禁止字典字串的約束位置拒絕 |
| student-oversized.pdf | — | — | — | — | — | 產生見證前拒絕：40966 > MAX_PLAIN 40960 |

兩份正向文件各 6／5 個受約束執行；兩份詞法負向額外要求失敗來源位置
對應 Word 規則，避免將錯誤輸出承諾或編譯失敗當成語法拒絕。兩份正向
文件各有 6 個電路外負向控制：更改 C_z、C_p、beta，省略 lexical 或
SHA-content，以及竄改 H_e。公開串接檢查不讀 Pi／S／Lambda 開啟資料；
另一層參考檢查才重算私密開啟與揭露欄位的 SHA-256 承諾。

這些文件不足一個手機明文段；一般 inflate 段、跨段狀態與 32 KiB 歷史
由分段回歸另外驗證。工具是 M3c 的參考見證產生器，不是 Rust 實作，
也不把 nargo 執行稱為 UltraHonk proof 或完整的 CMS 信任驗證。CMS
簽章／信任維持既有 Kotlin 測試與查驗政策。現有 PdfZkSupport 對這兩份
文件的內容、RC4、字型與數字結果沒有發現不同；但 PdfTextExtractor.runs
先串接 raw，再以解碼等價性檢查拒絕會改變結果的跨字串八進位／奇數
hex 案例；v2 則保留各字串邊界，這項介面差異在 PR 交由 Claude 處理。

### 量測方法與資產界線

固定 Noir 1.0.0-beta.15（noirc `83245db91dcf63420ef4bcbbd85b98f397fee663`）、
bb 2.1.9、UltraHonk ZK、Poseidon2；不傳 `--disable_zk`。同一 2-vCPU／
8-GiB cgroup，`HARDWARE_CONCURRENCY=2`、`RAYON_NUM_THREADS=2`。
完成全部其他編譯、回歸與 Gradle 後，以 `tools/compile_profile.py` 依序
執行十個不同的正式候選 package。SHA、claim、pred 是兩種等級共用的
四個電路，不重複計為不同資產。每組重新編譯，依序執行 witness、first
prove、warm prove、獨立 verify；量測期間不跑其他編譯或回歸。
文字三種電路沿用第九輪的 `--bounded-codegen`，compile 與 witness 的
旗標一致；SHA／inflate 為預設 codegen。電腦詞法編譯另設
`RAYON_NUM_THREADS=1`，其 prover 仍為兩執行緒。

`tools/serial_profiles.py` 重現完整順序，在每組開始前拒絕仍存在的
nargo／bb／Java 程序。24 GiB 為 RLIMIT_AS，另設 6 GiB RSS guard；
實體環境仍是 8 GiB。first/warm 是兩個獨立 prover 程序，使用同一個
CRS cache，不代表手機冷開機／熱開機。first 若下載 CRS 會包含下載
時間；每份 JSON 記錄 cache 前後大小。這是主機上的單次觀察值，不是
實機手機／桌機分布。Proof bytes 不包含公開輸入、VK 或 PDF。

```sh
cd native/circuits
python3 -I tools/serial_profiles.py --nargo /path/to/nargo --bb /path/to/bb \
  --crs /path/to/crs --output target/round10-profiles
```

或對其中一組直接執行：

```sh
HARDWARE_CONCURRENCY=2 RAYON_NUM_THREADS=2 python3 -I tools/compile_profile.py \
  --formal-tier phone --formal-kind sha_content --nargo /path/to/nargo \
  --bb /path/to/bb --prove --crs /path/to/crs --seconds 1800 \
  --address-space-gib 24 --rss-limit-gib 6 --output target/phone-sha-content.json
```

`PUBLIC_SPEC.md` 明列實際公開輸入：SHA content 294、opaque 27、inflate
first 9、一般段手機 25／電腦 17、lex 1646、claim 2058、pred 1798 Fields。
既有 text 三種電路的 bytes 逐 byte 佔一個 Field，與第 1.1.3 節的一律
pack31 文字需由 Claude 在凍結前統一；新 SHA 段遵守 pack31。`VERSIONS`
的候選資產指紋不等於 Claude 已審查或 Kotlin 已加入釘選清單。


### 必要檢查結果

`nargo test`：88 passed。`python3 -I tools/regressions.py` 各模式如下；
約束拒絕必須來自實際 ACIR 執行，解析、編譯或見證分解錯誤不算通過。

| 模式 | 接受 | 約束拒絕 | 電路外拒絕 | 合計 |
|---|---:|---:|---:|---:|
| 標準 inflate | 5 | 39 | 0 | 44 |
| --multiblock | 2 | 2 | 0 | 4 |
| --segments | 36 | 17 | 1 | 54 |
| --lex-claims（含欄位與述詞） | 85 | 32 | 2 | 119 |
| --sha | 9 | 31 | 0 | 40 |
| 合計 | 137 | 121 | 3 | 261 |

SHA 案例包含 head/tail、H_e、C_z、金鑰、私密長度與區塊數竄改，
非標準 pack31 高位及 Field 模數減一；正向控制包含 head=0/31/32/63、
滿容量、單位元組內容及未加密內容。31-byte 分組以兩個 128-bit limb
解碼，約束高 byte 為零；所有 Field 輸入都能產生分解，超寬值在約束
拒絕。內容抽取只讀已完成的 128-byte 視窗，不以私密索引讀寫同一陣列。

五份 PDF 串接結果如上表，另外驗證 12 個公開串接竄改控制。
`./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test`
為 BUILD SUCCESSFUL；370 tests、0 failures/errors、31 skipped。未變更 Rust
或 Kotlin；native 仍依既有 auto policy。完整摘要與來源指紋在
`native/circuits/validation/m3b-round10-tests.json`。

### 最終獨立量測數據

| Circuit / tier | Gates | Compile s / RSS GiB | Prove first / warm s | Prove first / warm RSS GiB | Verify s / RSS GiB | Proof bytes |
|---|---:|---:|---:|---:|---:|---:|
| sha_content / shared | 996,617 | 14.479 / 0.989 | 39.314 / 38.247 | 1.817 / 1.816 | 0.033 / 0.013 | 16256 |
| sha_opaque / shared | 571,201 | 2.381 / 0.313 | 30.146 / 36.986 | 1.624 / 1.623 | 0.024 / 0.014 | 16256 |
| inflate0 / phone | 1,033,678 | 149.094 / 2.339 | 40.998 / 39.513 | 1.818 / 1.818 | 0.031 / 0.018 | 16256 |
| inflate / phone | 1,009,891 | 119.846 / 1.677 | 47.072 / 47.661 | 1.797 / 1.796 | 0.026 / 0.017 | 16256 |
| inflate0 / desktop | 1,415,190 | 325.100 / 4.092 | 98.493 / 59.468 | 3.357 / 3.357 | 0.024 / 0.023 | 16256 |
| inflate / desktop | 1,275,071 | 170.205 / 2.173 | 75.073 / 70.468 | 3.298 / 3.297 | 0.025 / 0.021 | 16256 |
| lex / phone | 972,398 | 62.548 / 1.750 | 34.962 / 44.937 | 1.712 / 1.711 | 0.032 / 0.021 | 16256 |
| lex / desktop | 1,873,866 | 141.417 / 3.404 | 78.467 / 67.441 | 3.432 / 3.432 | 0.050 / 0.033 | 16256 |
| claim / shared | 429,943 | 5.699 / 0.429 | 23.882 / 18.814 | 0.874 / 0.879 | 0.035 / 0.014 | 16256 |
| pred / shared | 702,339 | 45.477 / 1.693 | 54.271 / 47.998 | 1.676 / 1.677 | 0.059 / 0.018 | 16256 |

兩種 SHA、claim、pred 為兩個等級共用；四個共享電路加六個等級專屬
電路，共十份 ACIR/VK、十四個 profile/kind 對應。每組 proof 均驗證通過，
proof 為 16,256 bytes；公開輸入另計。所有完成量測的 CRS cache 前後相同，
first/warm 均未包含下載。原始 JSON、完整 source/ACIR/VK SHA-256 與 ABI
位於 `native/circuits/validation/m3b-round10-{tier}-{kind}.json`；全部十四個
對應已寫入 `VERSIONS`。文字三種電路的 codegen 旗標也屬於資產識別。

手機詞法為 972,398 gates，比第九輪增加 32，餘裕 76,178；電腦詞法為
1,873,866 gates。SHA 內容 996,617 gates，距手機上限 51,959；手機
inflate-first 仍為 1,033,678，保留原本的 14,898 餘裕。本輪未最佳化詞法段。

新量測入口最初漏帶文字電路原有的 `--bounded-codegen`，未列入下列
估算：手機 unbounded 診斷為 1,005,628 gates；電腦 unbounded 在兩／一
編譯執行緒下分別於 99.27／93.78 秒觸及 6 GiB RSS guard，均沒有 gates
或 proof。原始診斷另存 `m3b-round10-lex-unbounded-phone.json`、
`m3b-round10-desktop-lex-rss-guard.json` 與
`m3b-round10-desktop-lex-single-thread-unbounded-rss-guard.json`。
恢復旗標後完成全部正式候選量測，未放寬任何約束或資源保護。

### 31,582 bytes／232 operators 樣本估算

| 等級 | inflate / lex / claim / pred / SHA | 總段數 | first 總秒數（估算） | warm 總秒數（估算） | warm 分鐘（估算） |
|---|---|---:|---:|---:|---:|
| phone | 16 / 16 / 1 / 1 / 1–2 | 35–36 | 1423.92–1454.07 | 1578.47–1615.46 | 26.31–26.92 |
| desktop | 8 / 8 / 1 / 1 / 1–2 | 19–20 | 1369.21–1399.35 | 1197.33–1234.32 | 19.96–20.57 |

範圍的上下界分別是不含／含一段 opaque，兩者均包含一個述詞段。
令 k=ceil(31582/P)，總 prove = SHA-content + inflate-first +
(k−1)×inflate-general + k×lex + claim + pred，選用 opaque 時再加 SHA-opaque。
這是將各電路的單段量測相加的估算，不是該文件的整份證明實測，也不是
手機實機時間；不含編譯、見證產生、PDF/CMS 處理及 I/O。假設樣本各段的
文字運算子、token 與 DEFLATE 區塊起點均符合所選參數；232 個運算子的
總數本身不能保證任一局部段都不超限。無述詞時各減一段及 pred 時間。

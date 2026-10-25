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

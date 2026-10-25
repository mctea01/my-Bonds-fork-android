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

### Round 5 容量調整與中斷檢查點（2026-10-25，未完成）

整合分支 `b35710616411428c93769c0bf8ee7d132eb797c8` 已包含在
工作分支；容量修改與量測工具提交為 `f79397c`。
依第 3.7 節，完整容量改為 **8,192 compressed／40,960 plain／
6,144 tokens／4 blocks**。本輪尚未加入任何 inflate 最佳化，
下表全部是容量調整後、最佳化前的基準。

本次實際環境為 AMD EPYC 9V74、**2 vCPU／8 GiB cgroup RAM**，
與 Round 4 的 4 vCPU／32 GiB 不同。工具仍為 nargo 1.0.0-beta.15
（noirc `83245db91dcf63420ef4bcbbd85b98f397fee663`）、bb 2.1.9。
各組以獨立程序、新 temporary package 依序執行，沒有 ACIR 快取。
`nargo info` 包含完整編譯並回報 opcodes；成功後另跑 `bb gates`。
每組均設 `--seconds 1800 --address-space-gib 24`，但實體容器
先受到 8 GiB 限制，**不能將本次 OOM 當成 24 GiB 預算下的失敗**。

所有組合 N=8,192；B=區塊、T=記號、P=輸出位元組容量：

| B | T | P | 結果 | 編譯時間 | 峰值 RSS（KiB） | ACIR opcodes | gates |
|---:|---:|---:|---|---:|---:|---:|---:|
| 4 | 6,144 | 40,960 | cgroup OOM，SIGKILL，無 ACIR | 257.40 s | 8,302,960 | 未取得 | 未取得 |
| 1 | 6,144 | 40,960 | cgroup OOM，SIGKILL，無 ACIR | 205.75 s | 8,307,004 | 未取得 | 未取得 |
| 4 | 512 | 1,024 | 編譯與 gates 完成 | 242.89 s | 3,700,048 | 1,735,520 | 5,840,513 |
| 1 | 6,144 | 1,024 | cgroup OOM，SIGKILL，無 ACIR | 218.20 s | 8,307,964 | 未取得 | 未取得 |
| 1 | 512 | 40,960 | 執行環境離線，未收到最終結果 | 未取得 | 未取得 | 未取得 | 未取得 |

第三組的 gate 工具另耗時 15.46 s；ACIR SHA-256 為
`bd0605ff682e47453c31d1c09bec720c3b49dd7c7398dce099b42f32eba1f723`。
已完成的數據由工具回傳記錄轉存至
`native/circuits/validation/m3b-round5-checkpoint.json`；第五組不能
以最後一次程序觀察值充當完成測量，也尚不能確認環境離線的原因。

目前只能確認：單區塊、1,024-byte 輸出仍會在 6,144 tokens 時耗盡
此容器記憶體，記號解碼成本需要處理；區塊表不是唯一的瓶頸。
輸出迴圈的獨立測量尚未完成，不能據此排名全部成本，也沒有線性
外推完整 gate、prove 或 RSS。

最佳化比較、完整容量重測、完整 prove／verify／proof 大小、遞迴
驗證 gate 實測均 **尚未完成**。尚未達成完整 M3b 或桌面 1 分鐘／
3 GiB 驗收。恢復後先核對第五組是否有完整記錄，否則重跑，再比較
必要欄位查表、固定表編譯期建立與位元讀取的候選最佳化。

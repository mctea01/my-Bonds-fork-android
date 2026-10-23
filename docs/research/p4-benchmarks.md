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

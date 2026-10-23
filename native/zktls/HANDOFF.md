# WP5 交接紀錄

工作包：WP5 TLSNotary 原生綁定
基準：`552204f4132839c1a63ac3fe7b3b3ad234dd8862`
分支：`codex/p4-wp5-tlsn`

## 範圍與整合邊界

依使用者「維持原範圍，交由 Claude 整合」的決定，本分支不修改
`native/diw-zk-ffi/src/lib.rs`、`native/Cargo.lock` 或產生的 Kotlin 綁定。
因此新增的 FFI 模組尚未註冊到正式 library，`native_info()` 也不宣告 TLSn
可用。不能把 Rust 元件測試通過視為 Kotlin 或 Android 整合驗收通過。

Claude 整合時需要：

1. 在共用 runtime **不加 feature gate** 地註冊 `mod zktls;`；讓停用後端時
   匯出函式仍存在並回傳 `Unsupported`。啟用時才回報 TLSn revision。
2. 更新工作區鎖檔；TLSn 固定為 alpha.15 commit
   `47aee45b53e06648c1b2ad3689b367b8c923fdec`。
3. 決定 Rust 工具鏈升級：這個 TLSn revision 的 mpz alpha.6 依賴要求
   Rust 1.95，現有 1.90 pin 不足。本次隔離驗證使用 1.95.0，沒有修改
   倉庫的工具鏈或工作區 rust-version。
4. 重新產生 Kotlin bindings，並讓 core/app 的 Gradle feature 驗證接受
   `tlsn` 及 `openac,tlsn`。本分支只修改允許範圍內的 `native/build.sh`。
5. 決定測試 CA 的介面：凍結的 FFI 簽名沒有信任根參數。正式 exports
   目前固定使用 TLSn 的 Mozilla roots；Rust loopback 直接傳入測試根。
   建議另訂限測試建置可用的 trust-root 注入方式，勿以全域正式信任庫
   接受任意測試 CA。
6. 補跑規格指定的 Kotlin `ZkTlsLoopbackTest` 及 Android 雙角色測試。
   本環境沒有 Android SDK、模擬器或 `/dev/kvm`，未宣稱 Android 已驗收。

## 實作

- Proxy 與 MPC 都驗證主機名、TLS 1.2 憑證鏈與協議上限；僅接受
  `proxy`／`mpc`，最多送出 4096、接收 262144 個明文字節。
- HTTP request 必須有唯一且相符的 Host、`Accept-Encoding: identity`、
  `Connection: close`。可揭露的 request 範圍限 method/path（排除 query）
  與 Host 行。傳輸不解析回應內容，chunked framing 保留於原始 transcript。
- Noise `NK_25519_ChaChaPoly_SHA256` 使用 32-byte request JWS hash 作
  prologue；callback 只搬運密文。雙位元組大端長度外框、16 KiB 分塊、
  驗證過的空密文訊息代表 EOF；每方向 1 GiB 傳輸上限。
- Noise 內另有四位元組大端 TLSn segment framing：`1..16384` 是資料，
  `0xffffffff` 是雙方完成證明／驗證後的同步訊號，`0` 是 segment EOF。
  同步後才關閉 mux，避免上游關閉時尚未交付給 peer 的證明資料遺失；
  分段 EOF 避免 mux 預讀吃掉下一段憑證訊息。兩端必須使用相同 wrapper。
- TLSn verifier 未直接輸出完整 MPC 憑證鏈，因此在 segment 後傳送最多
  64 KiB 的 bincode 1.3 HandshakeData，再驗證鏈、主機名、時間、ephemeral
  key 及雙方 random 與已認證 TLS session 一致；不信任單純附帶的憑證。
- 未揭露明文歸零，mask 保留認證範圍。SHA-256 commitments 使用 TLSn
  原生 salted transcript commitments；它們不是 `SHA256(plaintext)`。
- FFI callback bridge 有界緩衝，寫入有完成確認；取消每 20 ms 檢查，整個
  operation 600 秒上限。關閉 callback 後 join worker，不留下私密輸入工作。
  callback 的 `close()` 必須 thread-safe、可重複呼叫，且能解除 send/receive
  阻塞。任意外部 callback 若違反此契約，Rust 無法安全強制終止它。
- 外層 worker 與 callback worker 的 panic 不輸出 payload；錯誤映射為固定
  代碼。FFI 執行期間停用該執行緒的 tracing subscriber。

## 介面變更提案

`ZkTlsCommitment` 依 p4-circuits.md 4.3 的 range／alg／digest 定義，具體化為
`range: ZkRange, alg: String, digest: Vec<u8>`，`alg` 為 `SHA256`；目前只支援
單一 Received 範圍。請 Claude 確認 record 的型別選擇並與 WP6 對齊。
其餘 FFI records 與函式沿用規格，附加 request_hash／verifier_static_public
或 private。

正式 FFI 不新增任意 CA 或不驗證憑證的開關。

## 重現元件測試

工作區整合完成後：

```sh
cargo test --release --locked --manifest-path native/Cargo.toml -p zktls
cargo test --release --locked --manifest-path native/Cargo.toml -p diw-zk-ffi --features tlsn
cargo test --release --locked --manifest-path native/Cargo.toml -p diw-zk-ffi
```

目前測試是在 `/workspace/zktls-check` 隔離副本註冊新模組、產生獨立鎖檔並
使用 Rust 1.95.0 後執行，沒有將這些整合變更偷偷寫回本分支。測試資料為
每次新建的 localhost PKI、合成 HTTP query/body；沒有真實網站資料。

效能入口為 release `loopback` test executable 的 ignored
`desktop_benchmark`，設定 `DIW_TLSN_BENCH_MODE=proxy|mpc` 與
`DIW_TLSN_BENCH_BYTES=1024|16384|204800`。只輸出數字與模式，不輸出明文。
時間包含本機 TLS、Noise、交互式證明及收尾；`verifier_accept_ms` 是互動式
驗證加 supplemental certificate check，含等待 peer，不能當作純 CPU 時間。

## 第三方元件與授權

`NOTICE` 已新增 TLSNotary alpha.15、mpz alpha.6、tlsn-utils、snow 0.9.6、
Tokio、futures、serde、zeroize、tracing、bincode、TLS／crypto 依賴及 Mozilla
root data。Runtime 依賴的 Cargo metadata 沒有必須採 GPL／LGPL／AGPL 的項目；
未填 license 的 TLSn、mpz、tlsn-utils crates 另以各 repo README 的全 crate
MIT／Apache-2.0 宣告核對。r-efi 多重授權採 MIT／Apache-2.0 選項。
rcgen、rustls 0.23、tokio-rustls 只供本地 HTTPS 測試使用。

## 本輪測試結果

- 隔離副本 `cargo test --release --locked -p zktls`：**14 passed**，
  1 opt-in benchmark ignored。包括 HTTP reveal gate／header 拒絕、callback
  flush/cancel/panic/EOF race、連續 10 次 callback Noise 會話、Proxy、MPC、
  真正多 chunk 回應、連續 5 次 Proxy 會話及 3 組 Noise 正負向測試。
- 隔離副本 `diw-zk-ffi --features tlsn`：availability/key-length 與既有
  runtime 測試通過；停用 TLSn 的配置 **7 passed**，確認固定匯出回
  Unsupported。隔離註冊不等於正式 native_info／Kotlin 綁定已更新。
- WP1 Gradle `*NativeZkBenchmark.tlsNotaryDesktop -Pbench=true`：**PASSED**，
  Proxy/MPC 各測 1、16、200 KiB response，first/warm 各一次。
- `bash -n native/build.sh` 通過。逗號 list 拒絕空 entry／未知 feature。
- 原倉庫 `cargo test --release --locked --manifest-path native/Cargo.toml
  -p zktls`：**BLOCKED**，Cargo 明確回報 lock file needs to be updated。
  沒有移除 `--locked` 偷改被排除的鎖檔。
- 既有 Gradle core／desktop App compile 與 test-servers 全測通過；沒有
  Kotlin TLSn binding 時，這個結果不包含 Kotlin TLSn loopback。

因原提示詞要求 PR 前通過原倉庫 locked build 與工作包驗收，本分支在
上述整合完成前不得標記為可合併。Android／Kotlin acceptance 尚未完成。

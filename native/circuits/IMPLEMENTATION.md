# M3a 電路實作報告

電路：`pdf_text_v1` component library，里程碑 M3a
基準：`552204f4132839c1a63ac3fe7b3b3ad234dd8862`
分支：`codex/p4-wp3a-m3a`

## 約束對照

| 規格 | 實作與約束 |
|---|---|
| 3.2 SHA-256 視窗 | `sha256_window.nr::sha256_window`；大端組成 16 個 u32，呼叫固定版本標準庫 `std::hash::sha256_compression`，逐塊銜接 midstate 並等於 mid_out。沒有替私密視窗加 padding。 |
| 公開 head／tail | head、tail 長度各小於 64，head + private + tail 必須恰好填滿所選區塊；逐 byte 比對邊界。未使用的 head、tail 與區塊尾端強制為零。外層負責把這些參數設為 public。 |
| 3.3 zlib header | `inflate.nr::inflate`；CM=8、CINFO<=7、FDICT=0、mod31=0，距離不得超過 header 宣告的 window。 |
| stored／fixed／dynamic | stored 驗證 LEN/NLEN、字節對齊、內容與終點；fixed 使用 RFC 表；dynamic 重建 canonical Huffman tables，驗證 code-length repeat、HLIT/HDIST/HCLEN、EOB、過度訂閱及不完整樹。只允許 RFC 所需的單一長度 1 碼／空 distance 特例。 |
| 階段 A 完整解析 | 每個 private token hint 的 symbol、width、bit start 都對照原始 bitstream；block token 區間為連續 prefix sums；首 token 接 header，後續 token 必須接前一個終點，EOB 必須是最後 token，並接 block.end。BFINAL 只准最後 block 為 1，最後位元所在 byte 必須恰接 Adler32，拒絕多餘串流。 |
| 階段 B LZ77 | 以 private owner hint 選取唯一且不重疊的 token output 區間；literal 等於原字節，copy 只能從既有輸出往回讀，支援 overlap，拒絕越界距離。 |
| checksum 與上限 | 輸出逐 byte 計算 Adler32，與 zlib 大端 trailer 完全相等。上限 N<=8192、P<=40960、T<=20480、B<=8；實際長度是 private，未使用的輸入尾端為零，輸出尾端固定零。 |

沒有 `unsafe`／不受約束的 helper 參與接受條件。`owners`、`tokens`、
`blocks` 都是不可信提示，由上述約束完整檢查；Python 產生器不具驗證權限。

## 與規格不同之處

- Huffman decoder 使用「每個 symbol 的 canonical code 與 width」查表，
  而非 first_code + offset 表。兩者驗證同一組 canonical codes；本實作
  在 compile time 展開的成本較高，需要後續依實測優化。
- 通用 library 保留規格上限，但量測用 inflate instances 是 1 block、
  128 compressed bytes、192 tokens，分別有 16/32/40 KiB 輸出容量。
  它們使用重複字元的合成 zlib，不能代表 8-block／20480-token 最壞情況。
- M3a 不包含 M3b 的 PDF lexer、BI／ActualText 禁止規則、日期述詞、
  字串提示完整性或最終 public ABI。工作包總驗收的 Z8、Z9、Z13 屬於
  這些後續電路；本報告不把它們列為已完成。
- 小容量 constrained probe 的原始碼與完整 compiler checks 均已驗證。
  主要快速 inflate regressions 是 Brillig 語意測試，不把這些測試誤稱為
  每一個都已產生 ACIR 證明。

## 公開輸入

Library 本身不宣告 main/public ABI，交由 M3b 包裝。SHA benchmark main
的公開輸入順序為 `mid_in[8]`、`mid_out[8]`（u32 以 field 編碼），bytes
全部 private。inflate harness 的輸入與 expected output 都是 private，
用於約束測試及效能量測；它沒有綁定外部 PDF 的公開聲明。這些 main
不是第 3.6 節的最終 `pdf_text_v1_1p` ABI，也不得加入正式電路資產清單。

## 測試與證據

- `nargo test`：19 項通過。5 項 constrained SHA 測試包含 NIST abc
  compression known answer、正確 head/tail、單獨 head 篡改、單獨 tail
  篡改及空視窗拒絕。邊界負向案例保留正確 digest，避免由無關的錯誤
  midstate 造成假陽性。
- 14 項 inflate 語意測試：stored、fixed overlap、dynamic、multiple
  blocks、empty；checksum、token gap、wrong owner、輸出過長、輸出長度
  不符、BFINAL、dynamic hint、stored complement、FDICT 負向案例。
- `inflate_probe` 的完整 ACIR 編譯未關閉 underconstrained 或 Brillig
  constraints checks。`nargo execute` 接受 stored/fixed/dynamic/empty，
  拒絕 checksum、token gap、owner 篡改。合成 dynamic stream 另由 Python
  zlib 獨立解壓比對。
- 最終 probe 的 dynamic witness 產生 UltraZK proof，另一個 `bb verify`
  程序通過；782,382 gates、336,860 ACIR opcodes。first／warm 為
  39.03／40.62 秒，峰值 1,816,708 KiB RSS，proof 16,256 bytes，驗證
  約 36.3 ms。此為小容量 correctness probe，不代表 16/32/40 KiB profile。
- SHA 65/130/260 的 ZK proofs 均由獨立 verifier 程序通過。更改一個公開
  midstate field byte 後驗證失敗。數據與 hash 在 `validation/*.json`
  及 `VERSIONS`；完整桌面比較由 WP1 彙整。
- Z2：涵蓋 component 的 head/tail 綁定與公開 midstate 竄改；完整公開
  PDF 的驗證還需 WP4/M3b。Z12：輸出容量／長度拒絕在 component 約束
  中成立。未宣稱完成其他跨工作包的 Z 驗收。

## bb 零知識設定核對

版本固定為 bb **2.1.9**，命令為：

```sh
bb prove -s ultra_honk --oracle_hash poseidon2 -b circuit.json -w witness.gz \
  -o proof-dir --write_vk -c /path/to/crs
bb verify -s ultra_honk --oracle_hash poseidon2 -k proof-dir/vk \
  -p proof-dir/proof -i proof-dir/public_inputs -c /path/to/crs
```

兩邊都不傳 `--disable_zk`。此版本 `bb prove --help` 顯示該旗標預設 false；
不能套用舊版「UltraHonk 預設不是 ZK」的推論。另核對固定 tag 原始碼：

- [CLI API 旗標傳遞](https://github.com/AztecProtocol/aztec-packages/blob/v2.1.9/barretenberg/cpp/src/barretenberg/api/api_ultra_honk.cpp)
- [prove、VK 與 verify 的 flavor 選擇](https://github.com/AztecProtocol/aztec-packages/blob/v2.1.9/barretenberg/cpp/src/barretenberg/bbapi/bbapi_ultra_honk.cpp)

`poseidon2` 且 `disable_zk == false` 選取 **UltraZKFlavor**；true 才選
UltraFlavor。產生 key 與 verifier 必須跟隨相同選項。這是版本限定的
原始碼／CLI 核對，不能只由 proof 能否驗證推論它具有零知識性。

同一個 65-block 電路另以 `--disable_zk` 產生並自驗：非 ZK proof
14,624 bytes，ZK proof 16,256 bytes，相差 **1,632 bytes**（另有相同的
512-byte public inputs）。非 ZK 檔案只存在 ignored target，不作正式資產。
量測記錄為 `validation/bb-nonzk-comparison.json`。

## 需要 Claude 特別檢查

1. 不可信 token／owner hints 是否已完整綁定，特別是空 block、overlap
   copy、dynamic repeat 與 EOB 終點；本次實作尚未經獨立密碼學審查。
2. M3b 呼叫時必須把 SHA boundaries、midstates 與外部 public input
   綁定，並把 inflate 的 private compressed bytes 接到 SHA 視窗。
3. 完整 profile 的編譯與 proving 成本不能由小 token-budget 的 benchmark
   線性外推；優化或調整固定 profile 需要重新編譯及釘選 VK。
4. VERSIONS 的 ACIR/VK hash 僅是本次測量資產；正式發佈需再對最終
   M3b ABI、構建環境與下載清單審查後釘選。

新增第三方電路函式庫：無。使用 Noir 固定版本內建 SHA compression。
Noir／bb 只作開發與證明工具，本分支沒有新增 APK 原生 runtime 依賴。

最終 SHA ACIR 因測試與來源 metadata 更新而與首次測量檔 hash 不同；
`validation/*.json` 同時保留 `measured_acir_sha256`。已從最終 ACIR
重新產生三組 ZK VK，與量測時 VK 逐 byte 相同，確認約束未改。

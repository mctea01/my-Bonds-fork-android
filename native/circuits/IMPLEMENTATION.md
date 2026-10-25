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

## M3b 恢復檢查點（Round 4，尚未完成）

基準：整合分支 `24f32af39d605c92ee3f038ced1263ddbff3c6ff`。
恢復時遠端 `codex/p4-wp3a-m3b` 只有已合併的 M3a，沒有完整 M3b
電路。下列修改是 M3b 的前置工作，不能作為可發布的 zkPDF 電路。
M3d 合成文件在獨立分支 `codex/p4-wp3b-testdocs`、PR #20；本分支
未帶入該分支的測試文件。

### 已完成的約束與測試

- 第 3.4.1 節：保留全部 inflate 容量與檢查，將每個區塊的 Huffman
  表放入平坦陣列，`symbol_at` 以 `block * alphabet + symbol` 讀取
  碼長與 canonical code。區塊、alphabet、symbol 及讀取範圍仍有約束；
  不先依私密索引選取整張表。沒有新增 unconstrained acceptance path。
- M3a 的空區塊、overlap、dynamic repeat 與 EOB 審查項目已補上
  定向負向案例：空 stored endpoint、空 Huffman 缺 EOB、重疊輸出
  owner／distance、無前項的 repeat 16、repeat 18 超過碼長表尾端、
  動態表缺 EOB、錯誤 EOB endpoint。EOB endpoint 的修改仍留在原本
  最後一個 byte 中，避免僅靠 zlib 長度檢查拒絕。
- 多區塊正向案例包含不同的 fixed／dynamic 表及中間空 stored block；
  負向案例包含使用另一張表的碼長及跳過空區塊。產生器以 Python
  zlib 獨立核對每份正向串流，再只改指定的提示或位元。
- `nargo test`：**33 項通過**（5 項 SHA 測試、28 項 Brillig inflate
  語意測試）。`tools/regressions.py`：11 個 ACIR 案例通過；加上
  `--multiblock`：4 個 ACIR 案例通過。共 5 個接受、10 個約束拒絕。
  ACIR 執行啟用 pedantic solving，未略過 underconstrained 或
  Brillig constraints checks；解析／編譯錯誤不算負向測試通過。
- `:core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test`
  通過；354 項發現、325 通過、29 略過、0 失敗。另有兩個既有
  非 void JUnit 方法沒有被發現（`ZkTemplatePackTest.signedPackRoundTrip`
  與 `ZkTlsPlanTest.signedRequestRoundTrip`），未計入上述數量。本環境
  未安裝 Rust，原生測試依既有 auto 規則略過；沒有宣稱 Rust／原生
  後端驗收通過，也沒有修改 Rust 或 Android 程式。

### 小容量證明與版本

`inflate_probe` 的容量仍為 128 compressed／128 plain／32 tokens／
1 block。gate 數從 M3a 的 782,382 降至 **680,210**，ACIR opcodes
296,094。bb 2.1.9、`-s ultra_honk --oracle_hash poseidon2`，不帶
`--disable_zk`，first／warm 證明 22.29／17.33 秒，峰值 1,795,500
KiB RSS，16,256-byte proof，獨立 `bb verify` 通過（17.15 ms）。
此 probe 沒有公開輸入，**不驗證 PDF／SHA 公開綁定**。

本次為 4 vCPU／32 GiB 雲端容器，背景另有完整容量編譯，first
包含首次 CRS 下載；不能直接與 M3a 的 2 vCPU 時間比較。
`validation/m3b-inflate-probe.json` 保存量測；`VERSIONS` 更新此
小容量 probe 的 ACIR／VK SHA-256。M3a 歷史數據仍保留，其他 SHA
元件沒有改動。這些 hash 不是完整 M3b 的正式釘選。

完整容量 inflate 的兩次 600 秒編譯（原 M3a 與優化版）均 timeout。
優化版延長到 1,800 秒預算後，在 783.45 秒因記憶體配置失敗而
SIGABRT；峰值 RSS 24,139,060 KiB，位址空間預算為 24 GiB。沒有
取得 ACIR 或完整 gate／proof 數據。這是編譯資源限制，不能當成
證明成本；詳細環境、重現命令與未採用的調整方案見 benchmark 文件。

### 尚未完成與交接界線

| 規格 | 狀態 |
|---|---|
| 第 3.4 節 SHA 視窗與 inflate 連接 | 未接上；M3a 元件本身仍存在 |
| 第 3.4.2–3.4.5 節 lexer、完整性、錨點、承諾、日期述詞 | 未實作 |
| 第 3.5 節 Word 類規則 | 未實作；沒有宣稱 Z8／Z9／Z13 通過 |
| 第 3.6 節公開輸入與見證 ABI | 未實作；沒有 `PUBLIC_SPEC.md` 凍結提案 |
| 第 3.8 節簽章文件欄位與 β 綁定 | 尚不成立；本次 probe 只有解壓元件語意 |
| 完整 `pdf_text_v1_1p` 的 gate、證明、驗證、ACIR／VK hash | 尚無產物或量測 |

介面變更提案：無。沒有改容量、拆證明、修改其他工作包或新增第三方
元件。M3c 的開始條件尚未成立：整合分支沒有狀態為「已凍結」的
`PUBLIC_SPEC.md`，因此未開始證明器與 FFI。

接續工作先重現完整容量 inflate 編譯（`tools/compile_profile.py`；
量測見 `docs/research/p4-benchmarks.md` 的「完整 zkPDF 電路」一節），
解決編譯資源成本，再完成上述電路與 ABI、Z8／Z9／Z13、完整 proof
及規格凍結提案。不得把小容量 probe 當成完整電路驗收。Claude 仍需
獨立審查 hint 綁定與新的平坦表索引；本次回歸測試不取代密碼學審查。

## M3b 恢復檢查點（Round 5，中斷，尚未完成）

基準：整合分支 `b35710616411428c93769c0bf8ee7d132eb797c8` 已在
原工作分支歷史中，開始時 merge 回報 already up to date。
`f79397c` 將 inflate 上限與完整容量 harness 改成 N=8,192、
P=40,960、T=6,144、B=4，並讓 `compile_profile.py` 接受分維度
參數、記錄 opcodes、以 bb 取得 gates，保留失敗與容器限制。

這是規格已核准的容量調整，沒有放寬約束，沒有新增 unconstrained
接受路徑或修改其他工作包介面。既有邊界與多區塊測試原封保留。

### 已完成與未完成

- 已完成四組基準量測；三組在 **8 GiB cgroup** 下 OOM，一組編譯
  成功，1,735,520 opcodes／5,840,513 gates。詳細表格在 benchmark
  的「Round 5 容量調整與中斷檢查點」。
- 第五組 B=1、T=512、P=40,960 執行中環境離線，尚未收到最終記錄。
  不將中途 RSS／時間或環境離線當作已完成的 OOM 量測。
- 各組設有 1,800 秒／24 GiB RLIMIT_AS，但容器實際只有 2 vCPU／
  8 GiB，不能把結果寫成「24 GiB 仍無法編譯」。
- 候選最佳化只在工作區準備，**沒有加入分支，也沒有前後實測**。
  包含區塊／記號必要欄位投影、固定 Huffman 表編譯期建立，以及
  最多 16 bits 的讀取改用三個 bytes；是否採用仍待驗證。
- Round 5 的 `nargo test`、兩組 ACIR regressions 與要求的 Gradle
  指令 **尚未執行完成**。前述 Round 4 測試數是歷史紀錄，不能當成
  本輪驗收。Python 工具已通過語法編譯；四區塊診斷 harness 已實際
  完成 Noir 編譯與 bb gates。
- 沒有完整 PDF 電路、完整 prove／verify／proof 大小或新的正式
  ACIR／VK；沒有更新正式釘選。既有 `VERSIONS` 中的 probe hash
  仍是 Round 4 資產，恢復後需對最終來源重新量測。
- PR #21 保持 draft。沒有開始 M3c 或自行拆電路。Z8／Z9／Z13、
  lexer、錨點、欄位承諾、述詞與 Word 類規則仍未完成。

### 遞迴合併設計草案（待 Claude 決定，沒有實作）

候選切分以輸出位置為主：每段最多處理 1,024 個輸出位元組或
512 個記號，先到者結束；整份文件的原容量保持不變。跨段的
長度距離對保留剩餘長度與距離，下一段先完成該 copy，不重新解碼。
動態 Huffman header 可用獨立 header 段，保留全部碼長、repeat、
EOB 與完整樹檢查；空 stored／EOB 必須推進記號或區塊，禁止無進展段。

每個葉證明的公開邊界狀態包括：位元位置、區塊索引／類型／BFINAL、
全域記號與輸出位置、Adler-32 的 a／b、Huffman 表承諾、LZ77
視窗根、已輸出內容的串接承諾、未完成 copy 的長度與距離。
同時綁定壓縮資料承諾、zlib 長度／視窗設定、profile 與段號。
精確 field 編碼與數量須由 Claude 核准，不在此自行凍結 ABI。

LZ77 用 32,768-byte 環形 Merkle 視窗。葉子綁定槽號、絕對輸出
位置與 byte；初始根是已知的未寫入狀態。每次讀取驗證當時的根、
槽號 `(k-distance) mod 32768` 與絕對位置 `k-distance`，並約束
`1 <= distance <= min(k, zlib window)`，防止接受上一圈舊資料。
每 byte 寫入後更新根，重疊 match 依序讀寫，能讀到同一 match
剛產生的 byte。僅攜帶未驗證的 window hash 或各段獨立見證均不足。
Poseidon2 Merkle tree 的每次 15 層讀寫路徑成本仍須實測。

已輸出內容用含網域、長度與隨機鹽的串接承諾；lexer 段對完全相同
的順序重算承諾。壓縮資料的根亦須由 SHA 視窗葉電路綁定：驗證
head／tail、midstates 與 RC4 XOR 後，對實際 zlib bytes 計算根，
inflate 段的位元讀取需提供該根的 membership 證明。

以平衡二元樹聚合：每個內節點驗證兩個 UltraHonk ZK 子證明，
核對同一文件／profile、段號連續、左終態等於右初態。根節點檢查
初態、終態、總容量、唯一 zlib stream、EOB／BFINAL 與 Adler trailer，
再與 SHA、lexer／claims 證明連接。中間狀態及子證明在上一層是
private witness，對外只暴露第 3.6 節的正式公開輸入，不附送葉證明
與中間 inputs，避免洩漏位置與 Adler 中間值。每層均使用 ZK，
驗證金鑰必須以常數或已驗證 allowlist 綁定，不接受 prover 自選 VK。

成本估計只列可確定的呼叫數：n 個葉證明的二元樹有 n-1 個內節點、
2(n-1) 次子證明驗證。**尚未取得遞迴驗證 gate 實測**，不能宣稱
方案已符合時間／記憶體門檻。已核對 bb 2.1.9 的
[bb_proof_verification](https://github.com/AztecProtocol/aztec-packages/blob/v2.1.9/barretenberg/noir/bb_proof_verification/src/lib.nr)：
UltraHonk ZK 使用 proof type 7、508 proof fields、115 VK fields；
恢復後須分別量一個與兩個 verifier，並記錄 application public input
數。狀態連接、Merkle paths、承諾、SHA、lexer 與葉證明成本另計，
不能把單一 verifier gates 倍乘當成整體實測。

採納前需驗證錯誤 VK／public inputs、交換或跳段、視窗置換、
overlap、錯誤 Adler／終態等負向案例，並產生與獨立驗證完整聚合 proof。
本草案不取代規格審查，也不構成可發布的切分實作。

### 恢復順序

1. 恢復環境後先 fetch／merge 原工作分支，保留工作區未提交檔案；
   中斷期間透過 GitHub 連接器補了量測與文件檢查點。
2. 核對實際 RAM／CPU；依既定 1,800 秒／24 GiB 位址空間預算重跑
   未完成的第五組，並清楚區分容器限制與編譯預算。
3. 比較候選最佳化，附前後數據與回歸測試，再重測完整容量。
4. 補遞迴 gate 實測，完成本輪 Noir／ACIR／Gradle 檢查及 PR 說明；
   只有完整容量通過桌面 prove 門檻時才進入剩餘 M3b 實作。

新增第三方元件：無。沒有修改 Rust、Android 或其他工作包。

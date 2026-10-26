# M3a 電路實作報告

本檔保留 M3a 至 Round 5 的歷史報告。最新約束、測試與限制以後方
「Round 6 不可變提示與成本」為準；完整 M3b 尚未完成。

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

## M3b 檢查點（Round 5，尚未完成完整電路）

基準整合分支 `b35710616411428c93769c0bf8ee7d132eb797c8` 已包含在
工作分支。`f79397c` 將 inflate 上限與完整容量 harness 設為
N=8,192、P=40,960、T=6,144、B=4；`9717d17` 採用三 byte 位元
讀取。只修改本目錄與 `docs/research/p4-benchmarks.md`，沒有改動
其他工作包的介面、退路或相容行為。

### 完成範圍與量測限制

- 五組要求的容量基準全部有最終記錄；第五組在環境恢復後找回。
  四組在實際 **8 GiB cgroup** 下 OOM；B=4／T=512／P=1,024 成功，
  1,735,520 opcodes／5,840,513 gates。所有 N=8,192，設 1,800 秒／
  24 GiB RLIMIT_AS；不能把實體容器限制稱為 24 GiB 預算失敗。
- 三項候選分別從容量基準測量：必要欄位投影 gates 僅少 0.40%，
  固定表移至編譯期的 gates 相同，兩者不採用；patch 與數據保留
  供重現。三 byte 位元讀取採用後，同容量降至 1,408,180 opcodes／
  5,265,212 gates（少 9.85%），編譯 95.17 s、2,559,160 KiB。
- `bits()` 最多 16 bits、最大位移 7，最多跨三個 bytes；所有正式
  呼叫的 `limit=(data_len-4)*8`，故 `offset<=N-4`，包含尾界的
  width=0。直接索引保留陣列界限與 width／limit 約束，第四個 byte
  及索引夾限是冗餘工作。沒有放寬接受條件，沒有 unconstrained 路徑。
- 最佳化後完整容量於 113.70 s、6,292,780 KiB 觸及新設 6 GiB
  RSS guard，主動中止，無 ACIR。guard 用於保護 8 GiB 工作階段；
  不是 OOM、完整編譯成本或 24 GiB 預算失敗。
- 完整 `pdf_text_v1_1p` 尚未實作，完整 prove／verify／proof 大小
  及正式 ACIR／VK 未取得。桌面 1 分鐘／3 GiB 的先決條件未達成，
  不進行剩餘 M3b：lexer、運算子表、錨點、欄位承諾、述詞、Word
  類規則、`PUBLIC_SPEC.md` 與 Z8／Z9／Z13；也沒有開始 M3c。
- `VERSIONS` 更新的是小容量 `inflate_probe` 的 ACIR／VK hash，
  不是正式資產凍結。合成 dynamic Huffman 的 ZK first／warm prove
  26.65／22.33 s、verify 19.48 ms、proof 16,256 bytes；gates 571,668。
  詳細數據、各組來源 hash 與差異分析見 benchmark 的 Round 5 節。
- PR #21 保持 draft。以下切分提案沒有實作，須由 Claude 決定。

### 本輪驗證

- `nargo test`：36 tests passed，包含三 byte 最大寬度、零寬度尾界、
  越界拒絕；原有多區塊、不同 Huffman 表與負向案例保留。
- `python3 -I tools/regressions.py`：11／11；含 `--multiblock`：4／4。
  合計 5 正向、10 負向；負向必須回報 `Cannot satisfy constraint`，
  解析／編譯錯誤不算通過。結果在 `validation/m3b-round5-*-regressions.json`。
- 小容量 probe 兩份 UltraHonk ZK proof 均生成成功，獨立 verify 成功；
  沒有使用 `--disable_zk`，沒有輸出私密輸入或提交大型資產。
- Python 工具語法、RSS guard 成功／timeout／RSS 中止路徑已檢查，
  新 profiler 的完整容量保護中止與遞迴 fallback 均實際執行。
- `./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test`
  成功（4m 9s）；362 tests、0 failures／errors、29 skipped。
  `signedPackRoundTrip` 與 `signedRequestRoundTrip` 均被發現並通過。
  環境沒有 cargo，既有 auto 設定略過 native build；
  `deviceVerifierBehindTheRelay` 被發現但 skipped，不能宣稱已驗證
  relay 時序修正。本輪沒有修改 Rust，未執行 cargo test。
  使用 2 workers、JVM Xmx3g、Kotlin in-process 配合 8 GiB 環境；
  詳見 `validation/m3b-round5-gradle.json`。

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

以下為已被 Claude 在 Round 6 **否決**的歷史方案，不再作為後續建議：
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

n 個葉證明的二元樹有 n-1 個內節點、2(n-1) 次子證明驗證。
已核對 bb 2.1.9 的
[bb_proof_verification](https://github.com/AztecProtocol/aztec-packages/blob/v2.1.9/barretenberg/noir/bb_proof_verification/src/lib.nr)：
UltraHonk ZK 使用 proof type 7、508 proof fields、115 VK fields。
每份 32 個 application public inputs 時，一個／兩個 verifier 的
**獨立實測**為 704,869／1,471,929 gates，dyadic size 為
1,048,576／2,097,152；WASM gate 建構為 3.23／5.25 s、峰值
487,044／872,660 KiB。不是 prove 時間或完整聚合成本。

bb 2.1.9 原生 `gates` 的 `CircuitStats` 把 builder 當作 flavor
傳入 metadata helper，留下 `honk_recursion=0`，因而拒絕遞迴 opcode。
`tools/recursion_profile.py` 保留原生失敗，透過同版 bb.js 既有
`acirGetCircuitSizes(bytecode, false, true)` 量測；沒有修改 backend。
結果、API、資源限制與 hash 在 `validation/m3b-round5-recursion-*.json`。
只有 verifier black box，沒有有效遞迴 proof、可信 VK 綁定或段間狀態
檢查；32 個 inputs 也不是正式 ABI。不能依賴未核實的 `key_hash`
參數代替完整 VK 的常數／allowlist 綁定。

狀態連接、Merkle paths、承諾、SHA、lexer 與葉證明成本另計。
不能把 verifier gates 倍乘當成整體實測，不能宣稱方案已符合
時間／記憶體門檻。新增 optional `@aztec/bb.js` 2.1.9 為 MIT
授權外部開發工具，記於本目錄 `NOTICE`，沒有打包進 App。

採納前需驗證錯誤 VK／public inputs、交換或跳段、視窗置換、
overlap、錯誤 Adler／終態等負向案例，並產生與獨立驗證完整聚合 proof。
本草案不取代規格審查，也不構成可發布的切分實作。

### 下一步

Claude 先審查新的位元讀取邊界推導與遞迴狀態綁定提案，再決定
後續架構或其他保留容量的最佳化。不能把本輪的保護性中止推論成
24 GiB 失敗，也不能把小 probe 或 verifier 成本當作完整 M3b 驗收。
正式電路與 ABI 凍結仍需依工作包流程完成。

## Round 6 不可變提示與成本

基準整合 commit：`b35710616411428c93769c0bf8ee7d132eb797c8`，開始前已
fetch 並 merge（Already up to date）。僅調整本工作包的 component library、
bench、產生器及量測文件；完整 `pdf_text_v1_1p`、lexer、錨點及
`PUBLIC_SPEC.md` 尚未實作。PR #21 維持 draft。

### 第 3.4.1 節約束與健全性

- **不可變讀取**：`inflate.nr::inflate` 的 `plain`、`InflateHints`
  都是 private input。區塊迴圈在常數索引綁定平坦的 LL/DD 碼長與
  反轉碼、body、kind；記號迴圈在常數索引綁定 starts、lengths、ends、
  distances。私密區塊／owner 索引只讀這些輸入及 `.map` 投影的
  first_token、token count、end、symbol，沒有私密選取整個 struct。
- **明文唯一性**：區塊 token 區間連續，token output 區間由累加長度
  唯一決定；owner 必須落在其非空區間內。literal/stored 字節綁定
  已驗證的 symbol。copy 的 distance 為正且不超過已產生的長度，
  每次讀取 `plain[k-dist]` 都嚴格早於 k；以 k 歸納，即使 overlap
  也只能得到 RFC LZ77 的唯一輸出。每個 `plain[k]` 均由常數索引
  `assert_eq` 綁定，未使用尾端必須為零。harness 最後比對回傳值與
  expected 只是自等式，安全性來自上述逐 byte 約束；expected 本身
  就是被攻擊的明文提示，並非可信外部答案。
- **Huffman**：`table` 對每個 width=1..15、每個 symbol 驗證
  prefix counter 初值零及逐項遞推；first code 由前一層 count 決定。
  私密 width 只讀不可變 prefixes／first_codes。每層保留
  oversubscription 檢查、完整樹要求與原有單一長度 1／空 distance
  特例；長度限 15，EOB 必須存在。計數不超過 N<=320，first+count
  小於 N*2^15<2^32，cast 無法藏起溢位。固定表由 RFC canonical
  公式在編譯期建立；反轉只在建表時做一次。
- **dynamic header**：CL 表與 expanded lengths 在常數索引綁定；
  repeat 16 需前項、16/17/18 的次數範圍與剩餘容量皆受約束。
  `header_window` 一次驗證 CL code 及 extra，prefix/suffix 各自
  範圍限定後將三 byte 整數分解，總值小於 2^24，不能靠 Field
  溢位或進位抵消錯誤碼。碼長內的 unused repeat advice 不影響接受。
- **token window**：`token_window` 一次驗證 LL code、length extra、
  DD code、distance extra；各分量由 canonical table 或 base/extra
  範圍限制，總寬度至多 15+5+15+13=48 bits。加起始位移至多
  7 bits，只需七 byte；prefix<2^shift，suffix<2^(56-shift-width)，
  分解等式兩側均小於 2^56，沒有 Field wrap 或歧義。由
  start<=limit=(data_len-4)*8 推得前四次讀取在界內，後三 byte
  超出配置 N 時只補零，實際消耗位元仍需 end<=limit。
  bits helper 的 width<=16 與三 byte 界限仍保留；變動冪改讀常數表。
- **Adler-32**：令 n=plain_len、a=1+sum(plain[k])、
  weighted=sum(k*plain[k])。零 padding 推得
  b=n*a-weighted=n+sum((n-k)*plain[k])>=0。
  a<=1+40960*255=10,444,801<2^24，b<=40960*a<2^39，
  所有中間值遠低於 Field 模數與 u64 上限。最後才各做一次 mod65521，
  與逐 byte Adler recurrence 等價，並完全比對 trailer。
- **保留條件**：zlib header/window、stored LEN/NLEN、連續 bit
  endpoint、BFINAL、EOB 最後位置、單一串流精確終點、容量與輸入零
  padding 都保留；沒有新增 unconstrained 接受路徑，也沒有略過
  編譯器的 underconstrained checks。

### 測試、介面與後續

`nargo test` 69 項通過；這包含快速 Brillig 語意案例，不能全部稱為
ACIR proof。另以完整 constrained ACIR、pedantic solving 執行標準
41、多區塊 4、Adler wraparound 3 案例，共 7 個接受、41 個約束拒絕。
負向 runner 只接受 `Cannot satisfy constraint`，解析／編譯錯誤不算
成功。新增攻擊涵蓋錯誤明文、保持 Adler 不變的 (+1,-2,+1) 複製
修改、表項、起點／終點、距離、prefix counters、first codes、header
repeat 與有界／越界 token window hints。對語意修改同步更新未消耗
的 lookahead，避免僅因旁邊 suffix 過時造成拒絕。正向新增合法
15-bit Huffman 碼及 600 個 0xff 的 Adler 溢回；產生器全部提交。

第 3.4.1 節對應上述 inflate 約束；Z12 元件容量拒絕保留。Z2 的 SHA
元件案例保留。尚不宣稱完成需要 PDF statement、lexer、公開輸入的
Z8/Z9/Z13 或整體 M3b。新的 hints 僅改本工作包尚未凍結的 private
witness 格式；沒有修改第 3.6 節 public ABI、Kotlin/Rust 或其他工作包
介面。正式串接仍由 Claude 決定。新增第三方元件：無。

分維度量測與完整容量結果見 `docs/research/p4-benchmarks.md` 的 Round 6
節及 `validation/m3b-round6-*.json`。每記號約 408 gates、每 byte
約 59.3–60.0 gates，區塊約 27.5 萬 gates，後者未達 20 萬。
區塊需驗證 19/288/32 三組最多 15 層 canonical prefix 與 320 個
可能的碼長位置；即使實際是 fixed/stored，私密 kind 仍讓每個槽
保有 dynamic 路徑的約束成本。以私密提示重用表、反轉碼及 packed
header 已降低成本；不能僅信任提示或略過表合法性來達標。

原 Round 5 每 byte 兩條 Merkle 路徑方案已被 Claude 否決。如後續
採分段，方向是每段對完整 32 KiB 視窗做一次 Poseidon2 sponge
承諾（打包後約 1,060 fields），段內使用不可變私密陣列；本輪沒有
實作或量測此架構。請 Claude 特別檢查明文歸納、prefix 初值／遞推、
packed window 範圍證明，以及完整成本估算能否支持單一電路。


最終dynamic probe：304,435 gates／156,770 opcodes；first/warm
11.99/11.91 s、877,116/876,796 KiB RSS；獨立verify 17.69 ms，
proof 16,256 bytes。實際hash在VERSIONS與
`validation/m3b-round6-inflate-probe.json`。完整容量編譯在112.50 s
觸及6 GiB RSS guard，沒有完整ACIR或prove量測；不能視為24 GiB
預算失敗。Gradle必要tasks成功，test-servers強制重跑362 tests、
0 failures/errors、29 skipped；native auto build因無cargo略過，
relay案例亦skipped。此輪沒有Rust變更。完整數據與限制均列於benchmark。

## Round 7: committed inflate segments

Integration base: `b2c412c`. `pdf_inflate_seg_v1` implements section 3.12.3,
reusing Round 6 `dynamic_tables`, `fixed_tables`, `checked_code`, `bits` and
`token_window`. The only change to their accepted language is the requested
`hdist <= 30`, with 31/32 rejection cases. No third-party circuit was added.

### Commitment encoding (review proposal, not a frozen PUBLIC_SPEC)

`commitment.nr` implements section 3.12.1 using the standard library's public
BN254 Poseidon2 permutation. beta.15's sponge type is crate-private, so the
wrapper reproduces its fixed-length sponge: width 4, rate 3, additive absorption,
IV `(field_count << 64)`, zero-fill final rate, output state[0], no variable-length
terminator. Preimage is `[tag, salt, number_of_fields, fields...]`. The two known
answers use the independent bb.js 2.1.9 `poseidon2Hash` API, called by
`tools/poseidon_reference.mjs`:

- tag=1, salt=42, fields=[0,1,2] ->
  `0x0e38abf00bd0aeb288ed74a01e99cec931b4904f6ba8aec4b9aa762107256dea`.
- tag=2, salt=42, fields=[] ->
  `0x2bea62b95fd366e7903877a49f491dcbb320cd4c7d1b26bb9ed8baa75a564cdf`.

Packing reads each group of at most 31 bytes as a big-endian integer. A short
last group is left-zero-padded (e.g. [1,2,3] -> 66051); it is not right-padded.
Every packed integer is below 2^248 and therefore below the BN254 scalar modulus.
The byte capacities are fixed per circuit. Encodings proposed for Claude review:

- C_z fields: `[actual_byte_length, pack31(z padded to MAX_COMPRESSED)...]`.
- C_p fields: `[segment_index, actual_byte_length, pack31(plain padded to SEG_PLAIN)...]`.
- Huffman fields: LL lengths[288], LL codes[288], DD lengths[32], DD codes[32].
- State fields in order: pos, output, tokens, blocks, phase, kind, final_block,
  table_commitment, pending_len, pending_dist, a, b, stored_end.
- Missing history commitments and the first S_in are constant Field zero.
  Missing history bytes are constrained zero. Existing history segments have
  length SEG_PLAIN and bind their actual absolute segment index.

The byte length prevents zero-extension collisions in byte encodings. All
unused compressed/plain bytes are zero. Salt=42 is used only in synthetic
fixtures; a production prover must generate a fresh private salt with at least
248 random bits for each evidence package. The circuit cannot prove randomness.

Public main parameters have exactly the section 3.12.3 order: ASCII domain and
circuit-name Fields, index/first/last, C_z/S_in/S_out/C_p, then oldest-to-newest
history commitments. The main constrains the ASCII constants and first==(i==0).
Parameter sets require separately pinned ACIR/VK; they are not interchangeable.
There is no lexical scan, anchor, claim, Rust/FFI or PUBLIC_SPEC change.

### Segment transition and composition argument

1. Every segment reopens C_z with the same private salt, actual data length and
   capacity-padded z. A collision-resistant commitment prevents changing z or
   its length/salt between valid proofs with the same C_z. The SHA content-window
   component computes this exact commitment over private window XOR public
   keystream after its existing head/tail/midstate checks.
2. The first segment forces the RFC zlib initial state and checks the header.
   Later segments reopen S_in; the verifier must match it to the previous
   S_out. The header/window limit is rechecked on every segment. Incoming output
   equals index*SEG_PLAIN; global output/token/block bounds remain 40960/6144/4.
3. Each started block has its header checked by the reused Round 6 routines.
   Flattened immutable LL/DD arrays are bound at every constant index. The
   incoming table is opened against the incoming state's table commitment;
   newly built tables are committed into the outgoing state. Header events
   must occur exactly at the state's bit cursor and only in header phase.
   Token events must occur exactly at the cursor and in body phase. Header
   slots and token slots cannot be skipped, duplicated or reordered. Inactive
   events are trailing slots; all their output intervals are empty.
4. Token bytes, widths, length/distance extras and endpoints use the original
   bounded integer window decomposition. Canonical symbol lookup, reserved
   distance rejection and the zlib window bound remain intact. Stored blocks
   retain the checked end position, consume exactly eight bits per literal,
   and can end only at that position. Huffman EOB enters header/done phase
   according to BFINAL. No further events can follow done.
5. At most one decoded copy crosses the segment's output boundary. Its full
   interval is checked against the compressed token, but only the segment's
   prefix is emitted. The outgoing state carries its exact remainder and
   distance. A following segment emits that remainder before decoding another
   token. No new nonempty token may start at/after the boundary. Pending copies
   spanning multiple small segments follow the same rule without redecoding.
6. Output intervals start with incoming pending copy, then consecutive event
   intervals. Every byte owner must lie in its nonempty interval. Read source
   `history || plain_advice` is constructed once and never written thereafter;
   all source indexing is bounded and every copy distance is positive and at
   most the already produced global output. Each referenced source byte is
   strictly earlier than the output byte. Historical openings match previous
   C_p values with their absolute indices. Induction over global output position
   therefore fixes every byte uniquely, including overlapping copies. Every
   current plain byte is bound at a constant index; padding is zero.
7. If n bytes are emitted, a'=a+sum(byte[k]),
   b'=b+n*a'-sum(k*byte[k]), with reduction modulo 65521 at the boundary.
   Incoming a,b<65521, n<=8192, so a'<2^22 and b'<2^35. No Field/u64 wrap is
   possible; the expression is nonnegative and is the Adler recurrence.
8. Non-final segments emit exactly SEG_PLAIN bytes and cannot be done. The last
   segment must be done, have no remaining copy, consume exactly the deflate
   bytes (except final byte padding), and match the four-byte Adler trailer.
   With the verifier's contiguous index, shared C_z, S_out/S_in and history C_p
   checks, induction on segments composes these transitions into the unique
   complete RFC inflate of the SHA-bound z. This argument assumes commitment
   collision resistance, proof soundness and a verifier enforcing every join.

All private-index reads target inputs, constants, projections, or arrays fully
constructed with constant indices before their first read. No array is written
after a private-index read. There is no unsafe/unconstrained acceptance helper.

### Specification details needing Claude's decision

The design file is deliberately unchanged:

- A stored block needs `stored_end` (or remaining stored bytes) in committed
  state; the listed state fields alone do not describe a mid-stored boundary.
- A final stored block has LEN bytes and no symbol 256. Finalization accepts its
  exact stored end as RFC 1951 requires; the textual EOB requirement needs this
  explicit exception.
- Fixed-size plain segments cannot generally also split at block starts. A
  parameter set with B=1 rejects a fixed-size interval containing more than one
  start. The regression profile uses B=3 for mixed blocks; production B=1 is
  suitable for the sample's single dynamic block. Changing to variable-size
  segments would also require redesigning the fixed W-segment history bound.
- Section 3.12 does not fully specify field serialization, missing commitments,
  domain/name Field encoding or byte padding/actual-length handling. The above
  explicit proposal needs approval before M3c interoperability/freeze.

`tools/segment_reference.py` emits synthetic per-segment Prover.toml files and
checks public joins, history openings and the complete result independently with
Python zlib. It is a reference witness generator, not a proof verifier. bb.js is
an existing MIT development dependency; NOTICE now describes this additional use.

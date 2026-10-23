# WP3b M3d handoff

工作包：WP3b M3d 合成測試文件產生器。
基準：整合分支 `39f28964870e2265d4e8de1bd31894f764b51ddc`；整合分支後續
`24f32af39d605c92ee3f038ced1263ddbff3c6ff` 只修改 zkTLS 規格說明，不影響本工作包。

完成的驗收條件：

- [x] 一頁、一個內容串流的仿在學證明：Word 類 BT/Tf/Tm/TJ/ET、WinAnsi 數字、Type0 中文與 ToUnicode、QR 影像。
- [x] 仿出入境記錄：Standard V2 R3、RC4 128 位元、空白使用者密碼，數字為 CID。
- [x] 固定的合成資料、時間、文件 ID、測試 PKI；獨立重建兩次的所有產物逐位元組一致。
- [x] PKI 由測試專用的公開種子產生，透過現有 `TestPki.create(directory)` 載入；不提交私鑰。
- [x] 重用 core 的 PAdES CMS 產生與自驗。所有 PDF 的 P3 簽章完整性為 PASS，簽章者等於測試 PKI。
- [x] `PdfTextExtractor.runs` 與合成預期一致，WP2 與 P3 文字結果一致；RC4 公開金鑰流還原原始壓縮資料。
- [x] BI、ActualText、解壓超過 40960 bytes、簽後增量更新修改第 1 頁四種負向文件。
- [x] 內嵌可再散布的 Noto 字型子集、完整 OFL、重建腳本與檔案用途 README；PDFBox 可繪製兩種正向文件。

驗證：

- `DIW_ZKPDF_WRITE_FIXTURES=1 ./gradlew :test-servers:test --tests '*SyntheticDocumentsTest'`：6 passed。
- 不設定寫入旗標，執行 `./gradlew :core:compileKotlinJvm :app:compileKotlinDesktop :test-servers:test`：建置成功，JUnit XML 合計 360 cases，331 passed、29 skipped、0 failed。六項新測試均實際執行。
- `nargo test`（Noir 1.0.0-beta.15，`native/circuits`）：既有 M3a 19 tests passed；沒有修改電路。
- Rust crate 與 Android 原始碼未修改；本工作包不涉及 `cargo test` 或 Android release 建置。
- 字型子集連續重建的 SHA-256 相同：`d0a4f69b5fc5e303313dd26ef711241626beec7e1de627252d9a940bbc615818`。

未完成或偏離規格：

- 無 M3d 功能缺項。這些 PDF 是 M3b/M3c/WP4 的測試輸入，不宣稱已完成電路或證明器驗收。
- 使用 PDFBox 的 external-signing 容器加上現有 `DocumentSigning.cms`：core 的 `signPdf` 會拒絕加密 PDF，且增量 writer 的第二個 ID 使用亂數，無法直接提供逐位元組可重現的產物。只在測試產生器處理，未改任何 P1-P3 行為。
- 原生 ZK 工具鏈未安裝，相關既有測試依專案的 auto 模式略過；不把略過當成通過。

介面變更提案：無。

新增第三方元件與授權：

- Noto Sans CJK SC Regular 2.004 子集：OFL-1.1，只在測試資料中，已更新 NOTICE。
- fontTools 4.61.1：MIT，只用於重建字型，非 App／原生 runtime 依賴。
- PDFBox、Bouncy Castle、TestPki 與 QR encoder 均沿用現有依賴。

發現的既有問題（未修改，交由對應工作包處理）：

- JUnit 回報 `ZkTemplatePackTest.signedPackRoundTrip` 與 `ZkTlsPlanTest.signedRequestRoundTrip` 回傳非 void，因此未被發現執行。這兩項不在 360 個已發現案例或 29 個 skipped 之中。
- main 分支環境驗證的 `documentVaultSignDeriveAndPresent` 傳入 `timestamp=false` 卻採用預設 PAdES B_T，會向 DigiCert TSA 連線。此為先前基準的觀察，未在本工作包改動 App 測試。

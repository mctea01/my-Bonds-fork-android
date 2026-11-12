# bbs-2023 測試向量

取自 W3C Data Integrity BBS Cryptosuites v1.0 編輯稿的 `TestVectors/` 目錄（https://w3c.github.io/vc-di-bbs/TestVectors/ ，CRD 2026-09-10 附錄 A 引用的同一批檔案），依 W3C Software and Document License 使用。`FeatureInputs/verifierInfo.json` 是假名範例使用的 nym_domain，規格正文的連結漏掉了這個檔案。

目錄對應附錄 A：`prc/` 為 A.1 基本範例（永久居留卡），根目錄為 A.2 進階範例（帆船），`HolderBinding/`、`Pseudonym/`、`PseudonymHB/` 為 A.3 到 A.5 的可選功能（駕照，共用 `HolderBinding/` 的轉換結果）。

向量與規格正文不一致之處（測試照向量實際內容核對）：`prCredUnsigned.json` 與 `prc/addSignedSDBase.json` 簽署的文件內容不同，基本範例以已簽文件去掉 proof 為輸入；假名範例的基本證明標頭都是 0x08、衍生證明都是 0x09，`signer_nym_entropy` 以 CBOR tag 2（bignum）編碼，衍生證明沒有 nym_domain（7 個元素）。

使用者：`native/diw-zk-ffi/src/bbs.rs` 的 Rust 測試（BBS 運算）與 `test-servers` 的 `Bbs2023Test`（JSON-LD、RDFC、選擇性揭露與完整的加簽、衍生、查驗）。

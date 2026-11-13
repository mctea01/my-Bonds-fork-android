# zkryptium（W3C bbs-2023 修補版）

來源：crates.io 的 [zkryptium 0.8.1](https://crates.io/crates/zkryptium/0.8.1)（Fondazione LINKS，Apache-2.0，授權全文見 `LICENSE`）。只保留 `src/` 的 BBS 部分（刪除 CL03 與範例、測試資料），`Cargo.toml` 改寫為只含 BBS 功能。

## 為什麼要修補

zkryptium 0.8.1 實作 CFRG `draft-irtf-cfrg-bbs-signatures-14`、`draft-irtf-cfrg-bbs-blind-signatures-02` 與 `draft-irtf-cfrg-bbs-per-verifier-linkability-03`。以 W3C Data Integrity BBS Cryptosuites v1.0（CRD 2026-09-10）附錄 A 的測試向量驗證：

- 基本簽章、衍生證明、匿名持有人綁定（blind）：原版即相符。
- 假名（pseudonym 與 holder binding + pseudonym）：不相符。W3C 規格引用 `draft-kalos-bbs-per-verifier-linkability-00`，與 Digital Bazaar `@digitalbazaar/bbs-signatures` 3.1.0（W3C 測試向量的產生端）一致；pvl-03 在 header 後加上 nym 向量長度，challenge 也改為涵蓋 context_id。

## 修補內容（只動 `src/bbsplus/pseudonym.rs`）

1. 四處 `combined_header = header || I2OSP(nym 向量長度, 8)` 改為只用 `header`（簽章、驗證與最終化、證明產生與驗證）。
2. `proof_with_nym_challenge_calculate`：challenge 輸入在 pseudonym 之後加入 `OP = hash_to_curve_g1(context_id, api_id)`，並移除結尾的 `I2OSP(length(context_id), 8) || context_id`。

修補後 `native/diw-zk-ffi` 的 `bbs_vectors` 測試以 W3C 全部測試向量（基本兩組、匿名持有人綁定、假名、持有人綁定加假名）驗證通過，包括由承諾值重現發行端簽章與 nym_secret。

CFRG 假名草案定案、W3C 規格更新引用版本後，改回上游版本並移除這個目錄。

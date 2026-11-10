# Barretenberg Windows GNU：公開 proof 驗證

第三輪日期：2026-11-10。沿用 [Windows GNU 連結 PoC](bb-windows-link-poc.md) 的固定 BB 6.0.0、Zig 0.15.1 與原 DIW bridge，新增純 C caller，在 Wine 10.0 **接受一份公開合成 UltraHonk proof，拒絕三種修改，且拒絕後仍可接受原 proof**。沒有修改正式來源或密碼學參數。

## Fixture 與信任邊界

使用專案既有 [ultrahonk.rs](../../../native/zkpdf-prover/tests/ultrahonk.rs) 指向的 `outer_count_4_disclose.json`，來源為固定 zkPassport commit `dae2129a0722e9391a4a243c6d53df0a134a74f8`。它標示 BB 6.0.0，SHA-256 為 `a7470d4c4e71a24da90cfed8ec026cae24d4c7adbbd6f905bfffecad5655067d`。

fixture 內的 circuits commit `1a1836eb958b7d7bbb47fab060128757748dba6a` 與同一上游 tree 的 submodule gitlink 相符。產生器使用虛構 MRZ 與測試簽章憑證；本輪只使用其 key、proof 與 public inputs，不把 disclosure 原文寫入研究記錄。固定下載連結、來源雜湊與 gitlink 證據見 [fixture-source.json](evidence/bb-windows-proof/fixture-source.json)。

**這是以 fixture 自帶 verification key 進行的密碼學一致性驗證。** 本輪未重新產生 proof／key，也未驗 registry 信任、錢包政策、資產認證或目前正式電路的 key 對應。不能據此宣告 zkPassport／zkPDF 端到端流程通過。

## 實測結果

runner 將 `vkeyFields`（115）、`proof`（458）、`publicInputs`（9）各元素編為 32-byte big-endian，生成 repo 外的 C header。C caller 呼叫原 `zkpdf_bb_init_verifier` 與 `zkpdf_bb_verify`；使用原 bridge 的 verifier-only CRS 常數，不下載完整 proving CRS。所有呼叫依序執行。

| 測試 | 結果 |
|---|---|
| 原始 key／proof／public inputs | 回傳 0，接受 |
| 第一個 public input 的最後一 byte XOR 1 | 回傳 1，拒絕 |
| proof 最後一 byte XOR 1 | 回傳 1，拒絕；不宣稱已分類後端的具體拒絕原因 |
| proof 截掉完整 32-byte field | 回傳 1，拒絕；長度仍對齊，超過前輪單純 field alignment 拒絕範圍 |
| 還原資料、重複初始化後再次驗證 | 回傳 0，接受 |

前輪 Blake2s、buffer ownership、MessagePack 與環境 hooks 測試同時重跑通過。完整 39 個命令、exit code、來源／產物雜湊見 [result.json](evidence/bb-windows-proof/result.json)，proof 執行輸出見 [diw-proof-wine.log](evidence/bb-windows-proof/diw-proof-wine.log)。PE、fixture 與產生的 header 留在 repo 外。

## 重現方式

依[前輪工具準備](bb-windows-link-poc.md#重現方式)取得相同來源與 Zig／Wine，下載 [固定 fixture](https://raw.githubusercontent.com/zkpassport/zkpassport-packages/dae2129a0722e9391a4a243c6d53df0a134a74f8/packages/aztec/test-harness/fixtures/outer_count_4_disclose.json)。在相同 runner 命令加入：

```sh
  --proof-fixture /external/outer_count_4_disclose.json
```

仍需新的空白 `--out` 目錄。runner 在編譯前驗證 fixture hash、版本與 field count／encoding；不符合時失敗，不接受任意下載的 key/proof。省略 `--proof-fixture` 保留原本的 ABI smoke；省略 `--wine` 僅連結，proof 狀態仍為 `not-tested`。

[交付檢查](evidence/bb-windows-proof/validation.json) 包含所有輸入／產物雜湊、序列化與合成修改、錯誤 fixture 拒絕、文件／矩陣及正式檔案未變更。前輪暫存 archive 已重新下載並核對原 digest；本次證據使用持久工作目錄的副本。

## 下一個缺口

尚未執行原生 Windows、最低 CPU／OS／CRT、prover、BB 全庫重建、跨架構雙向證明驗證、DLL／MSVC host、Rust wrapper 或完整 App 流程。本輪把單一 fixture 的正反向驗證加入 `smoke-tested` 範圍，不升格為完整功能／平台支援。下一步可先建立 C DLL 與 host 邊界實驗，或在有原生 Windows runner 時重跑同一固定案例；完整 prover／跨架構互通仍需另外的可重現證據。

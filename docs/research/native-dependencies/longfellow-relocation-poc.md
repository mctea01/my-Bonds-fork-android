# Longfellow：移除舊版電路的來源目錄依賴

日期：2026-11-10。本輪延續 [Windows DLL PoC](longfellow-windows-poc.md)，先重現 v5–v7 電路載入依賴編譯時來源目錄的問題，再以隔離 patch 嵌入原始 LFA2 bytes。**來源 checkout 暫時移開時，舊 DLL 因缺檔 panic；新 DLL 可配置並逐 byte 比對全部 12 份舊版電路，也通過既有公開 proof 正反向測試。** 實測仍在 Linux 的 Wine，沒有修改正式產品。

## 修補與成本

[嵌入 patch](../../../tools/native-research/longfellow-embedded-assets.patch) 只改固定 Longfellow `mdoc-zk-artifacts/src/lib.rs` 的 `load_circuit_lfa2`：將磁碟檔案查找改為 12 個固定 hash 對應 `include_bytes!`，再回傳與原介面相同的 `Vec<u8>`。未知 hash 仍 panic；公開 C API 的不支援 spec 由 provider 先回傳錯誤，本輪另驗 version 999 回傳 4，且不配置輸出。

這 12 份檔案涵蓋版本 5、6、7，每版 1–4 attributes。[資產清單](../../../tools/native-research/longfellow-embedded-assets.json) 分開保存 spec hash、實際檔案 SHA-256 與長度，全部與固定 git commit 的原始 bytes 一致。沒有重新編譯電路、改 key／proof 格式或更換演算法。前輪六份 manifest 的 Windows SHA-2 patch 與研究 Cargo.lock 沿用不變。

| 項目 | 大小 |
|---|---:|
| 12 份原始壓縮資產合計 | 5,211,704 bytes |
| 前輪 DLL | 2,801,664 bytes |
| 嵌入後 DLL | 8,010,240 bytes |

這以約 5 MB 的 DLL 增量換取舊版電路不需另外部署檔案；DLL 配置時仍會複製 bytes 並解析 archive，本輪沒有量測效能或記憶體峰值。LFA1、測試 witness／proof 檔案讀取函式沒有改動；current-version 電路生成也沒有改動或驗收。不是宣稱整個 upstream crate 都不再存取檔案。

## 對照方法與結果

runner 先核對兩份建置報告、DLL／caller 雜湊、固定來源與兩份 patch，再將 DLL 和 caller 複製至新的輸出目錄。參考電路與公開 proof 另複製至測試目錄，只供 C caller 比對／驗證。隨後把專用研究 checkout 暫時改名，確認原編譯路徑不存在；所有測試完成或失敗後都以 `finally` 還原。沒有刪除來源或修改 Wine 的磁碟 mapping。

| 案例 | 結果 |
|---|---|
| 前輪 DLL，同一個 C caller，原來源路徑不存在 | 非零結束；錯誤明確為 `Failed to read lfa2 archive file`，是預期的失敗對照 |
| 新 DLL，v5–v7 × 1–4 attributes | 12 次成功配置、與釘選檔逐 byte 相同、以同庫 free 釋放 |
| 新 DLL，不支援的 spec | 錯誤碼 4；pointer／length 仍為 null／0 |
| 新 DLL，v7／1 公開 proof | 接受原 proof；拒絕修改 attribute、transcript、proof；還原後再次接受 |
| 檔案恢復 | 原來源路徑恢復，臨時隱藏路徑消失；來源差異仍僅兩份研究 patch |

建置記錄見 [build/result.json](evidence/longfellow-relocation/build/result.json)，搬移對照見 [relocation/result.json](evidence/longfellow-relocation/relocation/result.json)、[原版失敗](evidence/longfellow-relocation/relocation/baseline-missing-source.log)、[12 份電路](evidence/longfellow-relocation/relocation/all-assets-relocated.log)、[proof 測試](evidence/longfellow-relocation/relocation/proof-relocated.log)。預期失敗不能混列為全部命令成功；報告保留實際 exit code。

## 重現

依[前輪步驟](longfellow-windows-poc.md#重現)先產生只有 SHA-2 patch 的 baseline build，保存整個輸出目錄及 result.json。使用同一個專用 repo 外 checkout，再套用嵌入 patch：

```sh
git -C /external/multipaz/multipaz-longfellow/rust/longfellow-zk apply --unidiff-zero \
  /research-repo/tools/native-research/longfellow-embedded-assets.patch
```

在原 `probe_longfellow_windows.py` 命令加入 `--embed-assets`，選另一個空白 `--out /external/embedded`，保留 `--wine` 及必要的 Wine 設定。此模式同時檢查兩份 patch 與 12 份資產 hash。然後執行：

```sh
python3 tools/native-research/probe_longfellow_relocation.py \
  --build-dir /external/embedded \
  --baseline-dir /external/baseline \
  --out /external/new-empty-relocation
```

此工具會暫時改名建置報告指向的來源 checkout，僅用於專用研究副本，期間不可有其他 build 使用該目錄；build／baseline／output／Wine prefix 都必須在來源 checkout 外。兩份 DLL 必須從同一路徑建置，baseline 不得已包含嵌入 patch。被中斷後若留下 `<source>.relocation-hidden`，先確認程序已停止並還原來源，再繼續，不覆寫該目錄。

[交付檢查](evidence/longfellow-relocation/validation.json) 確認所有資產 bytes、兩份 patch 範圍、DLL 與記錄雜湊、來源已還原及錯誤輸入拒絕。正式部署仍需授權／打包審查、原生 Windows 與最低 OS／CPU 驗證；MSVC host、prover、current-version 電路、跨架構雙向 proof 與完整錢包流程仍未測。

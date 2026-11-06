# TWDIW 1.0.14 四個金鑰資產的用途核對

日期：2026-11-03。依已核對官方簽章的 base APK、stage-b DEX `4bac5eefe40ec027a39b9f8e38261d1cec34edd41c110fda1815c84538ed0e2d` 與 Dart AOT 分析，不讀取或解出官方私鑰。檔名相近不足以證實兩組數學上的公私鑰配對。

## 已確認的用途

| 資產 | 目前可確認的行為 | 證據界線 |
|---|---|---|
| `dwapp201i_private.txt` | `dwapp-201i` 應用 JWS 的私鑰來源：asset reader → Base64 → PKCS#8 EC → SHA256withECDSA | 已確認讀取與簽署呼叫鏈；未解出私鑰、未完成與公鑰的數學配對驗證 |
| `dwapp201i_public.txt` | 公鑰 reader 正規化文字的 SHA-256 填入七欄 payload 的 keyId | 雙層解碼及公鑰格式已重現；VM 成功路徑的第六參數已對到此 reader |
| `dwapp201i_private` | 已確認有獨立資產及共用資產 reader 的映射 | 尚未找到將它綁到具體功能的成功呼叫鏈，不能斷言是舊版、備援、測試或防逆向誘餌 |
| `dwapp201i_public` | 已解成另一把不同的 P-256 公鑰 | 不是 `.txt` 公鑰的副本；尚未證明具體功能或與無副檔名 private 的配對 |

`dwapp-201i` 的已追蹤成功路徑使用 `.txt` reader，不能將無副檔名資產互換放入此路徑。另一方面，未找到無副檔名資產的消費者，也不足以證明它在完整 App 的所有分支均未使用。

## 呼叫鏈與名稱核對

Dart `Utils.callDwapp201i`（`0x2c143c`）由 `did_sdk_channel` 呼叫 `dwapp-201i`。Android `N3Kf59pP` 的相應 handler 使用：

- stage-b DEX file offset `0x0b2a5c`：呼叫 PrivateKey getter 的橋接；`0x0e0e40` 再轉入 getter。
- `zAKsgAGv(Object[])`：開啟私鑰資產，外層 reader 固定 seed 與 `.txt` 私鑰的資產映射一致；後續匯入 EC PKCS#8。
- `Qv6H7VWA()`：開啟公鑰資產，外層 reader 固定 seed 與 `.txt` 公鑰的資產映射一致；後續正規化文字及雜湊。
- VM 成功路徑六參數 payload 建構子位於 `0x0b2896`，第六參數對應上述公鑰 reader 結果。

`N3Kf59pP.c(short,int,byte,Object[])` 的字串解碼器可離線還原以下名稱：

| 參數 | 結果 |
|---|---|
| `(17,3,-1)` | `dwapp201i_private.txt` |
| `(16,3,53)` | `dwapp201i_public.txt` |
| `(13,3,-1)` | `dwapp201i_private` |
| `(12,3,53)` | `dwapp201i_public` |

後兩個參數組合只證明字串表可產生該名稱，不是已找到呼叫者。`JcPQWBA` 對四個檔案都有 reader 映射，映射本身也不能證明某個業務功能實際呼叫它。

已比對的公開 OSS App／SDK 未提供可綁定這些名稱的新契約；在本次 AOT 常數池中確認的是 `dwapp-201i`，未找到 `diwapp-200i`。新專案因此採用明確的 `TWDIW_APP_PRIVATE_KEY`／`TWDIW_APP_PUBLIC_KEY` 設定，不猜測第二組專用環境或另一個方法名稱。

## 公鑰指紋

摘要對象為去空白後的 Base64 SPKI 文字 UTF-8 bytes：

| 檔案 | SHA-256 |
|---|---|
| 無副檔名 public | `38bbe4d0eef0b2616b0cb84f93c06a05fe94f8b623e4f09c403922f7a8e36ee7` |
| `.txt` public | `dfbbc7e88f69844fe449aca4f02ce1d719ddaaad9e3fd9dc25f1934869bc5a82` |

新專案不內建上列官方資產或指紋作為自身應用身分；建置配對的 keyId 由本次自有公鑰重新計算。

完整 reader／DTO 證據見 [領卡附件核對](twdiw-1.0.14-issuance-review.md)、[資產解碼說明](twdiw-1.0.14-asset-decoding-guide.md) 與 [新版領卡實作驗收](../acceptance/twdiw-application-signature.md)。本輪名稱與用途核對結果另存 `/workspace/scratch/twdiw-asset-key-usage.json`，不含金鑰內容。

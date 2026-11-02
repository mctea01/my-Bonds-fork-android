# TWDIW 格式 JWS 本機建立（2026-11-02）

已依研究格式完成可執行的 [簽署與驗證工具](../../tools/twdiw-jws/README.md)，並產生一份實際 Compact JWS。本次用新產生的本機 P-256 測試金鑰、自有測試 App ID `diw.local.test`、版本 `0.1.0-local`、合成 nonce 與測試 body；沒有讀取或重用官方私鑰，也沒有向官方服務發送請求。

## 結果與檔案

本機範例位於 `/workspace/scratch/twdiw-jws-demo/`：

- `signature.jws`：實際三段式 JWS。
- `decoded.json`：Header 與七欄 Payload。
- `request-body.json`：被簽章綁定的原始 body bytes。
- `public.pem`：測試公鑰。
- `context.json`、`verification.json`：本機測試身分／nonce／時間與驗簽結果。
- `signing-input.bin`、`signature.der`：供 OpenSSL 獨立驗簽的資料。

Header 的精確 JSON 為 `{"alg":"ES256","typ":"JWT"}`。Payload 中 appHash 使用應用 ID 原文、appPlatform 為 `Android`、bodyHash 綁原始 bytes、keyId 綁該測試金鑰的正規化 Base64 SPKI 文字，timestamp 為毫秒字串；簽章段解碼長度為 64 bytes。完整 body、nonce、時間與 keyId 由輸出檔保留，不在文件中固定為可用的正式請求參數。

## 驗證證據

5 項 Python 測試通過，其中包含獨立由 wire JWS 取 signing input、手動把 R／S 編成 ASN.1 DER，再呼叫 OpenSSL 驗簽。對這次實際輸出的範例另直接執行 `openssl dgst -sha256 -verify ...`，回傳 `Verified OK`。

修改 body 的尾端換行、nonce、payload、signature 或改用其他公鑰，均在相應測試中遭拒絕。工具拒絕錯誤曲線與額外 Header.kid；demo 產生的私鑰檔案權限為 0600，存於 scratch，不提交 repo 或放入交接包。

此結果證明本機範例的 wire 格式、簽章及 request context 綁定。它沒有證明測試身分或測試金鑰被官方接受；合成 nonce 也不具官方有效性。服務端准入、正式 nonce 的時效及實際領卡仍未驗收。本工具獨立於現有 App 流程，沒有因此宣稱 App 的推測性 `/api/did/` 註冊已修正。

## 重現

```bash
python -m unittest discover -s tools/twdiw-jws -p 'test_*.py' -v
python tools/twdiw-jws/twdiw_jws.py demo --out /tmp/new-twdiw-jws-demo
```

本次範例與工具的精簡包位於 `/workspace/scratch/twdiw-jws-local-example.zip`，包含測試 JWS、公鑰、body、解碼與驗證紀錄，以及工具原始碼；不含任何私鑰。可重新執行 demo 建立另一把測試金鑰與新範例，ECDSA 的完整 JWS 不要求逐位元組等同先前輸出。

格式證據來源見 [領卡與簽章附件核對](twdiw-1.0.14-issuance-review.md) 與 [native helper 模擬驗證](twdiw-native-helper-emulation.md)。

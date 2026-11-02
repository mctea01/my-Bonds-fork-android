# TWDIW Android JWS 本機簽署與驗證

依 1.0.14 研究結果建立 Compact JWS，使用呼叫者提供的 P-256 應用金鑰。工具不連網、不解析官方 APK 或金鑰資產；`demo` 會產生一把新的測試金鑰、自有測試 App ID 與合成 nonce。

## 已實作格式

- Header：`{"alg":"ES256","typ":"JWT"}`。
- Payload 七欄依序為 appHash、appPlatform、appVersion、bodyHash、keyId、nonce、timestamp，全部是字串。
- appHash 為呼叫者提供的應用 ID 原始字串；Android profile 的 appPlatform 為 `Android`。
- bodyHash 為原始 body bytes 的 SHA-256 小寫 hex；讀取檔案後不重新排版 JSON，也不移除尾端換行。
- keyId 為該金鑰 SPKI DER 的標準 Base64 文字（無 PEM 標籤、無空白）的 UTF-8 SHA-256 小寫 hex；不是 DER bytes 的雜湊。
- timestamp 為 Unix 毫秒字串；簽章為 SHA256withECDSA，再由 DER 轉固定 32-byte R 加 32-byte S，最後做無 padding 的 Base64URL。

使用已授權的應用金鑰與身分，才可能進一步驗收伺服器准入。新產生的測試金鑰、合成 nonce 與 App ID 並未向官方登記；本機驗簽成功不表示官方會接受。

## 安裝及本機範例

```bash
python -m pip install -r tools/twdiw-jws/requirements.txt
python tools/twdiw-jws/twdiw_jws.py demo --out /tmp/twdiw-jws-demo
```

目錄必須尚未含同名輸出檔，避免覆寫現有金鑰。範例包含 `signature.jws`、`decoded.json`、`request-body.json`、`public.pem`、`context.json`、`verification.json`，以及獨立驗簽使用的 `signature.der`、`signing-input.bin`。新產生的 `test-private.pem` 以 0600 權限建立，只供本機重現。

可另外以 OpenSSL 驗證：

```bash
openssl dgst -sha256 \
  -verify /tmp/twdiw-jws-demo/public.pem \
  -signature /tmp/twdiw-jws-demo/signature.der \
  /tmp/twdiw-jws-demo/signing-input.bin
```

## 使用呼叫者自己的金鑰

以下 nonce／時間／身分是命令用法示意，實際請求應帶對應伺服器核發的 ecosystem nonce、實際時間及獲授權的應用身分。這不是 OID4VCI holder proof JWT 的簽署工具，兩種 nonce 與金鑰用途須分開。

```bash
python tools/twdiw-jws/twdiw_jws.py sign \
  --body request-body.json --key application-private.pem \
  --app-id my.wallet.package --app-version 1.0 \
  --nonce server-issued-ecosystem-nonce --timestamp-ms 1793664000123 \
  > signature.jws

python tools/twdiw-jws/twdiw_jws.py verify \
  --jws signature.jws --body request-body.json --key application-public.pem \
  --app-id my.wallet.package --app-version 1.0 \
  --nonce server-issued-ecosystem-nonce
```

sign 讀取未加密的 P-256 PEM 私鑰，verify 讀取 PEM 公鑰。verify 會檢查簽章、Header、七欄結構與順序、platform、bodyHash、keyId、nonce 及應用身分；它不查驗伺服器 nonce 是否有效、時間新鮮度或官方授權狀態。

## 驗證

```bash
python -m unittest discover -s tools/twdiw-jws -p 'test_*.py' -v
```

涵蓋原始 bytes 綁定、文字公鑰指紋與 DER 指紋的區分、錯誤 key／nonce／body 拒絕、payload／signature 竄改、P-256 限制、Header.kid 拒絕，以及獨立由 JWS 段重組 DER 後以 OpenSSL 驗簽。OpenSSL 未安裝時，該項外部驗證會顯示 skipped。

本工具維持獨立的離線 CLI；App 的 `TwdiwDialect` 已另外採用相同的簽章契約並移除推測性註冊，見 [新版領卡驗收](../../docs/acceptance/twdiw-application-signature.md)。本工具早期驗證結果見 [本機 JWS 建立結果](../../docs/research/twdiw-jws-local-generation.md)。

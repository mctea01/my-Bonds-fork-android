# 全專案 Review 後續（2026-10-29）

性質：紀錄。來源是外部 Agent 的全專案 Review 報告（使用者 2026-10-29 提供）。每一項都先對照當時的程式碼查證，再決定處理方式。所有項目都已處理完；還沒做的部分列在最後一節，並同步在 [專案現況](../STATUS.md#4-未完成與待決定)。各項原本的規劃內容已移除，需要時看 git 歷史。

## 查證結果

| 報告項目 | 查證 | 處理 |
|---|---|---|
| OpenID Federation 不支援 | 屬實 | B5，已實作 |
| JWE 要求物件無法解密 | 已過時：PR #11 起 `Oid4vpHolder` 有解密金鑰登錄的程式路徑；App 沒有登錄金鑰，所以實際上拒絕加密的要求物件 | 列為未完成 |
| `withHashAlgorithm` 補償 | 屬實，為相容 Multipaz 回應格式的刻意補償 | 無 |
| TrustManager 只接受 EC | 部分屬實：RSA 憑證鏈由 PKIX 驗證補上，結果正確 | 無 |
| SD-JWT VC 一定要 nbf | 錢包端找不到要求 nbf 的路徑；限制在 Multipaz 查驗端（ISO 回應內的 SD-JWT VC） | 無 |
| Twdiw-Signature 未實作 | 當時只有推測的流程 | 2026-11-03 依 1.0.14 的證據重做 |
| `.en`、`.esw` 不支援 | 屬實 | B6，已實作讀取 |
| CI Action 未釘選、下載檔未驗證 | 屬實 | A1，已修正 |
| 依賴 CVE | 見 A4 | A4，已處理 |

## A. 修正

1. **CI 供應鏈**：第三方 Action 全部釘 commit SHA，直接下載的執行檔加 SHA-256 驗證。依賴更新由 Renovate 開 PR，minor 與 patch 在發布滿三天且 CI 通過後自動 Squash 合併；major、Kotlin、Compose、AGP、Multipaz、Ktor、Credential Manager 與 DC API 需人工核准。
2. **Multipaz 測試發證端（issuer.multipaz.org）**：伺服器只信任 Multipaz 自己的用戶端金鑰，第三方錢包都會在 PAR 被拒。新增預設關閉的「Multipaz 測試身分」（設定 > 開發者與測試），只在測試環境、只對該主機使用 Multipaz TestApp 公開的測試金鑰。
3. **用戶端驗證與 DPoP 顯示**：每張卡記錄 token 端點的用戶端驗證方式與存取權杖類型並顯示在詳細資訊頁。同時修正兩個 Credo（Animo）互通問題：AS 中繼資料沒列驗證方法時也送錢包證明；proof 有 `key_attestation` 時一併放 `jwk`。
4. **依賴 CVE**（OSV，2026-10-29）：App 本體沒有命中。Netty（只用於測試伺服器與自架主機工具）以 BOM 釘到已修正的版本。原生 Rust crate 沒有高風險命中，幾個中低風險項目等上游升級。

## 各項結果

| 項目 | 結果 | 測試 |
|---|---|---|
| TWDIW 應用簽章 | 改用獨立的應用金鑰照 1.0.14 的格式簽章，停用推測性的手機註冊與持有者金鑰退回；保留沒有應用簽章擴充的舊端點。官方平台是否接受未驗收。見 [驗收紀錄](../acceptance/twdiw-application-signature.md) 與 [1.0.14 分析](../research/twdiw-1.0.14/README.md) | `TwdiwEcosystemSignatureTest`、`TwdiwPlatformTest` |
| B5 OpenID Federation 1.0 | `core/federation`：信任鏈建立與驗證、`trust_chain` 標頭、constraints、metadata policy、`signed_jwks_uri`／`jwks_uri`、Trust Mark；查驗方的 `openid_federation:` 請求與發證端中繼資料都走聯邦；「自訂信任」可加入 Trust Anchor | `FederationTest` |
| B6 電子公文 `.en`、`.esw` | 依規範的 DTD 讀取信封檔、加密交換表單與交換確認訊息，結構化預覽；信封檔的雜湊當作公文容器的強證據。`.esw` 不解密（規範未指定對稱演算法） | `ExchangeFilesTest` |
| B7 NFC 近距離實機測試 | 測試項目 N1 至 N7 寫入 [實機測試清單](../research/device-test-checklist.md)；設定加上「NFC 靜態交握」開關 | 等兩支手機實測 |
| C8 PIV 簽章 | 自行實作 PIV APDU（`document/card/PivCard`），任何 PIV 卡皆可，NFC、USB CCID 與 PC/SC；簽署畫面列出各槽憑證，支援 RSA-2048 與 P-256 | 沒有自動測試，等實機驗收 |
| C9 匯出直接分享 | 文件、文件與證據、公文容器、OpenCerts 附件與身分證卡都可分享（Android） | |
| C10 CSC 補全 | PAR、非同步 `signHash`（`signPolling`）、`signDoc`、服務的時戳、`info` 的格式與層級、CSC Profile 匯入 | `CscSigningTest` |
| C11 C2PA 與 CAWG | 純 Kotlin 讀取與驗證 JPEG、PNG、WebP 與 sidecar；簽署者以 `TrustRole.CONTENT` 與內建的 C2PA 信任清單判定 | `C2paTest` |
| C12 PDF 可見簽章 | 檢視時在頁面上框出簽章位置；簽署時可選頁面、位置與圖片 | `PdfSignaturePlacementTest`、`DocumentSigningTest` |
| C13 付款交易 | 登錄 EUDI TS12 的 `urn:eudi:sca:payment:1`，同意畫面列出交易內容，KB-JWT 綁定交易資料 | `paymentTransactionIsDescribedAndBound` |

## 沒有做的部分

- TrustRegistry 層的統一聯邦錨點類型：目前在 federation 模組內以相同的等級規則判定。
- CSC 的 `authorization_details`（RFC 9396）。
- C2PA：BMFF（影片、HEIC）、PDF 內嵌 manifest、`c2pa.hash.boxes`、身分彙整服務的簽章驗證、寫入。
- `.esw` 解密，以及用真實的 `.en`、`.esw` 樣本比對。
- France Identité：playground 需要錢包先完成合作夥伴登錄，協定本身都已具備；是否申請由使用者決定。
- 實機驗收：NFC 兩機互通、PIV 與 YubiKey、分享到常用 App、付款測試卡加真實查驗端。

# P5 驗證者透明與主動驗證：設計與約定

撰寫日期：2026-11-15。性質：現行設計。各項目的實作狀態只記在 [STATUS.md](../STATUS.md)，本文寫約定與理由。研究來源是 [zkp-verifier.md](../research/zkp-verifier.md) 第 2、3 節與 [architecture-and-roadmap.md](architecture-and-roadmap.md) 的「驗證者身分、代表身分與目的」「主動驗證能力」「判定模型」三節。

## 1. 範圍與驗收

P5 讓錢包同時做好兩件事：

1. **持卡人看得懂查驗方是誰。** 出示同意畫面列出查驗方的身分類型（個人、法人、代表法人的個人、代表個人的個人）、名稱與識別碼、代表誰、目的、法律依據、保存期間、隱私權政策，以及每一項證據的查驗結果；請求超出查驗方聲明或註冊範圍的欄位逐項標示。
2. **錢包本身可以當查驗方，並帶著自己的身分。** 查驗分頁的「以誰的身分查驗」建立查驗方身分；「線上查驗（OpenID4VP）」以這個身分簽出請求、收回應並逐項判定；近距離查驗（ISO 18013-5）同樣帶上身分。衍生憑證與零知識證明有明確的查驗政策。

驗收：兩台裝置互為持有者與查驗方，持有端顯示查驗方的身分、代表關係與目的，查驗端逐項顯示結果。自動測試以兩個桌面錢包在 `test-servers` 跑完整流程；實機項目加入 [device-test-checklist.md](../research/device-test-checklist.md)。

不在範圍：iOS（P6）、EUDI 正式 Registrar 與 Access CA 的申請（外部條件）、以零知識證明隱藏查驗人員姓名（第 9 節說明原因）。

## 2. 決定

| # | 問題 | 決定 |
|---|---|---|
| E1 | 手機當查驗方時回應走哪裡（2026-11-15 使用者決定） | 正式服務端轉送加區網直連並存。經服務端時回應網址是 https，任何標準皮夾都能出示，服務端只保存加密的回應；兩台本錢包在同一區網時不經伺服器 |
| E2 | 標準與自訂的分界 | 標準路徑優先且一定保留：client_id 前綴（`x509_hash`、`decentralized_identifier` 等）、`verifier_info` 的 `registration_cert`（ETSI TS 119 475 WRPRC）、ISO 18013-5 reader authentication 與 `requestInfo["euWrprc"]`。本專案的「查驗方聲明」與「授權書」是自訂格式，放在 `core/verifier/declaration`，其他皮夾會忽略，缺少時不影響標準判定 |
| E3 | 查驗方的簽章金鑰 | 預設為每個查驗方身分一把錢包金鑰（`did:key`，`decentralized_identifier`）；可改用使用者的 X.509 憑證（`x509_hash`，PKCS#12、系統金鑰、PKCS#11、自然人憑證或工商憑證卡、PIV），沿用文件簽署的 `DocumentSigner` |
| E4 | 證據優先順序 | 依架構文件：查驗方自己的憑證出示（法人、代理、員工）、WRPRC、X.509 存取憑證、OpenID Federation、did:web 加 Linked Domains、未經證實的自我聲明 |
| E5 | 代表關係 | 有標準憑證時用標準憑證（EUDI `urn:eu.europa.ec.eudi:por:1` 代理權憑證、LPID）；台灣沒有對應的標準，另以本專案的「授權書」（被代表者以自己的 X.509 憑證或 DID 簽署）補足，為可選實作 |
| E6 | 判定呈現 | 沿用 T1 至 T4 與 `RiskConfirmDialog`；查驗方身分的等級取「請求簽章」「聲明」「各項證據」中最低者，部分通過不得看起來像通過 |

## 3. 查驗方身分（以誰的身分查驗）

查驗方身分（`VerifierProfile`）存在錢包內，可以有多個：

| 欄位 | 說明 |
|---|---|
| 身分類型 | `natural_person`（個人）、`legal_person`（法人）、`natural_person_for_legal_person`（代表法人的個人）、`natural_person_for_natural_person`（代表個人的個人） |
| 當事人 `party` | 資料實際交給誰：名稱、識別碼（`scheme` 為 `TW-UBN` 統一編號、`EUID`、`LEI`、`TW-ID` 身分證統一編號只顯示遮蔽值、或其他）、是否公部門 |
| 經辦人 `agent` | 代表當事人操作的自然人：名稱、職稱；只在代表類型出現 |
| 簽章 | `did:key`（錢包金鑰，HolderIdentities 的 `verifier:<id>`）或 X.509 簽署者 |
| 註冊憑證 | 使用者匯入的 WRPRC（`rc-wrp+jwt`），原樣放進每個請求 |
| 證據憑證 | 錢包中持有的證件與要揭露的欄位；每次請求以本次 nonce 重新出示 |
| 授權書 | 匯入或在錢包中簽出的授權書（第 5 節） |
| 目的範本 | 常用目的的文字、法律依據、保存期間、隱私權政策網址與要請求的欄位 |

## 4. 查驗方聲明（verifier_info）

### 4.1 格式

`verifier_info` 元素：`{"format": "urn:diw-wallet:verifier-declaration:1", "data": "<JWS>"}`，不帶 `credential_ids`（聲明涵蓋整個請求）。JWS 的 `typ` 為 `diw-verifier-declaration+jwt`，以簽請求物件的同一把金鑰簽署（X.509 時帶相同的 `x5c`，DID 時帶相同的 `kid`）。

```jsonc
{
  "iss": "<完整 client_id，含前綴>",
  "nonce": "<請求的 nonce；ISO 18013-5 為 base64url(SHA-256(SessionTranscript))>",
  "iat": 0, "exp": 0,                       // 有效期間不超過 10 分鐘
  "kind": "natural_person_for_legal_person",
  "party": {"type": "legal", "name": "...", "id": {"scheme": "TW-UBN", "value": "..."}, "public_body": false},
  "agent": {"name": "...", "role": "..."},
  "purpose": {
    "text": [{"lang": "zh-TW", "value": "..."}],
    "legal_basis": "consent | contract | legal_obligation | public_task | vital_interest | legitimate_interest",
    "retention": "none | P30D（ISO 8601 期間）",
    "privacy_policy": "https://..."
  },
  "credentials": [ /* 與 WRPRC 的 credentials 相同結構：format、meta、claim[].path */ ],
  "evidence": [
    {"type": "presentation", "role": "party | agent", "query": { /* 一個 DCQL credential query */ }, "vp_token": { /* 以 query id 為鍵 */ }},
    {"type": "mandate", "jws": "<授權書>"}
  ]
}
```

### 4.2 持有端的檢查（`VerifierDeclarationCheck`）

1. 簽章金鑰等於請求的簽章金鑰（x5c 葉憑證或 DID 金鑰），`iss` 等於請求的 client_id，`nonce` 等於請求的 nonce，未過期。任一不符即判定無效（不採用聲明內容）。
2. 每一份證據出示以 `PresentationVerifier.verifyEvidence` 驗證：KB-JWT 或 VP 的 `aud` 為 `iss`、`nonce` 為請求的 nonce；mdoc 的 SessionTranscript 為 OpenID4VP 交握（client_id、nonce、無加密金鑰、`response_uri` 固定為 `urn:diw-wallet:verifier-evidence`）。發行端信任、有效期與狀態照一般查驗。
3. 一致性：
   - `party.id` 與 X.509 存取憑證的 organizationIdentifier、WRPRC 的 `sub`、授權書的被代表者、`role=party` 證據中的識別碼欄位比對，不同即標示。
   - `agent.name` 與 `role=agent` 證據中的姓名欄位比對；沒有可比對的欄位時只列出，不判定。
   - 授權書的受託人必須是本次請求的簽章金鑰（或其 DID），範圍必須涵蓋本次目的與請求的證件。
   - 實際的 DCQL 必須落在聲明的 `credentials` 內，有 WRPRC 時也要落在 WRPRC 的範圍內，超出的欄位逐項列出（沿用 `VerifierInfoChecker.outside`）。
4. 結果 `VerifierIdentity`：類型、當事人、經辦人、目的、每一項證據的結果與整體等級（第 2 節 E6）。同意畫面以 `VerifierDeclarationCard` 呈現，聲明無效時與無效的 WRPRC 一樣需要勾選確認後才能繼續。

識別碼的比對欄位：`TW-UBN` 對應工商憑證主體的 `serialNumber` 與 organizationIdentifier 的 `NTRTW-` 前綴值；`EUID`、`LEI` 對應 organizationIdentifier（ETSI EN 319 412-1 的 `LEIXG-` 等前綴）與 LPID 的 `legal_person_id`；證據中的姓名欄位依序找 `name`、`given_name` 與 `family_name`、TWDIW 的 `name`／`姓名`。

## 5. 授權書（代表關係）

`typ` 為 `diw-verifier-mandate+jwt`，由被代表者簽署：法人以工商憑證或其他 X.509 憑證（`x5c`），個人以自然人憑證或錢包的 DID。

```jsonc
{
  "iss": "<被代表者：x509 主體識別碼或 DID>",
  "principal": {"type": "legal | natural", "name": "...", "id": {"scheme": "...", "value": "..."}},
  "agent": {"name": "...", "key": "<受託金鑰的 JWK 指紋（RFC 7638）或 DID>"},
  "scope": {"purposes": ["..."], "credentials": [ /* 同 4.1 */ ]},
  "iat": 0, "nbf": 0, "exp": 0              // 最長一年
}
```

持有端檢查簽章與簽署者信任（`TrustRegistry.decide` 或 `DidTrust`）、有效期、`agent.key` 等於請求金鑰，`principal.id` 與簽署憑證的識別碼相同。授權書是本專案格式，不宣稱具法律效力；畫面寫「由……簽署的授權書」，等級最高為簽署者本身的等級。

## 6. 線上查驗（OpenID4VP 1.0）

### 6.1 請求

查驗方選擇身分、目的範本與要請求的證件（範本：EUDI PID、mDL 年齡、TWDIW 卡片的 W3C 格式、文件衍生憑證、電子護照衍生憑證，也可手動輸入 DCQL），由 `RequestObjectBuilder` 簽出 `oauth-authz-req+jwt`：`response_mode` 一律 `direct_post.jwt`，回應以本次產生的 ECDH-ES 金鑰加密；`verifier_info` 依序放 WRPRC 與查驗方聲明。

### 6.2 傳輸（E1）

| 路徑 | request_uri 與 response_uri | 適用 |
|---|---|---|
| 正式服務端（`oid4vp` 功能） | 查驗方把簽好的請求物件交給服務端，取得 `https://<服務端>/oid4vp/v1/req/<id>` 與 `/resp/<id>`；持有端以標準 `request_uri` 取得請求、以 `direct_post.jwt` 送回加密回應；查驗方以建立時拿到的權杖取回回應 | 任何標準皮夾 |
| 區網直連 | 查驗方在本機開 http 服務，QR Code 的 `request_uri` 與 `response_uri` 是私有 IPv4 位址 | 兩台本錢包 |

服務端只保存請求物件（本來就給持有端看）與加密回應，取回或逾時（10 分鐘）後刪除，不記錄內容；權杖只存在查驗方手機。區網直連不符合多數皮夾的 https 要求，所以持有端只在下列條件同時成立時接受 http 的 `response_uri`：請求已簽章、`response_mode` 為 `direct_post.jwt`、主機是私有 IPv4、且 `request_uri` 與 `response_uri` 是同一主機。這是本專案的可選放寬，標準驗證器的預設不變。

QR Code 內容為 `openid4vp://?client_id=<client_id>&request_uri=<url>`（`request_uri_method` 不使用），與 OpenID4VP 1.0 第 5 節相同，其他皮夾可直接掃描。

### 6.3 判定

以 `PresentationVerifier.verifyDirectPost` 驗證，結果依架構文件的六個獨立欄位顯示（簽章、發行端信任、狀態、持有者綁定、業務規則、保證標籤），再加上環境（正式、測試、自訂）。任一欄位未知時不得顯示為通過。結果寫入紀錄（`HistoryKind.VERIFIED`），只記證件類型與欄位名稱。

## 7. 近距離查驗（ISO 18013-5）

- reader authentication：X.509 簽章的查驗方身分以該憑證鏈簽 `ReaderAuthentication`；`did:key` 身分改用以該金鑰自簽的讀卡機憑證（持有端判定為 T3）。
- `ItemsRequest.requestInfo`：有 WRPRC 時放 `euWrprc`（bstr，TS 119 472-2），查驗方聲明放 `diw.verifierDeclaration`（tstr，JWS），聲明的 `nonce` 為 SessionTranscript 的 SHA-256。
- 持有端（`ProximityModel`）以同一個 `VerifierDeclarationCheck` 檢查並在同意畫面顯示；reader authentication 失敗時聲明不採用。

## 8. 衍生憑證與零知識證明的查驗政策

查驗方在請求時選擇接受的保證層級（`VerificationPolicy`），結果的「業務規則」欄位依此判定：

| 保證層級 | 判定依據 |
|---|---|
| 政府直接簽發 | 發行端 T1，或 T2 且為官方信任清單 |
| 機關簽章文件衍生 | 文件衍生憑證，證據中機關簽章或 zkPDF 證明通過，簽章者 T2 以上 |
| 持有人衍生 | 持有人自行衍生或自簽（MyData、vc+moica、Photo ID），證據可重做 |
| 沙盒 | 測試環境的發行端；只在測試環境開啟時可選 |

另有兩個條件：要求零知識證據（zkPDF、mdoc ZK、年齡證明）時，沒有證明的回應判為不符；狀態依 `StatusPolicy` 與請求的風險判定。預設接受前兩層，與 Bonds 查驗端「政府卡、自發卡、任一」的選項一致（`BondsCredentialSource` 對應到這張表）。

## 9. 安全與隱私

- 聲明與證據每次請求重簽、綁定 nonce，不能被其他查驗方重放；授權書可重複使用，但綁定受託金鑰。
- 查驗方證據會揭露查驗人員的資料給持卡人；查驗方身分設定畫面列出每一份證據會揭露的欄位，預設只揭露名稱與職稱類欄位。
- 以零知識證明隱藏查驗人員姓名：EUDI 要求識別查驗方，法人不可匿名；組織內個人的匿名需要能證明「受僱於某法人」的 mdoc 或 SD-JWT VC 電路，目前沒有可用的發行端，不做。
- 經中介者的請求依 EUDI RPI_07 只顯示被代理者；本專案的聲明沒有中介者欄位，WRPRC 的 `intermediary` 照既有方式顯示。

## 10. 程式位置

| 內容 | 位置 |
|---|---|
| 聲明、授權書的格式、建立與檢查 | `core/verifier/declaration`（`VerifierDeclaration`、`VerifierMandate`、`VerifierDeclarationCheck`） |
| 以 `DocumentSigner` 簽 JWS | `core/verifier/declaration/SignerJws` |
| 證據出示驗證 | `PresentationVerifier.verifyEvidence` |
| 查驗政策 | `core/verifier/VerificationPolicy` |
| 查驗方身分、線上查驗 | App 的 `VerifierModel`、`ui/VerifierScreens` |
| 服務端轉送 | 服務端 repo 的 `oid4vp` 功能（`Oid4vpMailbox.kt`） |

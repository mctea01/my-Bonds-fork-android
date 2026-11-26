# X.509 完整解析與金鑰、擴充限制

狀態：現行（2026-11-26）

這份文件說明錢包怎麼解析 X.509 憑證、驗證時檢查哪些金鑰用途與擴充限制，以及不符時的信任結果。程式在 `core/src/commonMain/kotlin/diw/wallet/core/x509/`，測試是 `test-servers` 的 `X509ConstraintsTest`。

## 1. 查核時的缺口

查核前的狀況：

- 桌面版經 JDK PKIX 驗證的鏈會檢查 CA 層級的限制與未知的 critical 擴充；Android 用 BouncyCastle PKIX。
- mdoc 的 EC 鏈經 Multipaz `X509CertChain.validate`，會檢查 basicConstraints、pathLen、keyUsage、效期與簽章。
- 時戳權杖由 BouncyCastle 的 `TimeStampToken.validate` 檢查，要求 critical 的 timeStamping。

查核找到的缺口：

- 終端憑證的 keyUsage 與 extKeyUsage 沒有依用途檢查。
- 沒有演算法與金鑰長度的檢查。
- 經 Multipaz、信任清單與內建 CSCA 判定的鏈，沒有檢查 nameConstraints 與憑證政策。
- 委任的 OCSP 回應者沒有檢查 OCSPSigning。
- 憑證畫面只顯示部分欄位，未知擴充不顯示。

## 2. 解析（`X509Details`）

`Der` 是純 Kotlin 的 DER 讀取器，`X509Details.parse` 讀出憑證的每個欄位：

- 版本、序號、外層與 tbsCertificate 的簽章演算法（含參數）；
- 簽發者與主體的每個 RDN（多值 RDN 保留），以及唯一識別碼；
- 效期；
- 公鑰：類型、長度、曲線、RSA 指數、SPKI SHA-256；
- 每個擴充，包括 OID、critical 旗標與原始 DER；
- 簽章值、SHA-256 與 SHA-1 指紋。

已知的擴充由 `ExtensionDecoders` 解成欄位：

- RFC 5280 的全部擴充；
- 憑證透明度的 SCT 與 poison；
- ETSI qcStatements；
- ICAO 的 nameChange 與 documentTypeList；
- TLS feature；
- Microsoft 範本與應用程式原則；
- Netscape。

未知的擴充一樣列出 critical 旗標，並附 DER 的 ASN.1 結構與十六進位。

`X509Details.problems` 列出編碼問題：

- 序號不是 20 位元組以內的正整數；
- 外層與 tbsCertificate 的演算法不同；
- 第 1、2 版憑證帶有擴充；
- 同一個擴充出現兩次；
- 擴充無法解碼。

這些問題只顯示，不影響信任等級。

在 App 裡，`CredentialDetails.certificate` 以這份解析顯示主體與簽發者的每個屬性、公鑰、每個擴充（標題註明 critical 或 non-critical）、簽章值與指紋。解析失敗時退回 Multipaz 的基本欄位。

## 3. 檢查規則（`CertificateConstraints.check`）

`TrustRegistry.evaluate` 對每條判定的路徑執行這些檢查，路徑從終端憑證排到錨點。`decide`、`match`、`decision`、`path` 都用同一個結果，所以收卡、出示、查驗、文件簽章、時戳、mdoc 與 TWDIW 的 X.509 判定都套用同一套規則。

### 3.1 終端憑證的用途（`CertificatePurpose`）

所有用途共用的 keyUsage 規則：keyUsage 存在時，必須有 digitalSignature 或 nonRepudiation；mdoc 文件簽署者必須有 digitalSignature。

| 用途 | extKeyUsage 規則 | 依據 |
|---|---|---|
| TSA | 必須只有 timeStamping，且為 critical | RFC 3161 2.3 |
| OCSP 回應者（委任） | 必須含 OCSPSigning | RFC 6960 4.2.2.2 |
| CONTENT（C2PA 聲明簽署者） | 必須存在；不可有 anyExtendedKeyUsage；必須含 emailProtection、documentSigning 或 C2PA claimSigning 其中之一 | C2PA 14.5.1 |
| MDOC_ISSUER（帶 docType 的發行端） | 有 EKU 時必須含 1.0.18013.5.1.2；沒有 EKU 只加註 | ISO/IEC 18013-5 表 B.3 |
| DOCUMENT（文件與印章簽章） | 有 EKU 而且全是已知的其他用途（例如只有 serverAuth）時不允許；含不認得的廠商 OID 時加註後接受 | RFC 9336、RFC 8550 |
| 其他（ISSUER、VERIFIER 等） | EKU 只有 timeStamping 或 OCSPSigning 時不允許，因為這種金鑰專用於該服務；不常見的用途只加註 | |

DOCUMENT 接受的用途有：documentSigning、emailProtection、clientAuth、Adobe Authentic Documents、Microsoft 文件簽署與智慧卡登入。

ISSUER 與 VERIFIER 不更嚴格，原因是錢包服務端與 Multipaz 的讀卡機憑證會用 mdoc reader 的 EKU 簽署發行端項目，這些項目沒有規格定義的 EKU 規則。

### 3.2 路徑規則

- 簽發其他憑證的憑證必須有 basicConstraints cA=TRUE。錨點沒有時只加註（第 1 版的錨點不加註）。
- 簽發憑證的金鑰在 keyUsage 存在時必須有 keyCertSign，錨點也一樣。
- pathLenConstraint 計算它下方非自簽發的中繼憑證張數，錨點的 pathLen 也計入。
- nameConstraints 檢查下方每張憑證的主體、emailAddress 與 subjectAltName，可比對的類型有 DNS、email、URI、IP 與 DN。錨點自己的限制也套用（RFC 5937）。限制了錢包無法比對的名稱類型，或子樹設定了 minimum 或 maximum 距離（RFC 5280 規定 minimum 為 0、不得有 maximum）時，一律拒絕。
- 憑證政策依 RFC 5280 6.1 建立有效政策樹，包括 policyMappings、policyConstraints 與 inhibitAnyPolicy。初始為 anyPolicy、不要求明確政策，錨點本身的政策擴充不處理。
- 錢包不處理的 critical 擴充依 RFC 5280 4.2 拒絕；出現在錨點上只加註。

### 3.3 演算法與金鑰強度

| 情況 | 結果 |
|---|---|
| MD2、MD5 簽章 | 不允許 |
| RSA 或 DSA 低於 1024 位元，曲線低於 224 位元 | 不允許 |
| SHA-1 憑證簽章 | 判定時間在 2017-01-01 以後為強度不足，以前只加註 |
| RSA 或 DSA 低於 2048 位元 | 判定時間在 2014-01-01 以後為強度不足，以前只加註 |

錨點自己的自簽章不判定。判定時間與憑證鏈畫面一致：文件簽章用可信時戳或簽署時間，時戳用 genTime。

## 4. 信任結果

| 嚴重度 | 結果 |
|---|---|
| FAIL（不允許） | T4，標籤 `CERTIFICATE_CONSTRAINT`。理由列出「憑證名稱：規則」，`anchorName` 保留原本會連到的錨點。`match` 回傳 null，`evaluate` 把它放在 `rejected` |
| WEAK（強度不足） | 最高 T3，標籤 `WEAK_ALGORITHM`，理由列出原因 |
| NOTE（注意） | 只顯示，不改變等級 |

沒有連到錨點的鏈也做同樣的檢查：違反規則時是 T4，不是 T3。依信任模型，低信任的操作仍可在警告確認後繼續。

各處的呈現：

- PDF、CMS、XML 與 OFD 的簽章：違規理由列在簽章的問題中，加上「簽署憑證：」或「時戳憑證：」。強度不足的簽署憑證列在備註；強度不足的時戳不算可信時戳。
- C2PA：簽署憑證違規時，狀態代碼為 `signingCredential.invalid`。
- 委任的 OCSP 回應：回應者沒有 OCSPSigning 時，不採用這份回應（`ValidationCollector`、`PkiSupport.revocation`）。
- Bonds vc+moica 的持卡人憑證：以 DOCUMENT 用途檢查 MOICA 路徑，違規時拒絕（`invalid_certificate_chain`）。
- 憑證鏈畫面：上方的「用途與限制檢查」卡片列出不允許與強度不足的項目，每張憑證下方以顏色列出它自己的發現。

## 5. 錢包自己的自簽憑證

`DocumentSigning.selfIssuedCertificate` 產生的憑證預設帶 extKeyUsage documentSigning 與 emailProtection，符合文件簽章與 C2PA 的規則。以下憑證會帶這組用途：

- 錢包金鑰的簽署憑證；
- OpenPGP 卡沒有持卡人憑證時自簽的憑證。

保存的舊憑證沒有 extKeyUsage，使用時會重新產生（`selfIssuedNeedsRenewal`）。查驗方近距離的讀卡機憑證維持不帶 extKeyUsage。

## 6. 檢查的路徑

檢查的路徑從終端憑證開始，每一層都要名稱與金鑰識別碼相符，而且簽發者的金鑰能驗證簽章。這樣，與根憑證同名的換鑰憑證不會因為名稱相符而被略過。

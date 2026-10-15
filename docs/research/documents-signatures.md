# 數位身分皮夾「文件保存」模組：簽章電子文件格式與驗證調研

> 調研日期：2026-10-10。目標平台：Kotlin Multiplatform（Android 先行、iOS 之後、Compose Multiplatform）。
> 標記：**【確認】** 表示已從官方頁面、規格摘錄或 repo 原始碼（shallow clone 於 `scratchpad/src/`）直接驗證；**【推論】** 表示依經驗或間接資料推得，實作前需再驗證；**【待查】** 表示目前找不到公開權威資料。

---

## 0. 總結（先看這段）

1. **驗證核心建議放在 JVM/Android（Kotlin/Java），iOS 之後再補**。目前沒有任何一套開源函式庫能在 KMP 的 commonMain 完成 PAdES/CAdES/XAdES/OFD 的完整驗證。commonMain 只放資料模型、驗證結果模型、ASN.1/X.509 解析，以及「信任錨與政策」的抽象。
2. **EU DSS（LGPL-2.1，Java 8 bytecode）是 AdES 全家桶的事實標準**，但不是為 Android 設計。`dss-pades` 有 `java.awt` 依賴（字型、影像、視覺差異比對），`dss-validation` 依賴 JAXB 報表。Android 上可行的路線是只取 `dss-cades`、`dss-xades`、`dss-jades` 與 `dss-spi` 的驗證路徑，PAdES 則自行用 PdfBox-Android 加 BouncyCastle 實作 ByteRange/CMS 驗證，或者把完整 DSS 驗證放到後端服務。【推論，需要實測】
3. **iText（AGPL/商業授權）不適合閉源 App**；OpenPDF 3.x 需要 Java 21 且大量使用 `java.awt`，Android 不可用。PdfBox-Android（Apache-2.0）停在 PDFBox 2.0.27，最後一次 commit 是 2023-12，有 `PDSignature` 與 `COSFilterInputStream` 可取 ByteRange 內容，已經足以做驗證。
4. **台灣**：GRCA 不在 Mozilla 根庫（bug 1065896 WONTFIX），MOICA/GCA 也不在 Adobe AATL，**皮夾必須自帶 GPKI 信任錨（GRCA G1–G3 及 MOICA/GCA/XCA 中繼憑證）**。電子公文以 XML（.di/.sw/.si）為主，簽章是 XMLDSig 風格的 SignedInfo/SignatureValue/KeyInfo，演算法 RSA-2048 + SHA-256。MyData 下載檔的簽章格式【待查】。
5. **中國**：OFD 簽章在 `Doc_N/Signs/Signature.xml` 中以 References（逐檔 SM3 雜湊）加上 SignedValue.dat 組成；電子簽章（Seal）為 SES_Signature（GM/T 0031-2014 為 v1，GB/T 38540-2020 為 v4，**ofdrw 原始碼已支援 GM/T 0031-2025 的 v5**），數位簽名（Sign）則為 GB/T 35275 SignedData。**ofdrw（Apache-2.0）是唯一成熟的開源實作，但它的驗證容器自己註明「僅用於測試」：不做憑證鏈、撤銷、印章有效期、時間戳驗證**，這些需要自行補上。信任錨（國家根 CA 及各省 CA 的 SM2 根）沒有統一的公開發布點，是最大的落地風險。
6. **BouncyCastle 在 Android 上必須以「實例」方式註冊（`Signature.getInstance(alg, BouncyCastleProvider())`），或插入一個新名稱的 Provider**，不可依賴名稱 "BC"。Android P 之後，以名稱 "BC" 請求平台內建的 BC 實作會丟出 `NoSuchAlgorithmException`。

---

## 1. 歐盟／國際 AdES 家族

### 1.1 規格總覽

| 規格 | 編號（主文件） | 封裝 | 基線等級 | 重點 |
|---|---|---|---|---|
| PAdES | ETSI EN 319 142-1（基線）／-2（擴充）；ISO 32000-2 §12.8 | PDF 內嵌 CMS（`/SubFilter /ETSI.CAdES.detached`），舊版為 `adbe.pkcs7.detached` | B-B / B-T / B-LT / B-LTA | ByteRange 涵蓋除 `/Contents` 外的全部位元組；LT 以 DSS dictionary（`/DSS` 內含 `/Certs` `/OCSPs` `/CRLs` `/VRI`）保存驗證資料；LTA 加上 `/DocTimeStamp`（`/SubFilter /ETSI.RFC3161`） |
| CAdES | ETSI EN 319 122-1/-2；底層為 RFC 5652 CMS | CMS SignedData（attached/detached） | B-B/B-T/B-LT/B-LTA | 必要簽署屬性：`signing-certificate-v2`（RFC 5035）、`message-digest`、`content-type`；T 為 `signature-time-stamp`（unsigned attr）；LT/LTA 以 `archive-time-stamp-v3` 與 `ats-hash-index-v3` |
| XAdES | ETSI EN 319 132-1/-2；底層為 W3C XMLDSig 1.1 | enveloped/enveloping/detached | 同上 | `SignedProperties`（SigningCertificateV2、SigningTime）、`SignatureTimeStamp`、`CertificateValues`/`RevocationValues`、`ArchiveTimeStamp` |
| JAdES | ETSI TS 119 182-1；底層為 RFC 7515 JWS | Compact/JSON（可 detached，`sigD`） | 同上 | 受保護標頭 `x5t#S256`/`x5c`、`sigT`；未保護標頭 `etsiU` 放時戳與驗證資料 |
| ASiC | ETSI EN 319 162-1/-2 | ZIP 容器（`mimetype`、`META-INF/`） | ASiC-S（單一資料物件）／ASiC-E（多物件與 manifest） | 內放 CAdES（`signature*.p7s`、`ASiCManifest*.xml`）或 XAdES（`signatures*.xml`） |
| 時戳 | RFC 3161；RFC 5816（ESSCertIDv2） | TimeStampToken = CMS SignedData（eContentType id-ct-TSTInfo） | — | 驗證 messageImprint、TSA 憑證 EKU `id-kp-timeStamping`（critical）、TSA 憑證鏈 |
| 驗證程序 | ETSI EN 319 102-1（簽章驗證程序）、TS 119 102-2（驗證報告） | — | — | 基本驗證 → 含時間證明的驗證（past signature validation）→ 長期保存驗證（LTA） |
| 信任清單 | ETSI TS 119 612（TL）、EU LOTL | XML（XAdES 簽章） | — | EU 合格信任服務的信任錨來源 |
| 證據紀錄 | RFC 4998（ERS，ASN.1）、RFC 6283（XMLERS） | — | — | 無簽章文件或大量文件的長期完整性證明（Merkle 雜湊樹加時戳鏈） |

上表規格編號為【確認】（ETSI/IETF 公開編號，DSS 模組名稱 `dss-evidence-record-asn1/xml`、`specs-jades`、`specs-asic-manifest` 均與之對應）。版本號（如 EN 319 142-1 V1.2.1）請以 ETSI 官網為準【推論】。

### 1.2 PAdES 驗證流程（實作清單）

1. 解析 AcroForm 中每個 `/FT /Sig` 欄位 → `/V` 為簽章字典（`/Filter`、`/SubFilter`、`/ByteRange`、`/Contents`、`/M`、`/Reference`（DocMDP））。
2. **ByteRange 健全性檢查**（防 SWA）：必須正好兩段 `[0 a b c]`；`a + len(/Contents hex 含尖括號) == b`；`b + c ==` 該簽章所屬修訂版的 `%%EOF` 位置；第一段必須從 0 開始；`/Contents` 的範圍內只能有一個 hex string。
3. 以 ByteRange 取出位元組並計算雜湊 → 解析 `/Contents` 的 CMS → 比對 `message-digest` → 驗證 SignerInfo 簽章值 → 檢查 `signing-certificate-v2` 是否綁定簽署者憑證。
4. **修訂版分析**（防 ISA/Shadow）：簽章涵蓋的修訂版之後若有增量更新，依照 DocMDP `/P`（1/2/3）及 FieldMDP 判定變更是否允許。要比對物件層級的差異（新增頁面、覆寫 XObject、替換字型、隱藏覆蓋層等），而不只檢查「是否有附加資料」。
5. 憑證鏈建構至信任錨 → 撤銷檢查：優先使用簽章內嵌（CMS `RevocationInfoChoices`、adbe-revocationInfoArchival 屬性、`/DSS`），其次線上 OCSP/CRL。
6. 時戳（B-T）：驗證 `signature-time-stamp` 的 messageImprint 等於 SignerInfo.signature 的雜湊 → 時間證明 → 用於過期憑證的 past validation。
7. LTA：依序驗證 `/DocTimeStamp`，每個時戳涵蓋之前所有修訂版與 `/DSS`，逐層把驗證時間往前推。
8. 輸出 ETSI EN 319 102-1 的結論：TOTAL_PASSED / INDETERMINATE（子狀態，如 NO_CERTIFICATE_CHAIN_FOUND、REVOKED_NO_POE、TRY_LATER）/ TOTAL_FAILED。

### 1.3 PDF 簽章攻擊（驗證器必須防禦）

| 攻擊 | 來源 | 機制 | 對策 |
|---|---|---|---|
| USF（Universal Signature Forgery） | Mladenov et al. 2019（pdf-insecurity.org 2018 報告） | 移除或竄改 `/Contents`、`/ByteRange` 使檢視器略過驗證，卻仍顯示「已簽」 | 缺少 ByteRange 或 Contents 一律判 FAILED，不可略過 |
| ISA（Incremental Saving Attack） | 同上 | 在簽章後以增量更新附加內容；變體 2–4 甚至省略 xref/trailer，但寬鬆的解析器仍會顯示 | 偵測簽章覆蓋範圍之後的所有位元組；以修訂版為單位比對差異 |
| SWA（Signature Wrapping Attack） | 同上 | 改寫 ByteRange，讓被簽的原始位元組移到 `/Contents` 的填補區或其他位置，再插入惡意內容 | 第 1.2 節第 2 步的嚴格 ByteRange 檢查 |
| Shadow attacks（Hide / Replace / Hide-and-Replace） | Mainka, Mladenov, Rohlmann, NDSS 2021 | 簽署前就在文件中埋好不可見的物件，簽署後以「允許的」增量更新（如表單填寫、註解）切換可見內容 | 嚴格的 DocMDP/FieldMDP 判定；比對增量更新是否改變了頁面可見內容（物件參照替換、覆寫 xref 指向舊物件 ID） |

來源：<https://pdf-insecurity.org/signature/isa.html>、<https://pdf-insecurity.org/download/report-pdf-signatures-2018.pdf>、<https://www.ndss-symposium.org/wp-content/uploads/ndss2021_1B-4_24117_paper.pdf>、<https://www.nsoftware.com/kb/articles/sbb-pdf-security>【確認：攻擊分類；對策為業界通行做法】

> 實作提醒：DSS 的 `DefaultPdfDifferencesFinder` 和「modifications detection」就是在做這件事，但它使用 `java.awt` 繪製頁面影像來比對（見 1.4）。在 Android 上需要以物件層級比對取代，或者把頁面渲染交給 `android.graphics.pdf.PdfRenderer`。

### 1.4 函式庫評估

| 函式庫 | 語言／授權 | Android | iOS | KMP | 維護 | 備註 |
|---|---|---|---|---|---|---|
| **EU DSS** 6.5（`eu.europa.ec.joinup.sd-dss`） | Java；**LGPL-2.1**【確認：LICENSE】 | 部分可行【推論】 | ✗ | 僅 androidMain/jvmMain | 活躍（最後 commit 2026-08-28）【確認】 | 編譯目標為 Java 8（`<release>8</release>`）【確認】；依賴 BC 1.85、xmlsec 3.0.6、PDFBox 3.0.8 或 OpenPDF 1.3.43、jose4j（JAdES）【確認：pom.xml】。Cookbook 建議 Android 使用 `dss-utils-google-guava`，FAQ 也提到 Android 上 XMLConstraints 的例外與解法【確認】。**`dss-pades` 與 `dss-pades-pdfbox` 共 10 個以上的類別引用 `java.awt`**（字型、`ImageUtils`、`PdfDocumentReader`、`DefaultPdfDifferencesFinder`、`PdfBoxScreenshotBuilder`）【確認：grep】→ 在 Android 上執行 PAdES 驗證時，很可能在修改偵測階段出現 `NoClassDefFoundError`【推論】。`dss-validation` 依賴 JAXB 報表（jakarta.xml.bind）及 Jackson，APK 會增加數 MB，也需要 R8 keep 規則【推論】。LGPL 在 Android 上的義務：要允許使用者替換或重新連結該函式庫（以獨立 jar/aar 動態依賴、提供物件檔或說明），並保留授權聲明；**不要修改後靜態混淆合併**【推論，需法務確認】 |
| **iText Core 7/8/9** + pdfOCR/sign | Java/.NET；**AGPL-3.0 或商業授權** | 官方有 Android 參考實作（7.2.3 起，API ≥ 27）【確認】 | ✗（.NET MAUI 版另計） | ✗ | 活躍 | 有完整的 `SignatureValidator`、LOTL 支援；但 AGPL 會讓整個 App 必須開源，或需購買商業授權 → **閉源皮夾不建議** |
| **Apache PDFBox** 3.x | Java；Apache-2.0 | 原版依賴 `java.awt`（渲染、字型）→ 不能直接使用 | ✗ | ✗ | 活躍 | `PDSignature.getSignedContent()` 可取 ByteRange 內容，驗證邏輯需搭配 BC 自行撰寫 |
| **PdfBox-Android**（TomRoush） | Java；Apache-2.0【確認】 | ✓ | ✗ | androidMain | **停滯**：基於 PDFBox 2.0.27，最後 commit 2023-12-28【確認】 | 有 `pdmodel/interactive/digitalsignature`（`PDSignature`、`COSFilterInputStream`、`SigningSupport`）【確認】；依賴 `bcprov/bcpkix/bcutil-jdk15to18:1.73`（`api` 範圍，會傳遞給使用者）【確認：library/build.gradle】→ 需要以 Gradle `resolutionStrategy` 統一 BC 版本 |
| **OpenPDF** 3.x | Java；MPL-2.0 或 LGPL-2.1+【確認】 | ✗（Java 21、`java.awt` 有 261 處引用）【確認】 | ✗ | ✗ | 活躍 | 有 `PdfPKCS7`；舊版 1.3.x（Java 8）也同樣依賴 awt。僅適合後端 |
| **BouncyCastle** bcprov/bcpkix/bcutil 1.8x | Java；MIT（Bouncy Castle License） | ✓（需注意 Provider 衝突） | ✗ | androidMain/jvmMain | 活躍 | CMS（`CMSSignedData`、`SignerInformation.verify`）、TSP（`TimeStampToken`）、OCSP、CRL、`PKIXCertPathBuilder`、**SM2/SM3/SM4**、GB/T 35275 OID。Android 衝突：見 §5.1 |
| **pdf.js** | JS；Apache-2.0 | WebView | WebView | ✗ | 活躍 | **不驗證數位簽章**（只能顯示表單欄位）【推論，依長期已知 issue】；只適合用來檢視 |
| **PDFium**（Google） | C++；BSD-3 | ✓（NDK） | ✓ | 透過 cinterop | 活躍 | 能解析簽章欄位並取 ByteRange/Contents（`FPDFSignatureObj_*` API），**沒有密碼學驗證**；可作為跨平台 PDF 解析層【推論：API 名稱依記憶】 |
| **Apple PDFKit** | Swift/ObjC；專有 | ✗ | ✓ | iosMain | — | 沒有公開的簽章驗證 API【推論】 |
| **swift-certificates**（Apple） | Swift；Apache-2.0【確認】 | ✗ | ✓ | iosMain（需要 Swift 橋接層） | 活躍 | 有 X.509、`Verifier`（路徑驗證政策）、OCSP；**CMS 位於 `@_spi(CMS)`（非穩定公開 API）**【確認：原始碼】；演算法只有 ECDSA P-256/384/521、RSA PKCS#1 v1.5、Ed25519，**沒有 RSA-PSS、SM2**【確認：SignatureAlgorithm.swift】 |
| **Signum / indispensable**（A-SIT Plus） | Kotlin MP；Apache-2.0 | ✓ | ✓ | **commonMain** | 活躍（3.24.0，2026-06）【確認】 | ASN.1 編解碼、X.509、JWS/COSE 結構；**沒有 CMS、沒有 OCSP/CRL**，鏈驗證只到單張憑證的簽章【確認】→ 適合當 commonMain 的 ASN.1/X.509 基礎 |
| **cryptography-kotlin**（whyoleg） | Kotlin MP；Apache-2.0 | ✓（JDK provider） | ✓（Apple/OpenSSL3 provider） | commonMain | 活躍 | RSA-PSS/PKCS1、ECDSA、SHA-2/3；**沒有 SM2/SM3**【確認】 |
| **商業**：PSPDFKit/Nutrient、Apryse、SecureBlackbox | 商業 | ✓ | ✓ | — | 活躍 | iOS 端若需要和 Android 同等級的 PAdES 驗證，這是最省事的選項（Nutrient iOS 有 `PSPDFSignatureValidator`）【確認：官方文件存在】 |

來源：<https://github.com/esig/dss>、DSS cookbook（repo 內 `dss-cookbook/src/main/asciidoc/_chapters/faq.adoc`、`advanced-dss-java-concepts.adoc`）、<https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html>、<https://kb.itextpdf.com/itext/release-itext-core-7-2-3>、<https://github.com/TomRoush/PdfBox-Android>、<https://github.com/LibrePDF/OpenPDF>、<https://github.com/apple/swift-certificates>、<https://github.com/a-sit-plus/signum>、<https://github.com/whyoleg/cryptography-kotlin>、<https://www.nutrient.io/guides/ios/signatures/digital-signatures/validation/>

### 1.5 可能遇到的問題（AdES）

- **信任錨**：EU 文件要以 LOTL → 各國 TL 動態取得（XAdES 簽章的 XML，數 MB）；在手機上需要快取與背景更新（DSS 的 `dss-tsl-validation` 可用，但很重）。非 EU 文件（台灣、中國）則要自帶信任錨。
- **離線驗證**：皮夾常在離線狀態 → 必須充分利用 B-LT/LTA 內嵌的驗證資料；B-B/B-T 文件離線時只能給 INDETERMINATE（TRY_LATER）。
- **時間**：驗證時間 = 現在，或是最佳的 POE（proof of existence）時間；過期憑證要靠時戳或保存時的 POE。皮夾在「保存當下」就應建立自己的 POE（見 §4.4）。
- **演算法淘汰**：SHA-1、RSA-1024 的簽章依 ETSI TS 119 312 / SOG-IS 判斷是否可接受，要看時戳的時間點。
- **PDF 解析的容錯差異**：PdfBox 的寬鬆解析可能與檢視器（Adobe/Chrome）不同 → 這正是 ISA 類攻擊的根源；驗證器要「嚴格模式」。

---

## 2. 台灣

### 2.1 政府 PKI（GPKI）與信任錨

- **GRCA（政府憑證總管理中心，Government Root CA）** 是 GPKI 的信任錨，現由數位發展部管理；其下的一層從屬 CA 包括 **MOICA（內政部憑證管理中心，自然人憑證）**、**GCA（政府憑證管理中心，機關憑證）**、**XCA（組織及團體憑證管理中心）**、**MOEACA（工商憑證）**、**HCA（醫事憑證）**【確認】。
- 各代中繼憑證下載點（GRCA 官網列表）【確認】：
  - MOICA G2 `https://moica.nat.gov.tw/repository/Certs/MOICA2.cer`；G3 `https://moica.nat.gov.tw/repository/Certs/MOICA-G3.cer`（GRCA 頁面另列 `https://grca.nat.gov.tw/repository/Certs/MOICA3.cer`）；G1 已過期
  - GCA G2/G3 `https://gca.nat.gov.tw/repository/Certs/GCA2.cer`、`GCA3.cer`
  - XCA G2/G3 `https://xca.nat.gov.tw/repository/Certs/XCA2.cer`、`XCA3.cer`
  - MOEACA G2/G3、HCA G1（SHA1/SHA256）/G2
- MOICA CRL：G2 `https://moica.nat.gov.tw/repository/MOICA/CRL2/complete.crl`；G3 `http://crl-moica.moi.gov.tw/crl/MOICA-G3-complete.crl`；**每日 00:00 與 12:00 產製，最多落後 12 小時**；官方建議改用 OCSP，但儲存庫頁面未列出 OCSP URL（實作時從憑證的 AIA 擴充讀取）【確認】。
- **GRCA 不在 Mozilla 根庫**：Mozilla bug 1065896 以 RESOLVED WONTFIX 結案（super-CA 問題）【確認】；**Adobe AATL 中台灣只有中華電信與 Taiwan-CA，沒有 GRCA/MOICA/GCA**【確認】 → Acrobat 預設不信任自然人憑證簽署的 PDF，皮夾也不能依賴 Android/iOS 系統根庫。
- **建議**：在 App 內以「釘選」方式內建 GRCA 自簽根（G1/G2/G3，需從 GRCA 儲存庫取得並以多管道核對指紋，GRCA 的分發頁面本身沒有提供根憑證下載連結）【確認：頁面無根憑證連結】，以及上列中繼憑證；以遠端設定更新信任錨清單，並對清單本身做簽章。
- 演算法：MOICA G3 / GCA G3 等新一代使用 RSA-2048/4096 搭配 SHA-256【推論，需讀取憑證確認】。電子公文規範要求 RSA-2048、AES-128 以上、SHA-256【確認，見 2.3】。

來源：<https://grca.nat.gov.tw/GRCAeng/1-3.html>、<https://moica.nat.gov.tw/other/moica.html>、<https://moica.nat.gov.tw/other/save_1.html>、<https://bugzilla.mozilla.org/show_bug.cgi?id=1065896>、<https://helpx.adobe.com/acrobat/kb/approved-trust-list1.html>、<https://gca.nat.gov.tw/download/GRCA_GCA_XCA_third_setting.pdf>

### 2.2 PDF 簽章常見實作

- 以自然人憑證（IC 卡）透過 HiPKI 跨平台元件或各機關的簽章元件簽署 PDF；常見 `/SubFilter` 為 `adbe.pkcs7.detached`，少見 PAdES 基線屬性（`signing-certificate-v2`）或時戳；多數沒有 LTV（`/DSS`）【推論】。
- 機關以 GCA 機關憑證簽發的 PDF 證明（如各類電子謄本、證明書）【推論，需逐一取樣】。
- 驗證策略：**以 PAdES 驗證引擎處理，但對「非 ETSI 基線」容錯**（DSS 會回報 `*_NOT_ETSI` 等級，這是正常結果）【確認：DSS FAQ】；信任錨使用 §2.1 的 GPKI 清單。
- 問題：沒有時戳的 MOICA 簽章在憑證到期或撤銷後就無法再證明簽署時有效 → 皮夾在匯入時應立即取得 OCSP 回應並自行加時戳保存（建立 POE）。

### 2.3 電子公文（文書及檔案管理電腦化作業規範）

【確認】（依國家發展委員會檔案管理局發布、各機關轉載的規範及附錄）：
- 檔案類型：**`.di` 文書本文檔（XML）**、**`.sw` 交換表單檔**、`.dm` 文書訊息檔、`.co` 跨機關陳核會稿交換表單檔、**`.si` 簽核電子檔**（逐一簽核點累積記錄）、電子檔案封裝檔（`.xml`，須以機關憑證簽章）；加密交換表單另有 `.esw` 形式。
- XML：UTF-8（或 CNS11643）、無 BOM；各文別有自己的 DTD（例：`104_1_utf8.dtd` 令、`104_2_utf8.dtd` 函），共用基本標籤與交換標籤實體。可電子交換的文別有九種：令、函、公告、開會通知單、簽、簽稿會核單、會銜公文會辦單、會勘通知單、便簽。
- 簽章：線上簽核 DTD 中的簽章元素為 **`SignedInfo`（CanonicalizationMethod、SignatureMethod、Reference[Transforms、DigestMethod、DigestValue]）、`SignatureValue`、`KeyInfo`（X509Data）、`Object`**，即 XMLDSig 結構；另有「加簽時間」元素。每個簽核點的 Signature 都包含前一個簽核點的簽章資料（鏈式），SignedInfo 也記錄外部檔案的雜湊。信封檔的附件項目帶有 `needsig` 旗標與 SHA-256 雜湊。
- 演算法：RSA-2048、AES-128 以上、SHA-256；憑證作業遵循 GCA 規定；無法使用憑證時可用機關的臨時憑證，歸檔前須補簽。
- 呈現檔：`abc_di.pdf` 等「開放性可攜式文件格式」；跨機關會稿的呈現檔可用 PDF、TIFF 或 JPG。
- **對皮夾的意義**：民眾一般拿不到 .di/.sw 原檔，拿到的多半是 PDF 呈現檔或紙本 → 優先支援 PDF；.di/.si 驗證作為進階功能，可用通用的 XMLDSig 驗證器（§4.1）加上 GPKI 信任錨實作。DTD 的完整內容（附錄 3、4、8）需要另外取得【待查】。

來源：<https://general.ncnu.edu.tw/var/file/26/1026/img/85/373280180.pdf>、<https://www.laws.taipei.gov.tw/lawatt/Law/A040030001014200-20201203-8000-004.pdf>

### 2.4 MyData 下載檔

- 官方簡報只提到「國際標準數位簽章安全技術檢核資料完整性」、HTTPS 傳輸及「產製資料檔案時加密」【確認】。
- 下載檔的實際格式（壓縮檔密碼、內含 PDF/JSON/XML、各機關 PDF 是否有機關憑證簽章）**沒有公開技術規格**【待查】。我記得是一個有密碼的 ZIP，內含各機關的資料檔，部分 PDF 帶機關簽章，但這一點【推論，需實際下載樣本驗證】。
- 建議：以「容器拆包 → 對每個內含檔案送入格式偵測與驗證管線」設計；ZIP 本身沒有簽章時，以 §4.4 的完整性保存處理。

來源：<https://mydata.nat.gov.tw/mydataurlres/files/MyData%E5%B9%B3%E8%87%BA%E8%A6%8F%E5%8A%83%E8%88%87%E6%87%89%E7%94%A8%E8%AA%AA%E6%98%8E_20221003013733.pdf>、<https://www.money101.com.tw/blog/戶籍財產-資料-請假-mydata>

---

## 3. 中國大陸

### 3.1 國密演算法與 PKI

| 項目 | 標準 | 重點【確認處標註】 |
|---|---|---|
| SM2 橢圓曲線公鑰演算法 | GB/T 32918.1–.5-2016（GM/T 0003） | 曲線 `sm2p256v1` OID **1.2.156.10197.1.301**；簽章 sm2sign 為 301.1、金鑰交換 301.2、加密 301.3【確認：BC `GMObjectIdentifiers`】 |
| SM3 雜湊 | GB/T 32905-2016（GM/T 0004） | OID **1.2.156.10197.1.401**【確認】 |
| SM3withSM2 | GM/T 0006 OID 定義 | OID **1.2.156.10197.1.501**【確認】 |
| SM4 分組密碼 | GB/T 32907-2016 | 用於 OFD 加密（GM/T 0099），驗章時不需要 |
| SM2 使用規範 | GB/T 35276-2017（GM/T 0009） | **簽章前計算 Z_A = SM3(ENTL‖ID‖a‖b‖xG‖yG‖xA‖yA)，預設 ID = "1234567812345678"（hex 31323334353637383132333435363738）**；簽章值 DER 的 `SEQUENCE{r,s}` 或 64 bytes 的 r‖s 兩種形式都有人使用【確認：BC `SM2Signer` 預設 userID】 |
| SM2 憑證格式 | GM/T 0015-2012（及 GB/T 20518） | X.509 v3 結構，SM2 公鑰的 AlgorithmIdentifier 依 GM/T 0010；CA 憑證必有 keyUsage keyCertSign；**常見「雙憑證」（簽章憑證與加密憑證分開）**，以 keyUsage 區分【確認：GM/T 0015 摘錄】 |
| SM2 簽名訊息語法 | GB/T 35275-2017（GM/T 0010） | 類似 PKCS#7 的 SignedData，但 contentType 等使用國密 OID（`1.2.156.10197.6.1.4.2.x`）【推論：OID 依記憶】；OFD 的「數位簽名」須遵循此標準【確認：ofdrw `GBT35275DSContainer` 註解】 |
| 時間戳 | GB/T 20520-2006 | 結構與 RFC 3161 相容，簽章演算法可以是 SM2；GB/T 38540 要求以 DER 編碼保存【確認】 |

**SM2 實作陷阱**：
- 驗章時要以**簽署者憑證中的公鑰**與**正確的 user ID**計算 Z_A；ID 不是預設值時（極少見）會驗證失敗，而規格沒有欄位可以攜帶 ID → 只能先試預設值。
- Java 的 `Signature.getInstance("SM3withSM2", bcProvider)` 預設套用 Z_A；**不要**先自行算 SM3 再呼叫 "NONEwithSM2"。
- 簽章值編碼：GB/T 38540 為 BIT STRING 包 DER；部分廠商直接放 r‖s → 解碼前先判斷長度與 tag。

### 3.2 OFD 版式文件與其簽章

- **OFD：GB/T 33190-2016《電子文件存儲與交換格式 版式文檔》**（ofdrw repo 內附全文 PDF）【確認】。ZIP 容器：`OFD.xml`（入口） → `Doc_0/Document.xml` → `Pages/Page_N/Content.xml`、`Res/`、**`Signs/Signatures.xml`**（簽章清單）→ `Signs/Sign_N/Signature.xml` + `SignedValue.dat` (+ 選擇性的 `Seal.esl`)。
- `Signature.xml` 的 `SignedInfo`：`Provider`、`SignatureMethod`（如 1.2.156.10197.1.501）、`SignatureDateTime`、**`References`（`CheckMethod` 如 SM3 OID，逐檔 `Reference FileRef` + `CheckValue`）**、`StampAnnot`（外觀位置）、`Seal/BaseLoc`；`SignedValue` 指向 `SignedValue.dat`。`Signatures.xml` 中的 `Signature@Type` = **`Seal`（電子簽章）** 或 **`Sign`（數位簽名）**【確認：ofdrw `OFDValidator`】。
- 被簽的原文是 **`Signature.xml` 的位元組**（裡面已含各檔雜湊），而不是 OFD 全檔【確認：ofdrw `SESV4ValidateContainer` 先比對 SM3(tbsContent) 與 `TBS_Sign.dataHash`】。
- **驗證流程**（依 GB/T 38540 §6.3/§7.3 及 ofdrw 實作）：
  1. 逐一以 `CheckMethod` 重新計算 `References` 內每個檔案的雜湊並與 `CheckValue` 比對【ofdrw 有做】。
  2. 檢查是否有**未列入 References 的檔案被變更或新增**（OFD 允許多次簽章；後續簽章會把先前的 Signs 也納入）→ 應檢查 References 是否涵蓋所有內容檔（如 `ProtectFileFilter`），並禁止 References 本身以外的頁面替換【推論：與 PDF ISA 同類風險】。
  3. 解析 SignedValue.dat：`Seal` → SES_Signature（判斷版本 v1/v4/v5）；`Sign` → GB/T 35275 SignedData。
  4. SES_Signature：比對 dataHash → 以 `cert`（簽章者憑證）驗證 `TBS_Sign` 的 SM2 簽章值【ofdrw 有做】。
  5. **電子印章（SESeal）驗證**：印章格式、**製章者對印章的簽章**、製章者憑證鏈/撤銷/金鑰用途、**印章有效期**（`validStart`–`validEnd`）、簽章者憑證是否在印章的 `certList`（type 1 直接比對、type 2 雜湊比對）【確認：GB/T 38540 §6.3】→ **ofdrw 只比對 Seal.esl 與 SignedValue.dat 內嵌的印章是否相同，以上這些都沒有做**【確認：原始碼】。
  6. 簽章者憑證鏈、有效期、撤銷、金鑰用途【GB/T 38540 §7.3；ofdrw 未做】。
  7. `timeStamp`（GB/T 20520）：驗證後以其時間作為簽署時間的證明【ofdrw 未做】。
- **SES 版本**【確認：ofdrw `VersionParser`】：
  - **v1 = GM/T 0031-2014**：SES_Signature = SEQUENCE{toSign, signature}（2 個欄位），印章 = SEQUENCE{esealInfo, signInfo}。
  - **v4 = GB/T 38540-2020**：SES_Signature = SEQUENCE{toSign, cert, signatureAlgID, signature, [0] timeStamp OPTIONAL}；印章 4 個欄位 {esealInfo, cert, signAlgID, signedValue}。
  - **v5 = GM/T 0031-2025**：結構與 v4 相近，印章多了選擇性的 timeStamp；以印章 header 的 version=5 區分（ofdrw 於 2026-04 加入）。**我沒有找到 GM/T 0031-2025 發布的官方公告，此版本資訊僅來自 ofdrw 原始碼**【待查】。
- **OFD-A 歸檔**：GB/T 42133-2022（ofdrw-archive 實作）；OFD 加密與完整性保護：**GM/T 0099-2020《開放版式文檔密碼應用技術規範》**（ofdrw-crypto 實作，含 `GMProtectVerifier`）【確認：ofdrw README】。

來源：<https://github.com/ofdrw/ofdrw>（clone 後檢查 `ofdrw-sign/.../verify`、`ofdrw-gm/.../ses/parse/VersionParser.java`）、<https://www.chinesestandard.net/PDF-EN/GBT38540-2020EN-P08P-H6686H-599485.pdf>、<https://www.chinesestandard.net/PDF-EN/GMT0015-2012EN-P14P-H11738H-118503.pdf>、<https://raw.githubusercontent.com/bcgit/bc-java/main/core/src/main/java/org/bouncycastle/crypto/signers/SM2Signer.java>、<https://raw.githubusercontent.com/bcgit/bc-java/main/core/src/main/java/org/bouncycastle/asn1/gm/GMObjectIdentifiers.java>

### 3.3 電子證照、政務文件、電子發票

- **電子證照 GB/T 36901~36905-2018**（總體技術架構、目錄資訊規範、元資料規範、標識規範、文件技術要求）：證照文件以 **OFD 為版式**，以電子印章/電子簽章（GB/T 38540）簽署，搭配全國一體化政務服務平台的證照目錄與驗證服務【推論：標準名稱與 OFD 使用為業界通識，條文未取得】。
- **數電發票（全電發票）**：國家稅務總局的辦法規定可經電子發票服務平台或全國增值稅發票查驗平台免費查驗，可下載或匯出【確認：fgk.chinatax.gov.cn】。檔案提供 **XML、OFD、PDF** 三種；業界文章指出**只有官方管道取得、帶數位簽章的 XML 才能合規報帳入帳**，第三方由 PDF 轉出的 XML 沒有簽章【確認：業界文章，非官方規格】。XML 簽章的實際結構（XMLDSig 或自訂元素、SM2 或 RSA）**沒有公開規格**【待查】。實務上的權威驗證是「發票查驗平台線上比對」，而不是離線驗章。財政部「電子憑證會計資料標準」與 XML 的關聯【待查】。
- **PDF 上的 SM2 簽章**：**沒有國家標準規範 PDF 的 SM2 簽章**；廠商（如 BJCA、CFCA、數科）多以 `adbe.pkcs7.detached` 或自訂 `/SubFilter` 搭配 GB/T 35275 SignedData 或 SM3withSM2 SignerInfo 實作 → Adobe 無法驗證，只能用廠商閱讀器【推論】。GM/T 0112-2021（PDF 密碼應用相關）在搜尋結果中出現，但未取得內容【待查】。
- **XML 簽章使用 SM2/SM3**：W3C 沒有官方的 SM2/SM3 演算法 URI；國內實作自訂 URI【推論】。驗證器需要可插拔的演算法 URI 對應表。

來源：<https://fgk.chinatax.gov.cn/zcfgk/c100012/c5236067/content.html>、<https://www.sohu.com/a/976289833_122519060>、<https://www.ekuaibao.com/blog/292936.html>、<https://chinesestandard.net/PDF.aspx/GMT0112-2021>

### 3.4 函式庫

| 函式庫 | 授權 | 平台 | 狀態 | 評估 |
|---|---|---|---|---|
| **ofdrw** 2.4.0 | **Apache-2.0**【確認】 | Java 8 bytecode【確認】；`ofdrw-core/pkg/gm/sign` 沒有 awt；**`ofdrw-reader` 有 4 個類別使用 `java.awt`/`javax.imageio`**（影像與關鍵字擷取）【確認】；依賴 dom4j、jaxen、BC jdk18on 1.85 | 活躍（最後 commit 2026-09-20）【確認】 | Android：`ofdrw-gm` + `ofdrw-sign/verify` 預期可用（驗證路徑不觸及 awt 類別）【推論，需實測】；**必須自行補上印章與憑證的完整驗證**。注意 `ofdrw-sign` 依賴 `ofdrw-reader`，需確認類別載入不會牽動 awt |
| **BouncyCastle** | MIT | JVM/Android | 活躍 | SM2/SM3/SM4、`SM2Signer`（預設 Z_A ID）、SM2 X.509 解析與 `X509CertificateHolder.isSignatureValid`；**PKIX CertPathValidator 對 SM2 的支援要搭配 BC provider 實例**【推論】 |
| **GmSSL** 3.x | **Apache-2.0**【確認】 | C；官方 CI 測試 Android 與 iOS 交叉編譯（CMake + NDK / ios.toolchain.cmake）【確認：INSTALL.md】 | 活躍（2026-06）【確認】 | **iOS 端 SM2/SM3/SM4 與國密 X.509、SignedData 的首選**；透過 Kotlin/Native cinterop 接入 iosMain。另有 GmSSL-Java（JNI），但 Android 上用 BC 即可 |
| **Tongsuo**（銅鎖，原 BabaSSL） | Apache-2.0 | C（OpenSSL 3 分支） | 活躍【推論】 | 若 iOS 端已採用 OpenSSL，可作為替代方案 |
| Apple CryptoKit / Security | — | iOS | — | **不支援 SM2/SM3** → iOS 必須使用 GmSSL 或 Tongsuo |

### 3.5 信任錨問題（中國）

- 沒有類似 EU LOTL 的公開機器可讀信任清單；SM2 根有國家密碼管理局的「國家根 CA」（SM2 根）及各家 CA（CFCA、BJCA、各省 CA）的根，**散落在各 CA 官網**，多數不在 Mozilla/Apple/Android 根庫【推論】。
- 電子印章的製章者憑證通常來自地方公安或政務 CA（印章管理系統），**外部很難取得完整的鏈** → 實務上多數第三方驗證器只做到「簽章值數學驗證 + 文件完整性」，憑證鏈則回報 INDETERMINATE。
- 建議：信任錨以「地區信任包（trust bundle）」的形式由伺服器下發並簽署；UI 上要區分「文件完整未竄改」與「簽署者身分可追溯至受信任根」兩個層次。
- 撤銷：CRL/OCSP 端點常是中國境內內網或 HTTP，從海外（如台灣使用者）可能連不上 → 預設離線、結果標示「無法檢查撤銷」。

---

## 4. 通用格式與無簽章文件

### 4.1 XMLDSig（W3C XML Signature 1.1，及 XAdES 的基底）

- 結構：`Signature/SignedInfo(CanonicalizationMethod, SignatureMethod, Reference*[Transforms, DigestMethod, DigestValue])`、`SignatureValue`、`KeyInfo`、`Object`。
- 驗證：(1) 逐一 dereference 每個 Reference（URI 可以是同文件 `#id`、外部檔或空字串的 enveloped）→ 套用 transforms（enveloped-signature、C14N 1.0/1.1、exc-c14n）→ 計算雜湊並比對；(2) 對 C14N 後的 SignedInfo 驗證 SignatureValue；(3) KeyInfo 憑證鏈。
- **安全陷阱**：XML Signature Wrapping（XSW：被簽的節點和業務邏輯讀取的節點不是同一個）→ 業務層只能讀取「被 Reference 涵蓋的那個節點」；ID 屬性重複；XXE/DTD → 關閉外部實體（DSS 預設的 XMLSecurities 就是為此）；XSLT/XPath transform 應該禁用。
- 函式庫：**Apache Santuario xmlsec**（Apache-2.0；Java）。Android 平台沒有 `javax.xml.crypto`（JSR 105）API，因此建議使用 Santuario 的原生 `org.apache.xml.security.signature.XMLSignature` API，而不是 JSR 105【推論】；DSS XAdES 也基於 Santuario。iOS：沒有成熟的 Swift XMLDSig 函式庫 → 用 libxml2（系統內建）加 C14N，自行實作或使用 xmlsec1（C，MIT；依賴 libxml2/OpenSSL）的 cinterop【推論】。

### 4.2 CMS/PKCS#7 detached（`.p7s`、`.p7m`）

- RFC 5652（CMS）、RFC 8933（algorithm identifier protection）、RFC 5035（ESS signing-certificate-v2）。
- 驗證：計算 eContent 或外部檔案的雜湊 → 比對 signedAttrs 的 `message-digest` → 以 DER 重新編碼的 signedAttrs（SET OF，tag 0x31）驗證簽章 → 若有 `content-type` 屬性則檢查 → 憑證鏈。
- 陷阱：**signedAttrs 必須以 DER SET（0x31）重新編碼後再驗證**（不是原始的 [0] IMPLICIT 標籤）；BER 不定長度編碼；同一個 CMS 中有多個 SignerInfo；RSA-PSS 參數。
- 函式庫：BC `CMSSignedData`（JVM/Android）；iOS 用 swift-certificates 的 `@_spi(CMS)`（有風險）、GmSSL（國密）或 OpenSSL cinterop。

### 4.3 JWS 簽章文件

- RFC 7515（JWS）、RFC 7797（unencoded payload `b64:false`，適合 detached 大檔）、JAdES（TS 119 182-1）。
- 驗證：`alg` 白名單（禁止 `none`、HS*）→ 以 `x5c`/`kid`/`x5t#S256` 取得金鑰 → 驗證簽章 → JAdES 另需檢查 `sigT`、`sigD`（detached 物件的雜湊）與 `etsiU` 內的時戳。
- 函式庫：Nimbus JOSE+JWT（Apache-2.0，Java/Android）、jose4j（Apache-2.0，DSS JAdES 使用）、**Signum indispensable-josef（KMP，commonMain）**【確認：README】。皮夾既有的 SD-JWT/VC 堆疊大概已有 JWS → 共用即可。

### 4.4 無簽章文件的完整性保存

目標：證明「此檔案自 T 時起未被竄改」並保留可讀性。
1. **雜湊**：匯入時計算 SHA-256（可並行計算 SHA-512 或 SM3 以便將來演算法遷移），存入皮夾的加密資料庫；檔案本體以 Android Keystore/iOS Keychain 衍生的金鑰加密保存（AES-GCM）。
2. **時戳（POE）**：把雜湊（或多檔的 Merkle root）送到 RFC 3161 TSA，取回 TST 並保存 → 形成獨立於裝置的存在證明。可選擇台灣的 TSA（如 TWCA、中華電信的時戳服務）或 EU 合格 TSA；需要網路與費用評估【推論】。
3. **長期保存**：大量文件適合採用 **RFC 4998 Evidence Record**（Merkle 樹 + ArchiveTimeStamp 鏈，在演算法或憑證到期前做 renewal）；DSS 已有 `dss-evidence-record-asn1/xml` 可驗證 ER【確認：模組存在】。
4. **對簽章文件也要做 POE**：B-B/B-T 等級的文件在匯入時立即補取 OCSP/CRL，並對「文件 + 驗證資料」加時戳 → 等同在皮夾端把文件升級到 LT/LTA 的證據（不修改原檔，另外存 evidence 包）。
5. **封存 PDF/A**：ISO 19005-1/-2/-3/-4。需要「可讀的長期副本」時，可把非 PDF 文件轉成 PDF/A-3 並把原檔以 `/AF` 嵌入（原始簽章檔保持不變）。**不要對已簽章的 PDF 做 PDF/A 轉換，否則會破壞簽章。** 驗證 PDF/A 用 veraPDF（GPLv3+ 或 MPL-2.0 雙授權，Java，偏重桌面與伺服器；DSS 的 `dss-pdfa` 使用它）【推論：授權依記憶】。OFD 對應的是 OFD-A（GB/T 42133-2022）。
6. **匯出包**：建議用 **ASiC-E**（ZIP + manifest + 皮夾自己的 CAdES/JAdES 簽章或時戳）作為「保存證據包」的匯出格式，方便第三方以 DSS 驗證。

---

## 5. 平台議題

### 5.1 BouncyCastle 在 Android 上的衝突【確認＋推論】

- Android 系統內建一份重新打包的 BC（`com.android.org.bouncycastle`），註冊名稱為 **"BC"**。Android P（API 28）起，對已由 Conscrypt 提供的演算法，若以名稱或實例請求平台的 "BC" provider，在 targetSdk ≥ 28 時會丟 `NoSuchAlgorithmException`【確認：Android Developers Blog 2018-03】。
- 自帶的 `org.bouncycastle:bcprov-jdk18on` 套件名稱不同，不會發生類別衝突，但 **`Security.addProvider(BouncyCastleProvider())` 會因為名稱 "BC" 已存在而失敗**（回傳 -1）。常見做法：`Security.removeProvider("BC"); Security.insertProviderAt(BouncyCastleProvider(), 1)`，或**不註冊、一律傳 provider 實例**（推薦；ofdrw 正是這樣做的：`Signature.getInstance(oid, new BouncyCastleProvider())`）【確認：ofdrw 原始碼】。
- DSS 內部以名稱 "BC" 取得 provider 的地方要逐一確認，必要時呼叫 `DSSSecurityProvider.setSecurityProvider(...)` 指定實例【推論：DSS 有此 API，需要核對 6.5 版】。
- 版本統一：PdfBox-Android 透過 `api` 傳遞 `bc*-jdk15to18:1.73`，DSS/ofdrw 使用 `bc*-jdk18on:1.85` → **同一份 classpath 上會有兩套 BC（套件名稱相同、artifact 不同）造成 duplicate class**；須在 Gradle 中排除 jdk15to18 並強制使用 jdk18on【推論，屬高機率問題】。
- APK 大小：bcprov 約 8 MB → 要設定 R8 shrink 與 keep 規則（反射載入的 SPI 類別）。

### 5.2 Java 依賴的 Android 相容性

- `java.awt`、`javax.imageio`：Android 沒有 → DSS PAdES 視覺比對、OpenPDF、PDFBox 原版、ofdrw-reader 的影像部分都會受影響。
- JAXB（DSS 報表）：在 Android 上以 jakarta JAXB runtime 執行有反射與效能成本；可以只取 DSS 的 Java 物件報表（`Reports` 的 DTO），不要做 XML 序列化【推論】。
- `java.time`、`java.nio.file`：minSdk < 26 時要開啟 core library desugaring。
- xmlsec 3.x 依賴 `org.slf4j`、`jakarta.xml.bind`？（需確認）及 Xerces 相關的 XMLConstants 行為 → DSS FAQ 已提供 Android 上的 `SchemaFactoryBuilder` 屬性移除方法【確認】。

### 5.3 iOS 策略

- 沒有開源的 Swift PAdES 驗證器 → 選項：(a) **PDFium（解析與 ByteRange）+ OpenSSL/GmSSL（CMS、X.509、OCSP、SM2）透過 cinterop 自建**；(b) 商業 SDK（Nutrient/Apryse）；(c) **驗證結果在 Android 或伺服器端產生並簽章，iOS 端只驗證「驗證報告」的簽章**（過渡方案）。
- OFD：iOS 端要自行以 Kotlin 在 commonMain 實作 OFD ZIP/XML 解析（XML 用 xmlutil 或 KSoup 之類的 KMP XML 函式庫）+ GmSSL 驗證 SM2。這部分可行，因為 OFD 簽章驗證的核心只有「XML 解析 + 雜湊 + ASN.1 + SM2」【推論】。

---

## 6. 格式 × 建議函式庫 × 平台 × 授權風險

| 格式 | Android（androidMain/jvm） | iOS（iosMain） | commonMain 可共用 | 授權風險 | 備註 |
|---|---|---|---|---|---|
| PAdES / PDF CMS（含台灣 MOICA PDF） | PdfBox-Android（解析/ByteRange）+ BC（CMS/TSP/OCSP）+ 自寫 ETSI 驗證邏輯；或 DSS `dss-cades`/`dss-spi` 部分重用 | PDFium + OpenSSL（cinterop）或商業 SDK | ByteRange 檢查、修訂版分析模型、ETSI 結果模型、信任政策 | 低（Apache-2.0/MIT）；DSS 為 LGPL-2.1 → 中；**iText = AGPL → 高** | 需要自行實作 ISA/SWA/Shadow 防護 |
| CAdES / CMS `.p7s/.p7m` | BC `CMSSignedData`；DSS `dss-cades`（中） | OpenSSL CMS / swift-certificates `@_spi(CMS)`（SPI 風險） | ASN.1 解析（Signum）、屬性模型 | 低 / LGPL 中 | |
| XAdES / XMLDSig（含台灣電子公文 .di/.si） | Santuario xmlsec（原生 API）；DSS `dss-xades` | xmlsec1 + libxml2（cinterop） | Reference/Transform 模型、XSW 防護規則 | 低（Apache-2.0/MIT） | DTD/XXE 必須關閉 |
| JAdES / JWS | Nimbus 或 Signum josef；DSS `dss-jades`（jose4j） | Signum josef | **大部分可在 commonMain**（Signum + cryptography-kotlin） | 低 | 與 VC/SD-JWT 堆疊共用 |
| ASiC-S/E | DSS `dss-asic-cades/xades`，或自寫 ZIP + manifest | 自寫（ZIP 可用 okio/kotlinx-io） | ZIP 結構、manifest 解析 | 低 / LGPL 中 | |
| RFC 3161 時戳 | BC `TimeStampToken` | OpenSSL TS / GmSSL | TSTInfo 模型 | 低 | |
| LTV（DSS dict、OCSP、CRL） | BC OCSP/CRL + 自寫 `/DSS` 解析 | OpenSSL OCSP；swift-certificates OCSP | 撤銷資料模型、POE 時間演算 | 低 | 離線優先 |
| OFD + SES 電子簽章（v1/v4/v5） | **ofdrw-gm + ofdrw-sign（補完整驗證）** + BC | **commonMain 自寫 OFD 解析** + GmSSL（SM2/SM3/X.509） | OFD 容器與 Signature.xml 模型、SES ASN.1 結構（Signum ASN.1） | 低（Apache-2.0） | 信任錨取得困難；ofdrw 驗證「僅供測試」 |
| OFD 數位簽名（GB/T 35275） | BC（國密 OID 的 SignedData） | GmSSL | 同上 | 低 | |
| SM2 PDF 簽章（廠商擴充） | PdfBox-Android + BC SM2 | PDFium + GmSSL | ByteRange 檢查共用 | 低 | 沒有標準，以「盡力驗證」處理 |
| 數電發票 XML/OFD/PDF | OFD 路徑 + XMLDSig 路徑；權威驗證為線上查驗平台 | 同上 | | 低 | XML 簽章規格【待查】 |
| 無簽章文件 | 雜湊 + RFC 3161（BC）+ RFC 4998 ER（DSS 或自寫） | 雜湊（CryptoKit）+ OpenSSL TS | **雜湊、Merkle、ER 模型可在 commonMain** | 低 | |
| PDF/A 轉換與驗證 | 伺服器端（veraPDF、OpenPDF、PDFBox） | 伺服器端 | — | veraPDF GPL/MPL → 選 MPL | 不在手機端做 |

---

## 7. 建議的 KMP 模組切分

```
:docvault-core            (commonMain)
  ├─ model/      DocumentRef, Container(Zip/Pdf/Ofd/Xml/Jws/Raw), SignatureInfo,
  │              ValidationReport(ETSI EN 319 102-1 Indication/SubIndication), Evidence(POE, TST, ER)
  ├─ api/        interface DocumentInspector  { suspend fun detect(bytes|source): FormatHint }
  │              interface SignatureValidator { val formats: Set<Format>; suspend fun validate(doc, policy, trust): ValidationReport }
  │              interface TrustStore         { anchors(region: TW|EU|CN|...), intermediates, update(signedBundle) }
  │              interface RevocationSource   { ocsp(cert, issuer), crl(url) } // 可離線注入快取
  │              interface TimestampClient    { suspend fun stamp(digest): Tst }
  │              interface CryptoPrimitives   { verify(alg, spki, data, sig), digest(alg, data) }  // 含 SM2/SM3 擴充點
  ├─ pdf/        ByteRangeChecks, RevisionAnalyzer 規則（純 Kotlin，輸入由平台解析器提供的 xref/修訂版資訊）
  ├─ ofd/        OFD ZIP/XML 解析、Signatures/Signature.xml 模型、References 雜湊比對（純 Kotlin + kotlinx-io）
  ├─ asn1/       以 Signum indispensable-asn1 解析 CMS/SES_Signature/TSTInfo 結構（只做解析，不做密碼學）
  ├─ jws/        Signum josef + cryptography-kotlin（JWS/JAdES 基本驗證可完全放在 commonMain）
  └─ preserve/   Hash、Merkle、RFC 4998 Evidence Record 模型、匯出 ASiC-E

:docvault-jvm-common      (jvmAndroidMain：Android 與 desktop/server JVM 共用)
  ├─ BcCryptoPrimitives（BC 實例 provider，含 SM2 Z_A）
  ├─ CmsValidator / TspValidator / OcspCrl（BC）
  ├─ XmlDsigValidator（Santuario 原生 API，關閉 DTD/XXE）
  ├─ OfdSesValidator（ofdrw-gm 結構 + 自補印章與鏈驗證）
  └─ (選用) DssBridge：只引入 dss-cades/xades/jades/asic；以獨立 artifact 隔離 LGPL

:docvault-android         (androidMain)
  ├─ PdfBoxAndroidParser（PdfBox-Android → 修訂版、ByteRange、/DSS 抽取）
  ├─ PdfRenderer 頁面渲染（Shadow attack 的視覺比對，可選）
  └─ Keystore 加密儲存、WorkManager 背景更新信任包與 TST

:docvault-ios             (iosMain)
  ├─ cinterop: PDFium（解析）、OpenSSL 3 或 Tongsuo（CMS/OCSP/TS）、GmSSL 3（SM2/SM3/國密 X.509）
  ├─ 先期：只支援 JWS、OFD（commonMain 解析 + GmSSL）、CMS detached；PAdES 待第二階段或採用商業 SDK
  └─ Keychain/Secure Enclave 加密儲存

:docvault-trust-bundles   (resources，伺服器簽章後下發)
  ├─ tw-gpki: GRCA G1–G3、MOICA/GCA/XCA/MOEACA/HCA 各代中繼憑證（釘選指紋）
  ├─ eu-lotl: LOTL 快取 + 簽章憑證（或由後端轉成精簡清單）
  └─ cn-sm2: 已知 SM2 根與 CA 中繼（盡力收集，標示信任等級）
```

**階段建議**：
1. Phase 1（Android）：CMS/PAdES 基本驗證（BC + PdfBox-Android + 嚴格 ByteRange/ISA 檢查）、JWS、雜湊 + RFC 3161 保存、TW GPKI 信任包。
2. Phase 2：OFD/SES（ofdrw 加上自補驗證）、XMLDSig（電子公文、發票）、LTV/LTA、EU LOTL。
3. Phase 3（iOS）：commonMain 已有的 OFD/JWS/保存功能先上；PAdES 走 PDFium + OpenSSL，或商業 SDK。
4. 評估把「完整 DSS 驗證（含 LOTL、ER、視覺修改偵測）」放在後端驗證服務，App 端顯示並保存經後端簽章的驗證報告（也就是 ETSI TS 119 102-2 報告加上 TS 119 441 驗證服務的概念）。

---

## 8. 待驗證事項清單

- [ ] 在 Android（minSdk 26 以上）實測：DSS 6.5 `dss-cades` + `dss-xades` + `dss-validation` 的 APK 大小、JAXB 與 xmlsec 是否能執行。
- [ ] 實測 DSS `dss-pades-pdfbox` 在 Android 上的哪些路徑會觸發 `java.awt`（預期是修改偵測與視覺簽章）。
- [ ] 確認 ofdrw `ofdrw-sign` 的 verify 路徑在 Android 上不會載入 `ofdrw-reader` 的 awt 類別。
- [ ] 取得 GRCA 自簽根憑證（G1/G2/G3），並以官方公告核對指紋。
- [ ] 取得 MyData 下載樣本，確認容器、加密與簽章格式。
- [ ] 取得數電發票 XML 樣本，確認簽章元素與演算法。
- [ ] 確認 GM/T 0031-2025 是否正式發布及其內容（目前僅有 ofdrw 原始碼的依據）。
- [ ] LGPL-2.1 在 Android 上（R8/AAR）的合規做法，需法務確認。

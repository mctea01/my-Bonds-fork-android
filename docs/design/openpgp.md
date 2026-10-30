# OpenPGP 與 OpenPGP 卡

2026-10-30 使用者要求加入 PGP 支援與 OpenPGP 卡。本文是設計與約定，實作在同一個 PR（疊在 PR #55 之上，沿用其 PIV 與硬體簽章群組）。

## 1. 目標與範圍

| 項目 | 內容 |
|---|---|
| OpenPGP 卡 | 讀取卡片資訊（不需 PIN）、以簽章金鑰簽署、以解密金鑰解開寄給自己的 OpenPGP 檔案 |
| OpenPGP 簽章 | 對文件產生分離式簽章（`.asc`，ASCII armor，v4，簽章類型 0x00 binary document） |
| X.509 文件簽章 | OpenPGP 卡的簽章金鑰也可簽 PAdES、CAdES、XAdES、ASiC-E 與公文簽核點，憑證用卡上的持卡人憑證（DO 7F21），沒有時以卡片自簽 |
| 查驗 | 文件檢查認得 OpenPGP 分離式簽章、明文簽章訊息（cleartext signed）、內含簽章訊息（one-pass + literal）、公開金鑰檔與加密訊息 |
| 公開金鑰清單 | 匯入 `.asc`／`.gpg`／`.pgp` 公開金鑰，列出、刪除；以指紋向 keys.openpgp.org 查詢並經確認後加入；自己的 OpenPGP 卡金鑰可一鍵加入 |
| 加密 | 把保存的文件加密給清單內的公開金鑰（可多位收件人，含自己的卡片），輸出 `.gpg` |
| 解密 | 以 OpenPGP 卡的解密金鑰解開 `.gpg`／`.asc` 加密訊息，結果另存為新檔並檢查 |

不做：在錢包內產生或匯入 OpenPGP 私鑰（私鑰只在卡片上）、把私鑰寫入卡片、變更卡片 PIN／重設碼／管理 PIN（PW3）、卡片出廠重設、Web of Trust 計算、加密郵件。這些交給 GnuPG、Sequoia 或卡片廠商工具。

## 2. 依據的規格

- Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems 3.4.1（向下相容 2.0 到 3.3）
- RFC 4880（OpenPGP）、RFC 6637（OpenPGP 的 ECC）、RFC 9580（OpenPGP v6；查驗與解密支援，產生的簽章固定為 v4 以相容 GnuPG）
- ISO/IEC 7816-4（APDU、GET RESPONSE、command chaining）

## 3. 卡片與傳輸

沿用 `diw.wallet.core.document.card.CardChannel` 與 `NfcCardChannel`（包 Multipaz `NfcIsoTag`），因此與自然人憑證卡、PIV 卡走同一條路：

| 平台 | 傳輸 |
|---|---|
| Android | 手機 NFC（IsoDep reader mode，YubiKey 5 NFC 貼近即可）、OTG 接上的 USB CCID 讀卡機，或直接插上的 YubiKey／Nitrokey／Gnuk（Multipaz `CcidDriver`，APDU 層，與讀卡機同一條路；`AndroidNfcReaders`） |
| 桌面 | PC/SC（`PcscReaders`）：讀卡機或直接插上的安全金鑰 |

Android 的 YubiKey 與其他安全金鑰：

- 依 USB 廠商代碼標示名稱（Yubico 0x1050 為「YubiKey」、0x20A0 為「Nitrokey」、0x234B 為「Gnuk」），在讀卡機清單顯示為「YubiKey 5 NFC（USB）」等，並優先選用直插的金鑰（不需感應）。
- 插上的 YubiKey 沒有 CCID 介面時（只開了 FIDO／OTP，或是只支援 FIDO 的 Security Key 系列），清單說明要以 Yubico Authenticator 在 USB 介面設定開啟 CCID。
- 讀卡機清單可「重新尋找」，簽署途中插上的金鑰不必重開畫面。
- 第一次使用 USB 裝置時系統會詢問權限；NFC 由錢包自己的感應提示顯示，只在等待感應時開啟 reader mode。

桌面：GnuPG 的 scdaemon 會獨占 YubiKey（SCARD_E_SHARING_VIOLATION）。直插的金鑰不會被拔出，以前的等待移除迴圈會一直等，現在改為立即停止並提示關閉該程式或執行 `gpgconf --kill scdaemon`。

不依賴 YubiKit 或任何廠商程式庫。已知可用的卡片：YubiKey 5（OpenPGP applet 3.4）、Nitrokey Pro 2／Start／3、Gnuk（FST-01）、SmartPGP（JavaCard）、ZeitControl／FLOSS OpenPGP 卡 2.x 與 3.x。卡片 AID 前綴 `D2 76 00 01 24 01`，回應中的版本、廠商代碼與序號顯示在卡片資訊。

## 4. 架構

| 位置 | 類別 | 職責 |
|---|---|---|
| `core/commonMain/.../document/card/OpenPgpCard.kt` | `OpenPgpCard`、`OpenPgpCardInfo`、`OpenPgpCardKey`、`OpenPgpAlgorithm` | APDU：SELECT、GET DATA（6E、65、5F50、7A、F9）、讀公開金鑰（GENERATE ASYMMETRIC KEY PAIR P1=81）、SELECT DATA＋GET DATA 7F21、VERIFY（含 KDF-DO）、PSO:CDS、PSO:DECIPHER |
| `core/commonMain/.../document/pgp/OpenPgpPackets.kt` | `OpenPgpPackets` | 純 Kotlin：由卡片公開金鑰重建 v4 公開金鑰封包並比對卡上指紋（C5）、MPI、v4 簽章封包、ASCII armor 與 CRC-24 |
| `core/commonMain/.../document/pgp/OpenPgpCardSigner.kt` | `OpenPgpTapSigner` | `DocumentSigner`（X.509 格式）與 `signDetached`（OpenPGP 分離式簽章）；每次簽章前 VERIFY PW1，簽完以公開金鑰檢查簽章值 |
| `core/commonMain/.../document/pgp/OpenPgp.kt` | `expect object OpenPgp`、`OpenPgpTrust`、`OpenPgpTrustedKey`、`OpenPgpReport` | App 需要的 OpenPGP 運算：解析公開金鑰、取出金鑰封包、加密、以會話金鑰解密、取出簽章訊息的內容；信任等級與報告模型 |
| `core/jvmCommonMain/.../document/pgp/` | `OpenPgp` actual、`OpenPgpInspection` | 以 Bouncy Castle `bcpg` 實作；`DocumentInspector` 新增 `DocumentFormat.OPENPGP` 與 `SignatureFormat.OPENPGP` |
| `app/commonMain/.../OpenPgpModel.kt` | `OpenPgpModel` | 公開金鑰清單與信任（儲存表 `DiwOpenPgpKeys`）、卡片自簽憑證（`DiwOpenPgpCardCerts`）、讀卡、WKD 與 keys.openpgp.org 查詢 |
| `app/commonMain/.../FilesModel.kt` | `SignerChoice.OpenPgp`、`SignForm.OPENPGP_DETACHED` | 以卡簽署（.asc 與 X.509 格式）、以卡解密、取出簽章訊息內容、加密給收件人 |
| `app/commonMain/.../ui/OpenPgpScreens.kt` | 簽署者選擇、卡片資訊、公開金鑰清單、文件頁 OpenPGP 區塊、加密對話框 | |

新增依賴 `org.bouncycastle:bcpg-jdk18on`（與 bcprov、bcpkix 同版，Renovate 同一組更新）。卡片 APDU 與簽章封包是 commonMain 純 Kotlin，不需要 bcpg；查驗、加密與解密用 bcpg 以涵蓋 v3／v4／v6、壓縮、各種演算法。

## 5. 讀卡流程（不需 PIN）

1. `SELECT` AID `D2 76 00 01 24 01`（P1=04，Le=00）。
2. `GET DATA 6E`（Application Related Data）：AID（版本、廠商、序號）、historical bytes、extended capabilities（C0）、三把金鑰的演算法屬性（C1 簽章、C2 解密、C3 認證）、PW 狀態（C4：PW1 是否每次簽章都要驗證、最大長度、剩餘次數）、指紋（C5）、產生時間（CD）。
3. `GET DATA 65`（持卡人姓名 5B）、`5F50`（公開金鑰 URL）、`7A`（簽章計數 93）；不支援的資料物件略過。
4. 每把金鑰：`GENERATE ASYMMETRIC KEY PAIR`（00 47 81 00，CRT B6／B8／A4）讀公開金鑰（RSA：81 模數、82 指數；EC：86 點）。卡上沒有金鑰（指紋全 0 或 6A88）時標示為空。
5. 持卡人憑證：3.0 以上以 `SELECT DATA`（00 A5，P1 為出現次序：認證 0、解密 1、簽章 2，資料 `60 04 5C 02 7F 21`）再 `GET DATA 7F21`；部分 YubiKey 韌體要省略 `60` 外層，失敗時改用 `5C 02 7F 21` 再試。2.x 卡只讀得到認證金鑰的憑證。
6. KDF-DO（F9，3.3 起，extended capabilities 第 0 位元）：啟用 `KDF_ITERSALTED_S2K` 時，PIN 先以卡片指定的雜湊、鹽與次數做 iterated-salted S2K 再送 VERIFY。

回應超過 256 位元組（RSA 4096 公開金鑰、6E）以 61XX 與 GET RESPONSE 取得，`NfcCardChannel` 已處理。

## 6. 由卡片重建公開金鑰與指紋比對

OpenPGP 的指紋包含金鑰產生時間與（ECDH）KDF 參數，卡片只存公開金鑰的數學部分。錢包以卡上的產生時間（CD）組出 v4 公開金鑰封包，計算 SHA-1 指紋，與卡上指紋（C5）比對：

- RSA：演算法 1。
- ECDSA（19）與 EdDSA（22，Ed25519 legacy）：曲線 OID 加點。
- ECDH（18）：KDF 參數依序嘗試 GnuPG 的預設（P-256／Curve25519：SHA-256＋AES-128；P-384：SHA-384＋AES-256；P-521：SHA-512＋AES-256），再嘗試其他雜湊與 AES 長度的組合，取指紋相符的一組。
- 公開金鑰清單裡已有同指紋的金鑰時，直接採用該封包。

比對不到時（例如由其他工具以非標準參數產生），OpenPGP 分離式簽章與解密會停止並說明原因：簽出的指紋對方無法以你公布的公開金鑰找到。卡上指紋全為 0（金鑰由卡片產生但沒有寫指紋）時以重建的封包為準並提示。X.509 格式不受影響。

## 7. 簽署

### 7.1 OpenPGP 分離式簽章（`.asc`）

- 金鑰：卡片的簽章金鑰（C1）。
- 雜湊：RSA、P-256、brainpoolP256r1、Ed25519 用 SHA-256；P-384、brainpoolP384r1 用 SHA-384；P-521、brainpoolP512r1 用 SHA-512。
- 簽章封包 v4，類型 0x00，hashed 子封包：簽章建立時間（2）、簽署者指紋（33，v4）；unhashed：簽署者 key ID（16）。
- 卡片輸入：RSA 送 DigestInfo（卡片做 PKCS#1 v1.5 填充）；ECDSA 送雜湊值；EdDSA 送雜湊值（OpenPGP 的 EdDSA 簽的就是雜湊）。輸出：RSA 原始簽章；ECDSA 與 EdDSA 為 r‖s，各自轉為 MPI。
- 簽完以重建的公開金鑰檢查簽章值，不符不保存；結果存為 `原檔名.asc`，並記住原檔（與 `.p7s` 相同），立即以查驗流程檢查。

### 7.2 X.509 文件格式

卡片簽章金鑰為 RSA（任何長度）或 EC P-256 時，可用於現有全部格式（`DocumentSigner`）：

- 卡上有簽章金鑰的持卡人憑證，且憑證公開金鑰與卡上金鑰相同：用這張憑證，信任依憑證鏈判定。
- 沒有：以卡片簽一張自簽憑證（與錢包金鑰相同，T3），以卡上指紋快取在錢包內，之後不必再簽。
- 其他演算法（Ed25519、P-384、P-521、brainpool）只能做 OpenPGP 簽章，簽署畫面會說明。

### 7.3 PIN 與安全規則

- PW1 長度 6 到卡片宣告的最大值（C4），只存在記憶體中這一次簽署，不保存、不記錄。
- 每次 PSO:CDS 前都 VERIFY（P2=81），不依賴卡片的「PIN 一次有效多次」設定；解密前 VERIFY P2=82。
- 錯誤 PIN 立即停止並顯示剩餘次數（63CX）；剩 0 次或 6983 顯示已鎖定，請以重設碼或管理 PIN 在電腦上解鎖。
- Android NFC：讀卡資訊與簽署分兩次感應；USB 與 PC/SC 一次完成。簽章值一律以第一次讀到的公開金鑰檢查，換卡會被拒絕。

## 8. 查驗

`DocumentInspector.sniff` 在 CMS 與 PDF 之前認出 OpenPGP：armor 標頭（`-----BEGIN PGP SIGNATURE-----`、`SIGNED MESSAGE`、`MESSAGE`、`PUBLIC KEY BLOCK`）或二進位封包（新舊格式封包標頭，第一個封包為簽章、one-pass、壓縮、literal、PKESK／SKESK 或公開金鑰）。副檔名 `.asc`、`.sig`、`.gpg`、`.pgp` 只用於平手判斷。

| 內容 | 處理 |
|---|---|
| 分離式簽章 | 需要原檔（同 `.p7s`：簽完自動關聯，匯入時可「選擇被簽署的檔案」），以 binary 或 canonical text（0x01，CRLF 正規化）驗證 |
| 明文簽章訊息 | 依 RFC 9580 7.1 去除 dash-escape 與行尾空白後驗證，可預覽文字 |
| 內含簽章訊息 | 解壓、取 literal data 驗證，可把內容另存成檔案 |
| 公開金鑰檔 | 顯示主金鑰與子金鑰指紋、使用者 ID、演算法、建立與到期時間、撤銷狀態，提供「加入公開金鑰清單」 |
| 加密訊息 | 列出收件人 key ID 或指紋與演算法、加密演算法；收件人是自己的 OpenPGP 卡時提供「以 OpenPGP 卡解密」 |

每個簽章產生一個 `SignatureInfo`（`SignatureFormat.OPENPGP`）：
- `integrity`：找到公開金鑰時為驗證結果；找不到為 NOT_CHECKED，並說明簽署者指紋，文件頁提供查詢簽署者的公開金鑰。
- 子金鑰簽章需有有效的子金鑰綁定簽章且金鑰旗標允許簽章（沒有旗標時接受）；主金鑰或子金鑰在簽章時已撤銷或到期時 `certificateValidity` 為 FAIL。
- `signer` 以 `CertInfo` 表示：subject 為主要使用者 ID，serialHex 為指紋，publicKey 為演算法描述，der 留空（不是 X.509）。
- `claimedTime` 為簽章建立時間（宣稱，未經時戳）；檔案層的 RFC 3161 時戳照舊可加。

## 9. 公開金鑰清單與信任

OpenPGP 沒有 X.509 信任根。錢包不計算完整的 Web of Trust，而是讓使用者對每把金鑰明確決定（同 GnuPG 的 validity 與 owner trust 的簡化版），對應錢包的信任等級：

| 信任（`OpenPgpTrust`） | 等級 | 如何得到 |
|---|---|---|
| 自己的 OpenPGP 卡（OWN_CARD） | T2，USER_ANCHOR | 只能由錢包讀取卡片設定：讀卡後「加入公開金鑰清單」、以卡簽署或解密時卡片金鑰不在清單（或只是未核對）時自動標示 |
| 已核對指紋（VERIFIED） | T2，USER_ANCHOR | 使用者確認已透過可靠管道核對完整 40 位指紋（對話框列出分組指紋，並提醒短 ID 可偽造） |
| 未核對（UNVERIFIED） | T3；由介紹人認證時升為 T2 | 匯入檔案、文件中的金鑰、WKD 或 keys.openpgp.org 查到的金鑰的預設 |
| 不信任（DISTRUSTED） | T4，簽章一律不可信 | 使用者設定；保留在清單避免被重新匯入當成新金鑰 |
| 不在清單 | 不判定 | integrity NOT_CHECKED，整體 PARTIAL，提供查詢 |

介紹人：已核對或自己的卡的金鑰可設為介紹人，它對某把「未核對」金鑰的使用者 ID 所做的有效認證（非撤銷）讓該金鑰升為 T2，報告寫出「由某某認證」。只算一層，不往下傳遞，以免信任在使用者不知情下擴散。

介紹人的認證必須由介紹人的主金鑰在有效期間內做出：介紹人主金鑰已因外洩等原因撤銷（硬撤銷）時一律不算，因退休或被取代而停用時只算停用前的認證；認證本身已過期，或之後被同一把金鑰以認證撤銷收回時也不算。

清單規則：

- 以主金鑰指紋為鍵；同一把金鑰再次匯入時與已存的憑證合併（`OpenPgp.merge`，Bouncy Castle `PGPPublicKeyRing.join`），新的撤銷或到期會加入，少了撤銷的舊版或刪減版也拿不掉已存的撤銷；保留使用者的信任。
- 子金鑰必須有有效的綁定簽章才能簽章或加密。唯一的例外是錢包實際從持有人卡片讀到的金鑰（項目的 `cardKeys`，交給查驗與加密），因為由卡片建立的公開金鑰沒有綁定簽章。這樣把可信主金鑰的簽章全部刪掉、再附上別人的子金鑰的偽造憑證，簽章會判定金鑰無效，也不能拿來加密。
- 已有「不信任」的金鑰不會因重新匯入或查詢而變成可信。
- 只含卡片金鑰（沒有使用者 ID 與綁定簽章）的項目，在匯入涵蓋這些金鑰的完整公開金鑰時被取代，並沿用原本的信任；卡片讀取不會覆蓋已有的完整公開金鑰。
- 給查驗的順序是「不信任」優先，再依信任高低，避免同一把金鑰在兩個項目時誤判為可信。
- 清單或信任改變後，錢包重新檢查所有 OpenPGP 檔案。

查詢（都需使用者看過結果並以強提示確認才加入，加入後為未核對）：

- 電子郵件：先查該網域的 Web Key Directory（advanced：`openpgpkey.網域`，再 direct：`網域/.well-known/openpgpkey/hu/`，檔名為小寫本地部分 SHA-1 的 z-base-32），沒有時查 keys.openpgp.org `/vks/v1/by-email/`。只保留使用者 ID 含該地址的金鑰。
- 40 位指紋或 16 位金鑰 ID：keys.openpgp.org `/vks/v1/by-fingerprint/`、`by-keyid/`，只保留含該指紋或 ID 的金鑰。
- 回應超過 1 MB 拒絕。

## 10. 加密與解密

- 加密：選擇清單內一或多把有加密能力、未撤銷、不是「不信任」的金鑰（預設勾選自己的卡），以 AES-256、SEIPD v1（MDC）加密，literal data 帶原檔名，輸出 `原檔名.asc`（armor）或 `原檔名.gpg`，存為新檔。收件人有未核對的金鑰時以紅字提醒。
- 解密：讀卡比對收件人（PKESK v3 金鑰 ID 或 v6 指紋），不是寄給這張卡時在送出 PIN 前停止。RSA（1）：PSO:DECIPHER 送 `00`＋密文，卡片回傳去填充的會話資料（演算法、金鑰、檢查碼）。ECDH（18，NIST、brainpool 與 Curve25519）：送 `A6 { 7F49 { 86 臨時公開金鑰 } }` 取共享秘密，依 RFC 6637 以 KDF 與 AES Key Wrap 解出會話金鑰。v6 的 X25519（25）金鑰目前沒有 OpenPGP 卡支援，不實作。會話金鑰交給 bcpg 解密並檢查完整性（MDC 或 AEAD）；沒有完整性保護的舊式 SED 一律拒絕，MDC 不符就不保存。解出的檔案以 literal data 的檔名（清理後）存為新檔並檢查，內含的簽章另存為 `.asc` 分離式簽章與內容配對。
- 簽章訊息（gpg --sign）與未簽章的 literal data：文件頁「取出內容另存」，簽章同樣另存為 `.asc`。

## 11. 介面

- 簽署畫面：簽章格式多一個「OpenPGP 分離式簽章（.asc）」，選它時簽署者只有 OpenPGP 卡；其他格式在「實體卡／硬體憑證」群組多一個「OpenPGP 卡／YubiKey」。都可選讀卡機（含重新尋找）、輸入 PW1、先讀取卡片看金鑰、指紋、PIN 剩餘次數與是否有持卡人憑證；簽章金鑰不是 RSA／P-256 時說明 X.509 格式不可用。
- 文件頁：OpenPGP 簽章卡片顯示簽署金鑰指紋與「金鑰效力」，不顯示 X.509 的撤銷資訊列；OpenPGP 區塊列出檔案中的金鑰（可加入清單）、加密訊息的收件人與「以 OpenPGP 卡解密」、簽章訊息的「取出內容另存」、清單中沒有的簽署者的「查詢簽署者的公開金鑰」。分離式 `.asc`／`.sig` 沒有配對原檔時可「選擇被簽署的檔案」。其他動作加「以 OpenPGP 加密」。
- 設定 → 信任 →「OpenPGP 公開金鑰」：信任等級說明、匯入檔案、查詢、讀取自己的卡、每把金鑰的信任切換、介紹人、匯出／分享（armor）、移除。

## 12. 測試與驗收

- `test-servers` 的模擬 OpenPGP 卡（`CardChannel` 實作，以軟體金鑰回應 APDU，含 RSA-2048、P-256、Ed25519、Curve25519、KDF-DO、61XX 分段）：讀卡、指紋比對、PIN 錯誤次數、簽章、解密。
- 產生的 `.asc` 以 bcpg 與系統 `gpg --verify` 驗證（CI 有 gpg 時執行，沒有時略過該斷言）。
- `gpg` 產生的分離式、明文、內含簽章與加密訊息由 `DocumentInspector` 檢查與以模擬卡解密。
- 實機驗收（使用者）：YubiKey 5 NFC 以手機 NFC 與 USB、桌面 PC/SC 各簽一次 `.asc` 並以 GnuPG 驗證；以 GnuPG 加密給卡片後在錢包解密；有持卡人憑證與沒有時各簽一份 PAdES。

# ZKP 全景、驗證者身分／意圖揭露、信任分級 UI：研究筆記

> 撰寫日期：2026-10-10。對象：KMP + Compose Multiplatform（Android 先行）、以 Multipaz 為底層的數位身分皮夾。
> 標記：**【確認】** 表示已讀過原始規格、repo 或官方頁面；**【推論】** 表示依據已知資料推論，或憑記憶整理、尚未在本次研究中逐字核對。
> 原始檔（本次下載，供複查）：`/tmp/claude-0/-home-claude/1d918b7c-45c0-59bb-9eeb-d2fad55d6a21/scratchpad/dl/`（EUDI TS4/TS5/TS6/TS13/TS14、ARF Annex 2、Topic I/J、OpenID4VP 1.0 原始 md），以及 `.../scratchpad/repos/`（multipaz、zkID、eudi-app-android-wallet-ui、longfellow-zk 的淺層 clone）。

---

## 2026-10-16 查驗者信任前置條件

Zero-Knowledge Proof 並不能替代查驗者身份、同意用途與 Key Authorization 的驗證。PR #11 的 DC API 多重簽章已逐一驗簽；使用者匯入的 RICAL 只對明確標示 `isTrustAnchor` 的讀者 CA 建立信任，需另驗證清單發行者簽章。OpenID Federation 尚需真正的信任鏈與 Policy 驗證；此缺口不可藉由展示 ZKP 通過或 `client_metadata` 宣稱已解決。

## 0. 一頁重點

1. **短期最可行的 ZKP 是 Longfellow（Google）**：發行端不需改變（直接證明既有 mdoc 的 ECDSA P-256 + SHA-256 簽章），不需 trusted setup，只依賴雜湊（有後量子的潛力）。Multipaz 已有 `multipaz-longfellow` 模組（Android arm64/x86_64 JNI、iOS、JVM、Web），Google Wallet 已透過 DC API 支援 `mso_mdoc_zk`。【確認】
2. **BBS 家族**（IRTF CFRG draft-12、W3C `bbs-2023` CRD）效能最好、證明最小（約 272+32·i bytes），但**發行端必須改用 BBS 簽章（BLS12-381 配對曲線）**，HSM／SE 都不支援，ECDSA 裝置綁定也還沒有標準。EUDI TS14 把它定位為「第 2 階段（中長期）」。【確認】
3. **SD-JWT VC 的 ZK 化**：EUDI TS13 定義了 `zk-jwt`（Longfellow）的 circuit 規格，但 longfellow-zk 的 C++ repo 目前只有 mdoc circuit【確認：只看到 `lib/circuits/mdoc`】。以太坊基金會 zkID 的 **OpenAC**（Spartan2 + circom，MIT 授權，經 Mopro/UniFFI 上 Android/iOS）已有 SD-JWT（ES256）與 mdoc 的 PoC，並且**已在 TWDIW（moda-gov-tw）做酒類購買年齡驗證的整合 PoC**；circuit 內建 `roc_date`（民國日期）格式。【確認】
4. **驗證者身分**：OpenID4VP 1.0（2025-07 Final）定義了 7 種 client_id prefix 與 `verifier_info`。EUDI 的作法是「WRPAC（X.509，用 `x509_hash` 簽 request）＋ WRPRC（JWT `rc-wrp+jwt`／CWT，以 `verifier_info` 的 `format:"registration_cert"` 傳遞；在 18013-5 中放在 `ItemsRequest.requestInfo["euWrprc"]`）」。WRPRC 的內容包含法定名稱、`public_body`、`purpose`、`credentials`（可用來檢查是否超額請求）、`intermediary`、監管 DPA。【確認】
5. **「驗證者用 VC 證明自己」目前沒有成熟的標準**：OpenID4VP 的 `verifier_info` 是正式的擴充點，支援 claim-bound 與 key-bound 兩種 PoP。可在其中放入自訂 `format`，例如攜帶法人／代理憑證的 VP。W3C「Recognized Entities」（WD，實驗性）、DIF Linked VP、Well-Known DID Configuration 都只能做部分補充。【確認／推論見 §2.12】
6. **信任分級 UI**：ARF 規定，RP 驗證失敗時必須告知使用者，並由 wallet provider 決定是否阻擋；警告情境下「沉默或預先勾選不算同意」。EUDI 參考 App 和 Multipaz 都有現成的 UI 字串（見 §3），可以直接借鏡。【確認】

---

## 1. 任務一：ZKP 全景

### 1.1 總覽表

| 方案 | 成熟度 | 標準化 | 發行端需配合？ | 持有端／驗證端程式庫（語言、授權、平台） | 證明大小／時間（已知數據） |
|---|---|---|---|---|---|
| **Longfellow ZK**（Ligero + sumcheck，Frigo & shelat） | 已部署：Google Wallet（Bumble 登入）；EU AV blueprint 列為實驗功能 | IETF `draft-google-cfrg-libzk-02`（2026-07，Informational；CFRG 正拆成 Fiat-Shamir／通用方案／參數／circuit 四份文件）；ISO 18013-5 第二版 `ZkRequest`/`ZkDocument`；EUDI TS13 的 `longfellow-libzk-v1` | **不需要**（證明既有 mdoc 的 ECDSA） | google/longfellow-zk（C++，Apache-2.0，另有 Rust 改寫）；ISRG `zk-cred-longfellow`（Rust，bit-compatible）；Multipaz `multipaz-longfellow`（KMP：Android JNI、iOS、JVM、Web）；Google 提供 Docker 驗證服務 | TS13：Pixel 6 Pro 產生 mdoc age_over_18 證明約 0.8 s（TS4 寫 1.2 s），驗證約 0.6 s，證明約 400 KB。Mac M4 上 ECDSA PoP：prover 16.7–38 ms。irmago 估計證明時峰值記憶體約 88 MB；單一屬性 circuit 壓縮後 278 KB、解壓後 88 MB |
| **BBS（IRTF CFRG）** | 規格穩定中，生產部署少 | `draft-irtf-cfrg-bbs-signatures-12`（2026-09-28，Active RG doc）；blind `-02`；per-verifier-linkability（pseudonym）`-03`（2026-06）；W3C DI BBS CRD 2026-04-07；JOSE JWP/JPA draft-14 以 BBS 為 Required | **需要**（發行端用 BBS 在 BLS12-381 上簽） | zkryptium（Rust，Apache-2.0，實作 bbs-12、blind-02、pvl-03）；docknetwork/crypto（Rust，Apache-2.0，有 wasm，無官方行動綁定）；mattrglobal/pairing_crypto（Rust，Apache-2.0，但停在 draft-03）；Ubique zkattest-rs（ECDSA↔BBS 橋接） | TS4：證明產生／驗證 < 2 ms；大小 272+32·i bytes（i 為隱藏訊息數） |
| **BBS# / SAAC**（無配對 KVAC 變體，Orange 等） | 研究／試點 | 無（eprint 2025/619、2025/513） | **需要**，且需要與發行端額外互動（verify MAC 或 oblivious proof），量級接近批次發行 | Orange BBS-SHARP 文件 repo | TS4：高階手機 < 2.5 ms；大小 416+32·U bytes |
| **BBS + ECDSA PoP 混合**（裝置綁定） | 研究 | 無；TS14 建議第 1 階段使用 Schnorr-based（需非標準 T256 曲線） | 需要（BBS 簽章內含 ECDSA 公鑰） | docknetwork `equality_across_groups`、Ubique zkattest-rs | TS4：CDLS 約 160 KB、Mac M1 610/450 ms；Woo2025 406 B、1.6/1.7 ms（伺服器） |
| **Crescent**（Microsoft，Groth16） | 研究 1.0、未稽核 | 無（eprint 2024/2013） | 不需要（JWT RS256／mDL ECDSA） | microsoft/crescent-credentials（Rust，MIT） | TS4：Xeon 線上 29 ms／驗證 12 ms（含裝置綁定 315/184 ms）；離線準備 19 s；**setup 參數 580 MB**、proof 1019 B；需 circuit-specific trusted setup |
| **OpenAC / zkID**（以太坊基金會 PSE，Spartan2 + circom on secq256r1） | PoC；論文 eprint 2026/251；spec 狀態為 raw | 無（自家 COSS spec `1/OPENAC`，提及 ARF 對應） | 不需要（SD-JWT ES256、mdoc） | privacy-ethereum/zkID（MIT）；mobile 走 Mopro（UniFFI）＋Flutter；`openac-sdk` | Pixel 10 Pro：Prepare 5.2 s（離線、可重用，峰值 2.27 GiB）、Show 證明 308 ms、驗證 65 ms；iPhone 17：2.1 s／85 ms。Prepare proof 76–308 KB、Show proof 40.5 KB；Prepare proving key 257 MB–1.5 GB |
| **zk-creds**（Rosenberg 等，Groth16/arkworks） | 學術 | 無 | 不需要（可包裝既有文件，例如護照） | arkworks Rust（Apache/MIT）【推論】 | 無本次核對數據 |
| **CL / AnonCreds v1** | 生產（Hyperledger Indy/Aries 生態） | AnonCreds v1 spec（Hyperledger）；非 ISO/IETF | **需要**（CL-RSA 簽章、需 ledger 或 registry） | anoncreds-rs（Rust，Apache-2.0；Node/RN/Python 綁定，無官方 Kotlin/Swift） | 證明數 KB 級、RSA 群運算較慢【推論】 |
| **PS（Pointcheval–Sanders）** | 學術／ISO 20008 部分 | ISO/IEC 20008、24843（PWI）；TS14 認為次於 BBS | 需要 | docknetwork `coconut` | TS14：與 BBS 效能差異應 < 100 ms |
| **U-Prove**（Microsoft） | 舊、基本停滯 | 開放規格（OSP） | 需要；每個 token 只能用一次（需批次） | U-Prove SDK（C#/JS）【推論】 | — |
| **通用 SNARK on mobile**（Groth16/Halo2/Noir；Spartan） | 工具鏈成熟度不一 | — | 視 circuit 而定 | Mopro（Rust，Apache/MIT，UniFFI → Kotlin/Swift/Flutter/RN） | Mopro：S23 Ultra 上 SHA256 Groth16（rapidsnark）228 ms、RSA 950 ms；Halo2 RSA 在手機上記憶體不足而崩潰；Noir 在 Pixel 6 上 Keccak 1.3 s |

### 1.2 Longfellow（mdoc；IETF draft-google-cfrg-libzk）

- 【確認】`draft-google-cfrg-libzk-02`：2026-07，作者為 Frigo、shelat（Google），Informational。只依賴抗碰撞雜湊，**無 CRS／trusted setup**。草案本身只規範證明系統；ECDSA／SHA-256／mdoc circuit 另有文件。https://ftp.sjtu.edu.cn/pub/internet-drafts/draft-google-cfrg-libzk-02.html
- 【確認】IETF 126 CFRG 投影片：ISRG 第二個實作與第一個 bit-compatible；已有 Trail of Bits、Ligero、ISRG 三份安全審查；效能提升超過 20%。EU、Apple、Google 的回饋都**偏好 PQ 方案**。https://datatracker.ietf.org/meeting/126/materials/slides-126-cfrg-longfellow-zk-00
- 【確認】IETF 124 dispatch：已部署於 Google Wallet（用於 Bumble）；Multipaz、wwWallet 表示有興趣。https://datatracker.ietf.org/meeting/124/materials/slides-124-dispatch-longfellow-zero-knowledge-credentials-00
- 【確認】ISO 18013-5 第二版（CD ballot resolution／DIS 草案）結構（取自 EUDI TS13）：
  - `DeviceRequest.docRequests[].itemsRequest.requestInfo["zkRequest"] = { systemSpecs:[{zkSystemId, system:"longfellow-libzk-v1", params:{…circuitHash…}}], zkRequired: bool }`
  - `DeviceResponse` 以 `ZkDocument { documentData: #6.24(ZkDocumentData{docType, zkSystemId, timestamp, issuerSigned?, deviceSigned?, msoX5chain?}), proof }` 取代 `Document`。
  - irmago 的整理中，`params` 包含 `version`、`num_attributes`、`block_enc_hash`、`block_enc_sig`、`circuit_hash`；v6 circuit 依屬性數 1–4 各有一個。https://github.com/privacybydesign/irmago/issues/724
- 【確認】OpenID4VP DCQL（EUDI TS13）：`format:"mso_mdoc_zk"`，`meta.zk_system_type:[{zkSystemId, system:"longfellow-libzk-v1", params:{circuit_hash}}]`。SD-JWT 用 `format:"zk-jwt"`。Google Wallet 的線上 RP 文件也使用 `mso_mdoc_zk` + `longfellow-libzk-v1`。https://developers.google.com/wallet/identity/verify/accepting-ids-from-wallet-online
- 【確認】Multipaz：`org.multipaz.mdoc.zkp.ZkSystem`（`generateProof(spec, MdocDocument, sessionTranscript, timestamp)`、`verifyProof(...)`）、`ZkSystemRepository`、`multipaz-longfellow/LongfellowZkSystem`。circuit 檔內建於 `src/commonMain/circuits`（v6/v7 × 1–4 屬性）。JNI 只提供 arm64-v8a 與 x86_64（**不含 armeabi-v7a**）。OpenID4VP 的 `mso_mdoc_zk` 已處理。https://klibs.io/project/openwallet-foundation/multipaz
- 【確認】驗證端注意：proof 隱藏了 MSO 與 DS 憑證，**驗證者必須事先取得發行端（IACA/DS）公鑰**（帶外取得，或在 circuit 中證明「由清單內某把 key 簽發」）。EU AV profile 的 ZK 只走 DC API + `org-iso-mdoc`，不走 OpenID4VP（irmago 的整理）。
- 【確認】EU 年齡驗證 blueprint 路線圖：2026-01 釋出 Android DC API 版 ZKP，2026-07 釋出 iOS 版。https://docs.ageverification.dev/Roadmap/

### 1.3 BBS／BBS+ 與擴充

- 【確認】`draft-irtf-cfrg-bbs-signatures-12`（2026-09-28，IRTF Informational，Active RG Document，尚未進入 IRSG 審查）。https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- 【確認】`draft-irtf-cfrg-bbs-per-verifier-linkability-03`（2026-06）：pseudonym 擴充。blind 擴充為 `draft-irtf-cfrg-bbs-blind-signatures-02`（zkryptium 的實作版本）。https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-03
- 【確認】W3C Data Integrity BBS Cryptosuites v1.0（`bbs-2023`）CRD 2026-04-07。功能包括 baseline、anonymous holder binding、credential-bound pseudonyms（`nym_secret` + `nym_domain`）、holder binding + pseudonym。**可選功能被標為 at-risk**：IETF 沒有同步成為 RFC，或缺少兩個獨立實作，就會被移除。https://www.w3.org/TR/2026/CRD-vc-di-bbs-20260407/
- 【確認】JOSE JWP：`draft-ietf-jose-json-proof-algorithms-14`（2026-07），BBS 為 Required；另有 SU-ES256（single-use ECDSA）、MAC-*。編輯註記仍預期會有重大變更。https://datatracker.ietf.org/doc/draft-ietf-jose-json-proof-algorithms/
- 【確認】EUDI TS14（v1.0，2026-02-27，預計移交 ETSI）重點：
  - mdoc／SD-JWT 與 MMS 本質上不相容（單一簽章 vs. 多訊息向量），所以**另定新格式**（範例用 JWP）。
  - 第 1 階段（短中期）：PID LoA High 採用無配對 MMS，或「BBS + 以 circuit／Schnorr 證明 ECDSA 裝置綁定」；第 2 階段（硬體支援配對曲線後）用 BBS（Recommendation 2）。
  - BBS 因 Cheon attack，**長期需要 192-bit 安全等級的曲線**。
  - Range proof 建議用 Bulletproofs（Rec. 6），commitment 用 Pedersen（Rec. 4）。
  - 撤銷建議：第 1 階段用「簽章的索引對（signed pairs）＋短效撤銷證明」（Rec. 9）；Token Status List 不符合 ZKP_07 不可連結性；Accumulator 擴展性尚待驗證。
  - https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/main/docs/technical-specifications/ts14-zkps-from-mms.md
- 【確認】TS4 指出：BBS+ 的標準版本不處理綁定到 WSCD 公鑰的問題；配對曲線不被 HSM／SE／SIM 支援。

### 1.4 SD-JWT VC 的 ZK 化

- 【確認】EUDI TS13 定義了 SD-JWT 的 circuit 約束（驗證 issuer P-256 簽章、KB-JWT 簽 nonce、`cnf` 中的 dpk、`nbf<now<exp`），以及回應格式（base64url JSON + "." + proof）。但 TS13 的 JWT circuit 適用於「**不含 disclosure 的 SD-JWT**」。https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/main/docs/technical-specifications/ts13-zksnarks.md
- 【確認】google/longfellow-zk 的 `lib/circuits` 只有 `mdoc`、`ecdsa`、`sha`、`cbor_parser`、`mac` 等，沒有 JWT circuit（2026-09-30 HEAD）。所以 **SD-JWT 的 Longfellow 實作需要自行開發，或等待上游**。
- 【確認】OpenAC（zkID）：
  - 兩階段 Prepare（離線驗證發行簽章、可 reblind 重用）與 Show（線上回應 predicate + 裝置綁定 + nonce）。
  - 支援的 claim 格式有 `bool`、`uint`、`iso_date`、`roc_date`、`string`。
  - 採用 Spartan2 + Hyrax 類承諾，跑在 secq256r1 上（屬於橢圓曲線方案，**非 PQ**；這是根據 circom 以 secq256r1 為原生域所做的【推論】）。
  - 已有 TWDIW 整合 PoC（Driver License VC → age≥18，回傳 pass/fail）。
  - https://github.com/privacy-ethereum/zkID 、https://github.com/zkmopro/TWDIW-integration 、https://eprint.iacr.org/2026/251
- 【推論】做法比較：(a) circuit 證明既有 ES256 簽章（Longfellow／OpenAC／Crescent），發行端不用改；(b) 改發 BBS-SD-JWT 或 JWP（發行端要改）；(c) 退回批次發行 + 一次性金鑰，用 SD-JWT VC 原生方式達成 RP 間的不可連結（ARF 目前的主流做法）。

### 1.5 Anonymous Credentials 經典系（CL、PS、U-Prove）

- 【確認】anoncreds-rs（Apache-2.0）實作 AnonCreds v1。官方綁定只有 Node、RN、Python，沒有 Kotlin/Swift UniFFI。https://github.com/hyperledger/anoncreds-rs
- 【確認】ETSI TR 119 476-1 V1.3.1（2025-08）把 BBS/BBS+/BBS#/CL/PS 歸為「multi-message signatures，可完全不可連結但未完全標準化」；ISO/IEC 20008 已標準化部分 BBS 與 PS；ISO/IEC 24843 與 27565 在推進中。zk-SNARK 類（Cinderella、zk-creds、FIDO-AC、Crescent、ECDSA AC）被認為仍在研究階段。https://www.etsi.org/deliver/etsi_tr/119400_119499/11947601/01.03.01_60/tr_11947601v010301p.pdf
- 【推論】U-Prove 已無活躍維護，不建議納入，只在相容性表中列為「不支援」。

### 1.6 ISO／EUDI／ETSI／W3C 的 ZK 進展

- 【確認】**ISO/IEC 27565:2026**「Guidelines on privacy preservation based on zero-knowledge proofs」，2026-02-10 出版（指引性質，非協定）。https://committee.iso.org/standard/80398.html
- 【確認】**ISO/IEC 18013-5 第二版**：WG10 在 2026-09 的 ETSI/CEN workshop 上仍表示「finalising」；新增 extended request（來自 23220-4）、可在 request 中要求非 mdoc 格式（如 SD-JWT）。ZK 結構見 §1.2（Multipaz 目前以「最新 DIS 草案」為目標）。**RICAL**（Annex F，Reader Identity CA List）提供 reader 信任清單。https://docbox.etsi.org/ESI/Open/workshops/202609%20ETSI_CEN%20workshop%20on%20EU%20Digital%20Framework%20centring%20on%20the%20EU%20Identity%20Wallet/Session%2004%20-%202%20-%2018013-5-Session-4-Geluk.pdf
- 【確認】**EUDI ARF 3.0.0**，Annex 2 Topic 53（ZKP_01..09，來自 Topic G 討論文件 v1.4，2025-03-30）：
  - ZKP_01：隱藏所有屬性的前提下，要能證明屬性值、有效期、未撤銷、WSCD 金鑰綁定。
  - ZKP_03（SHOULD）：與 PID 綁定。
  - ZKP_04（SHOULD）：可驗證的 pseudonym。
  - ZKP_05：遠端與近場都要可用。
  - ZKP_06（SHOULD）：能對既有 18013-5／SD-JWT VC 產生證明。
  - ZKP_07：不得引入可追蹤的額外通訊。
  - ZKP_08：**只能使用 ECCG Agreed Cryptographic Mechanisms v2.0 中的演算法**。
  - ZKP_09：不得妨礙 LoA High。
  - 來源：https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/main/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md 、https://eudi.dev/latest/discussion-topics/g-zero-knowledge-proof/
- 【確認】EUDI TS4（v1.0.1）結論：「目前沒有任何 ZKP 方案成熟到能直接整合進 EUDI Wallet」，因此分出 TS13（circuit 類，Longfellow；範圍只含遠端、不含 pseudonym、不含需 trusted setup 的方案）與 TS14（MMS 類）。
- 【確認】**W3C DC API**：WD 2026-09-04。protocol registry 為 `openid4vp-v1-unsigned/signed/multisigned`、`org-iso-mdoc`（18013-7 Annex C）。API 本身與 ZK 無關，ZK 是透過協定內的 `mso_mdoc_zk` 或 `ZkRequest` 傳遞的。https://www.w3.org/TR/digital-credentials/

### 1.7 Range proof／年齡證明、不可連結性、可撤銷性

- **年齡**：
  - mdoc 原生的 `age_over_NN` 加上選擇性揭露，就能證明年齡，但 MSO 簽章、deviceKey 與 salt 都可被用來連結。【確認】
  - Longfellow 能證明 `age_over_18==true`，同時隱藏 MSO／簽章（ZK）。【確認】
  - OpenAC 可以直接對 `roc_birthday <= X` 做比較（真正的 range predicate）。【確認】
  - BBS 系列用 Bulletproofs（TS14 Rec. 6）。【確認】
- **不可連結性**：
  - SD-JWT／mdoc 要靠批次發行、每次使用不同的 salt 與綁定金鑰，才能做到 RP 間不可連結；而且**無法防止 RP 與發行端串通**（ETSI TR 119 476）。【確認】
  - ZK 方案可以防止串通（TS13 的目標）。【確認】
- **撤銷**：
  - TS13：發行端每個 epoch 對已撤銷 ID 排序後，簽署相鄰的 `(id_i, id_{i+1}, ep)` 對；持有者在 circuit 中證明 `Lid < ID < Rid`。witness 是常數大小、可公開下載，不需要 accumulator。【確認】
  - TS14：可用 accumulator（docknetwork `vb_accumulator`、KB universal）、短效證明、signed pairs、Token Status List（可連結）、VLR 等，並給出比較。【確認】
  - SMT（Sparse Merkle Tree）的非成員證明：概念上等價於 signed-pairs 或 Merkle 路徑，用 circuit 證明 log(n) 路徑即可（TS13 有討論 Merkle tree 方案的缺點：發行端每天要重算全部有效憑證）。【確認／推論】

### 1.8 對本專案的 ZK 架構建議【推論】

- 在 `ZkSystem` 介面之上建立抽象層 `ZkBackend`：實作有 `Longfellow`（Multipaz 現成）、`OpenAC`（Rust → UniFFI → Kotlin/Native 或 JNI）、`BBS`（zkryptium → UniFFI）。以 DCQL `format`／`zk_system_type` 做路由。
- circuit 檔很大：依 circuit_hash 按需下載，並驗證 SHA-256，避免 APK 膨脹（約 1.1 MB 壓縮；OpenAC proving key 可能數百 MB，不適合放進 App）。
- 在背景執行緒或 WorkManager 中證明；低階機需要逾時與退回機制（例如 > 8 s 就改用一般 mdoc 回應，並讓使用者知道隱私等級較低）。

---

## 2. 任務二：驗證者（RP）身分與意圖揭露

### 2.1 OpenID4VP 1.0 client_id prefix【確認】

來源：OpenID4VP 1.0 Final（2025-07-09）§5.9.3 原始 md：https://raw.githubusercontent.com/openid/OpenID4VP/main/openid-4-verifiable-presentations-1_0.md 、https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

| prefix | 語意 | 驗證方式 | 能否簽章 |
|---|---|---|---|
| `redirect_uri:` | client_id 即 redirect/response URI；metadata 放在 `client_metadata` | 無密碼學驗證 | **不能**簽 |
| `openid_federation:` | Entity Identifier；忽略 request 中的 `client_metadata`；可附 `trust_chain` | 建立 Federation Trust Chain，套用 policy 後取得 metadata | 是 |
| `decentralized_identifier:` | DID；`kid` 指向 DID Document 的 verificationMethod | DID Resolution | 是 |
| `verifier_attestation:` | `sub` 必須等於 client_id；request 用 `cnf` 金鑰簽；attestation 放在 JOSE header `jwt` 中 | `iss` 必須是 wallet 信任的簽發者；`typ: verifier-attestation+jwt`；必填 `iss`/`sub`/`exp`/`cnf`；可選 `redirect_uris` 約束 | 是 |
| `x509_san_dns:` | DNS 名稱須等於 leaf 憑證的 dNSName SAN；憑證鏈放 `x5c` | PKI 鏈；非 DC API 時 redirect_uri FQDN 必須相符（除非 client 已受信任） | 是 |
| `x509_hash:` | leaf 憑證 DER 的 SHA-256（base64url） | PKI 鏈 | 是 |
| `origin:` | 保留給 DC API，**wallet 不得在 request 中接受**；DC API 回應的 audience = `origin:<Origin>` | 由平台提供 Origin | — |

- 另外：使用前五種可簽章 prefix 時，Verifier 必須能安全保存私鑰。這對「原生 App 驗證者」是部署限制。
- **HAIP 1.0 Final（2025-12-24）**：簽章 request **必須使用 `x509_hash`**；`x5c` 中不得包含 trust anchor，也不得自簽；DC API 須支援 unsigned／signed／multi-signed，回應用 `dc_api.jwt`；DCQL `trusted_authorities` 必須支援 `aki`。https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html
- **EUDI**：RPA_02 註明 OpenID4VP 走 HAIP 的 `x509_hash`；ETSI TS 119 472-2 V1.2.1 寫明「shall use x509_hash」。

### 2.2 `verifier_info`（OpenID4VP 1.0 新增）【確認】

- 結構為陣列，每個元素是 `{ format (必填，建議 collision-resistant), data (物件或字串，例如 JWT), credential_ids? (對應 DCQL id；省略即套用到全部) }`。
- 用途舉例：registration certificate、policy statement、角色證明（如 PSD2 PSP）。Wallet 遇到不認得的類型時 **SHOULD 忽略**。
- PoP 有兩種模型：
  - **claim-bound**：以 `sub` 等欄位綁定簽 request 的憑證 DN 或 `client_id`。
  - **key-bound**：Verifier 用 attestation 內或相關的金鑰，對 `nonce` + `client_id` 簽章。
- multi-signed（JWS JSON）時，`client_id` 與 `verifier_info` 必須放在各 signature 的 protected header 中。也就是說，**同一個 request 可以帶不同信任框架的 client_id，各自配一組 verifier_info**。
- EUDI 用法（ETSI TS 119 472-2 §6.3.2.2）：`{"format":"registration_cert","data":"<base64url(serialized WRPRC)>"}`，**不得有 `credential_ids`**；有 WRPRC 就必須附上（RPRC_19：每個 request 帶一張、by value）。德國 sandbox 文件則直接把 JWT 字串放進 `data`。https://etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf 、https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/rp/onboarding/registrar_certificate_usage

### 2.3 DCQL 與 transaction_data【確認】

- DCQL：`credentials[]`（`id`、`format`、`meta`、`claims[].path`、`values`、`claim_sets`）、`credential_sets`（`options`、`required`）、`trusted_authorities`（`aki`／`etsi_tl`／`openid_federation`）。
- 規範指出 Verifier **SHOULD** 在送出前向使用者說明查詢目的，但 OpenID4VP 本身**沒有標準化的 `purpose` 欄位**。目的需透過 WRPRC 的 `purpose` 或自訂 `verifier_info` 傳遞。【確認：規格只有 UI 考量說明】
- `transaction_data`：base64url JSON 陣列，每筆都必須有 `type` 與 `credential_ids`；wallet 不支援時**必須回錯**；資料要被持有者的綁定金鑰簽入（例如 SD-JWT 的 KB-JWT `transaction_data_hashes`）。用於支付 SCA、QES 簽署。Multipaz consent UI 已有字串「Includes transaction data:」。

### 2.4 W3C DC API 與 origin【確認】

- OpenID4VP Appendix A：
  - signed request 必須帶 `expected_origins`，wallet 要以**純字串比對**平台提供的 Origin，不符就回 `invalid_request`；unsigned request 中的 `expected_origins` 要忽略。
  - unsigned request 必須忽略 `client_id`。
  - 回應的 audience 為 `origin:<Origin>`。
- Android App origin 格式為 `android:apk-key-hash:<…>`（Google Wallet 文件）。
- **ARF RPA_01a／RPA_07a**：RP 驗證與使用者同意**不得交給瀏覽器或 OS 代為處理**，必須由 wallet 自己完成。
- ⚠ Multipaz `OpenID4VP.kt` 在 wallet 端仍有 `// TODO: handle expected_origins`（2026-10 clone）。**需要自行補上**，否則有 relay 攻擊風險。【確認：程式碼註解】

### 2.5 ISO/IEC 18013-5 reader authentication 與 18013-7【確認】

- Reader 在 `ReaderAuthentication`（含 SessionTranscript 與 ItemsRequest）上以 X.509 reader 憑證簽 COSE_Sign1，`x5chain` 帶鏈。
- 第二版加入 RICAL（Annex F），是 reader 根 CA 清單，相當於 VICAL 的 reader 版。MATTR 建議把 `display_name`、`logo_uri`、`privacy policy`、aggregator 資訊以 CBOR 自訂 OID 擴充放進 leaf reader 憑證。https://learn.mattr.global/docs/digital-trust-service/rical-overview
- Multipaz 有 `RicalTrustManager`、`VicalTrustManager`、`CompositeTrustManager`、`ConfigurableTrustManager`，以及 `TrustMetadata(displayName, displayIcon, displayIconUrl, privacyPolicyUrl, disclaimer, testOnly, extensions)`。
- EUDI 的 WRPRC 在 18013-5 中放在 `ItemsRequest.requestInfo["euWrprc"]`（bstr）；ReaderAuth 仍用 WRPAC（TS 119 472-2 §5.3.2）。
- 18013-7：Annex A（OpenID4VP redirect，ARF 中為 MAY）、Annex C（DC API `org-iso-mdoc`，ARF 中為 SHALL，OIA_08b）。
- Apple：reader 憑證鏈到 Apple Root CA，帶有「是否保存資料（intent to retain）」的 x509 擴充；顯示名稱與 icon 需透過 Apple Business Register 註冊；Data Transfer 模式需申請 entitlement 並證明法律需求。https://support.apple.com/guide/security/secb569bf393/web
- Google（近場）：reader auth 為「強烈建議」，取得敏感屬性時可能是法規要求；**通過驗證**的 reader 會在同意畫面顯示其身分與組織名稱。https://developers.google.com/pay-wallet/products/wallet/identity/verify/accepting-ids-from-wallet-offline

### 2.6 EUDI：WRPAC、WRPRC、ETSI TS 119 475、TS 119 411-8【確認】

- **WRPAC**（存取憑證，X.509；政策見 ETSI TS 119 411-8）：
  - subject 包含 CN、O、organizationIdentifier、C、SAN URI；自然人則加 givenName、surname、serialNumber。
  - entitlement OID arc 為 `0.4.0.19475.1`。
  - 須有聯絡 SAN；keyUsage 為 digitalSignature。
  - 只接受 Member State 通報之 Access CA 的 LoTE trust anchor（RPA_04）。
  - 來源：https://pkg.go.dev/github.com/gmb-eudi/go-eudi-rpcert
- **WRPRC**（ETSI TS 119 475 V1.2.1，2026-03）：
  - JWT `typ: rc-wrp+jwt`（JAdES B-B，帶 `x5c`），或 CWT `typ: rc-wrp+cwt`（帶 `x5chain`）。
  - 核心 claims：`name`、`sub`、`sub_ln`（法人名）／`sub_gn`+`sub_fn`（自然人）、`country`、`registry_uri`、`srv_description`、`entitlements`、`privacy_policy`、`info_uri`、`support_uri`、`supervisory_authority`、`policy_id`（含 `0.4.0.19475.3.1`）、`certificate_policy`、`iat`、`exp`（不得超過 iat+12 個月）、`status`（idx+uri）。
  - 條件式 claims：`purpose`（多語）、`intended_use_id`、`credentials`（含 claim paths，用於超額請求檢查）、`provides_attestations`、`public_body`、`intermediary{sub,sname}`、`act.sub`。
  - 來源：https://etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
- **登記資料集**（EUDI TS6 v1.2，2026-08，依 CIR 2025/848 與 CIR 2026/1730）：
  - Name：法人用 `legalName`，自然人用 `givenName`/`familyName`。RP 可以是自然人或法人。
  - Trade Name、Identifier（預設 EUID，否則各國公告）、地址、infoURI、聯絡方式、Service Description、Data Requested（`IntendedUse.credentials`）、Purpose、`isPSB`（是否公部門）、Entitlements（10 種）、Intermediary 關聯、Supervisory Authority、providesAttestations。
  - TS5 提供 JSON Schema／OpenAPI，以及 registrar 的公開查詢 API。
  - 來源：.../ts6-common-set-of-rp-information-to-be-registered.md 、.../ts5-common-formats-and-api-for-rp-registration-information.md
- **ARF 對 wallet 的強制行為**：
  - RPA_05/06a：驗證失敗要通知使用者，並決定拒絕或讓使用者選擇。
  - RPA_06：顯示 access cert 中的 RP 與 Service trade name。
  - RPA_10：顯示 intended use 與隱私權政策連結。
  - RPRC_17/17a：WRPRC 缺漏、無效，或與 WRPAC 的 identifier 不一致時要警告。
  - RPRC_21：超額請求時要警告，並由 wallet provider 決定 a) 全部可同意、b) 只給已登記部分、或 c) 全拒。
  - RPA_07b：警告時「沉默或預先勾選不足以構成同意」。
  - RPA_07c：要求肖像時要警告這是生物特徵資料。
  - RPI_07：經中介者時**只顯示被代理的 RP，不顯示中介者**。
  - 時程：wallet 驗證 WRPRC 的要求在修訂 CIR 2024/2982 生效後 24 個月才適用（RPRC_17 註）。
- **代理與中介**：TS6 的 `usesIntermediaries`、`serviceIdentifier`；RPI_01..10 規定中介者須以 RP 身分註冊、轉送後須立即刪除。

### 2.7 OpenID Federation、did:web 與 DID Configuration、Linked VP

- 【確認】OpenID Federation 1.0 已於 2026-02 成為 Final；「OpenID Federation for Wallet Architectures」仍是草案。https://self-issued.info/?m=202602 、https://openid.net/specs/openid-federation-wallet-1_0.html
  - 在 OpenID4VP 中，用 `openid_federation:` prefix 加上可選的 `trust_chain`；在 DCQL 中用 `trusted_authorities.type = openid_federation`。
- 【確認／推論】did:web 搭配 DIF Well-Known DID Configuration（`/.well-known/did-configuration.json` 中的 Domain Linkage Credential，加上 DID Document 的 `LinkedDomains` service）可做到 DID 與網域的雙向綁定。DIF 狀態為「Working Group Approved Draft」【推論，未本次核對】。OpenID4VP 使用 `decentralized_identifier:did:web:…`。
- 【確認】DIF Linked VP：在 DID Document 中以 `LinkedVerifiablePresentation` service 公開 VP，可用來公開組織憑證（例如法人登記 VC）。https://identity.foundation/linked-vp/
- 【確認】W3C「Recognized Entities v1.0」：WD 2026-09-06，實驗性、不適合用於生產。定義 `RecognizedEntityCredential`、`RecognizedAction`（例如 `issue`、`verify`），可用來表達「某權威機構認可此實體可執行 verify」，但**沒有定義 wallet 如何檢查 verifier**。https://www.w3.org/TR/vc-recognized-entities-1.0/
- 【確認】ToIP TRQP v2.0（2026-04 封存版）：可查詢「X 是否被授權在框架 Y 中做 Z」，可對應驗證者授權。https://trustoverip.org/wp-content/uploads/TRQPv2.0-Archival-PDF-2026.04.23.pdf

### 2.8 法人 PID（LPID）與代理／授權

- 【確認】CIR 2024/2977 Annex 第 2 節「legal person identification data」：
  - 必填：current legal name、unique identifier（由發送國建立，盡量持久）。
  - 選填：地址、VAT、稅號、EUID、LEI、EORI、Excise number。
  - 規則中沒有代理相關內容。
  - https://docs.igrant.io/regulations/implementing-acts-pid-and-eaass/
- 【確認】EWC RFC005 LPID：SD-JWT VC，必填 `legal_person_id`（EUID）與 `legal_person_name`；申請者需在 LoA High 下驗證其代表權。https://www.weboftrust.org/standard/ewc_rfc005:_issue_legal_person_identification_data_(lpid)-56
- 【確認】Power of Representation 範例（A-SIT Plus，walt.id 目錄）：
  - `vct: urn:eu.europa.ec.eudi:por:1`。
  - claims：`legal_person_identifier`、`legal_name`、`full_powers`、`e_service`、`effective_from_date`／`effective_until_date`、`issuing_authority` 等。
  - https://credentials.walt.id/sd-jwt-credentials/asit-power-of-representation
- 【確認】ARF Topic I（自然人代理自然人）：
  - 代理必須用**獨立的 attestation type**，載明代理性質與可執行的操作，且不得隱藏。
  - 必須是短效或可撤銷。
  - RP 必須能知道自己是在和代理人互動。
  - 該文件明確**不涵蓋「自然人代表法人」**。
- 【確認】European Business Wallet（EBW）提案（Bitkom 2025-12 評論）：
  - 刪除 eIDAS Art.5a 中「法人用 EUDI wallet」，改由 EBW 承接。
  - 以 EUID 為主識別（無 EUID 者另定新識別碼）。
  - 有角色／授權模型（Art 5(1)(j)、6(2)(b) 與附件），但 sub-delegation 不明。
  - https://www.bitkom.org/sites/main/files/2026-01/bitkom-statement-proposal-for-a-regulation-establishing-european-busuniess-wallets.pdf
- 【確認】CEN/TS 18098:2026（PID onboarding 指引）的範圍：自然人控制 wallet、為自己或代表他人（自然人或法人）；不含「wallet 使用者本身是法人」的情況。https://www.evs.ee/et/cen-ts-18098-2026
- 【推論】可用的建模：
  - 自然人：PID。
  - 法人：LPID（存在 EBW 或機關系統，不在個人 wallet）。
  - 組織內自然人：PID + 「PoR／Mandate／Employee-role attestation（subject = 自然人，指向 legal_person_identifier，scope = 授權範圍）」，以同一 holder binding（或 ZKP_03 的 PID-binding）串接。

### 2.9 驗證者以 VC 證明自己：現況整理

| 機制 | 現況 | 說明 |
|---|---|---|
| OpenID4VP `verifier_info` | 【確認】Final 規格中的擴充點 | 可放任何 `format`。EUDI 已用於 `registration_cert`。**沒有標準化的 VC／VP 格式值**，需要生態系自訂（例如 `"vp+dc+sd-jwt"`、`"vp_token"`）。 |
| `verifier_attestation`（JWT） | 【確認】 | 第三方簽發的「驗證者證明」，但只是 JWT 而非 VC，以 `cnf` 綁定。 |
| W2W（Wallet-to-Wallet） | 【確認】ARF Topic J | Holder 會驗證 Verifier Wallet Unit 的有效性（WUA）；雙向驗證、限速、禁止法人濫用。驗證者以自然人身分出現時，可要求雙方互相出示資料。 |
| DIDComm present-proof、Aries 雙向 | 【推論】 | Aries 生態可雙向請求證明（verifier 也可以是 holder）。 |
| Linked VP、Recognized Entities、TRQP | 【確認】草案或實驗 | 以公開 VP 或 registry 查詢補強。 |
| Google Wallet `gw_rp_metadata_bytes` | 【確認】專有 | Google 核准 RP 後提供已簽名的 metadata，每個 request 都必須帶上。 |

**結論【推論】**：「verifier presenting credentials to holder」目前沒有跨生態的正式規格。最佳路徑是：**以 X.509（WRPAC 或在地 PKI）或 DID 完成 client 認證，再把以 VC 形式存在的證據（WRPRC、LPID、PoR／Employee 憑證的 VP）放進 `verifier_info`，並用 key-bound PoP（對 nonce + client_id 簽章）綁定到本次 request**。

### 2.10 建議資料模型：「驗證者聲明」（Verifier Declaration）【推論】

```jsonc
// verifier_info 元素（OpenID4VP）；18013-5 則放在 ItemsRequest.requestInfo["<org>.verifierDecl"]（CBOR）
{
  "format": "x-<org>-verifier-decl+jwt",        // collision-resistant；同時也接受 "registration_cert"
  "data": "<JWS，由 request 簽章金鑰簽署；typ=verifier-decl+jwt>",
  "credential_ids": ["pid", "age"]              // 可選：此聲明只套用到哪些 DCQL query
}
// JWS payload
{
  "iss": "<client_id 完整值，含 prefix>",      // claim-bound
  "aud": "<wallet 或 origin>", "nonce": "<request nonce>", "iat": 0, "exp": 0,  // key-bound PoP
  "actor": {
    "kind": "legal_person | natural_person | natural_person_on_behalf_of_legal | natural_person_on_behalf_of_natural",
    "display_name": {"zh-TW": "…", "en": "…"},
    "legal_person": {"name": "…", "identifier": {"scheme": "EUID|TW-UBN|LEI", "value": "…"}, "is_public_body": true},
    "natural_person": {"display_name": "…"},     // 可由 ZK 只揭露職稱、不揭露姓名
    "intermediary": {"name": "…", "identifier": "…"} // 依 RPI_07，UI 只顯示被代理者
  },
  "purpose": {
    "intended_use_id": "…", "text": {"zh-TW": "…"},
    "legal_basis": "consent|contract|legal_obligation|public_task|…",
    "retention": "none|session|P30D", "privacy_policy": "https://…",
    "requested": [{"credential_id": "pid", "claims": [["age_over_18"]]}]
  },
  "evidence": [
    {"type": "wrprc", "ref": "verifier_info[0]"},                 // EUDI 註冊憑證
    {"type": "x509_access_cert", "ref": "x5c"},                   // WRPAC 或在地 PKI
    {"type": "vp", "format": "dc+sd-jwt", "vp": "<LPID 的 VP，KB-JWT 綁定 nonce+client_id>"},
    {"type": "vp", "format": "dc+sd-jwt", "vp": "<PoR/Employee 的 VP>"},
    {"type": "vp", "format": "mso_mdoc_zk", "vp": "<以 ZK 證明『我是受僱於 X 的稽查員』>"},
    {"type": "openid_federation", "trust_chain": ["…"]},
    {"type": "did_configuration", "did": "did:web:…", "origin": "https://…"}
  ]
}
```

驗證演算法（wallet 端）：
1. 驗證 request 簽章與 client_id prefix；DC API 須比對 `expected_origins`。
2. 逐筆驗證 evidence（鏈、狀態、有效期、trust list 等）。
3. **一致性檢查**：
   - evidence 中的法人識別碼要等於 access cert 的 organizationIdentifier（或等於 WRPRC 的 `sub`）。
   - PoR 的 `legal_person_identifier` 要等於 LPID。
   - PoR 的 holder binding 要等於簽 verifier-decl 的金鑰，或另有 PoP。
4. **目的一致性**：DCQL 請求必須 ⊆ `purpose.requested` ∩ WRPRC 的 `credentials`。
5. 計算信任等級（見 §3.4），並把每個檢查的結果呈現在 UI 上。

### 2.11 驗證端 ZKP 支援【確認／推論】

- **驗證者要能驗 ZK**：
  - Longfellow 驗證約 0.6 s（Pixel 6 Pro）、proof 約 400 KB，可在伺服器端驗證（Google 提供 Docker 驗證器）。
  - Multipaz 的 `ZkSystem.verifyProof` 是 KMP 實作，可以在 App 內做 W2W 驗證。
  - OpenAC 驗證約 65–318 ms（行動裝置）。
  - BBS 驗證約 ms 級。
  - 驗證者必須事先持有發行者公鑰清單（VICAL／LoTE／etsi_tl），因為 proof 隱藏了 issuer 憑證。【確認】
- **驗證者以 ZK 證明自身屬性**：沒有現成的標準。可行的做法是把 holder 端的 ZK 技術反向使用（驗證者 App 本身也是 Multipaz 持有端），在 `verifier_info` 中放 `mso_mdoc_zk` 證明，例如「我持有『X 機關授權稽查員』mdoc，且未過期」，只揭露機關與角色，不揭露個人姓名。【推論】
  - 衝突：EUDI 的 RPA 要求「識別 RP」，所以對 EUDI 合規場景，RP 本身（法人）不能匿名；**ZK 只適合用來隱藏「組織內個人」的身分**。【推論】
  - 成本：wallet 端每次要驗證一個 ZK 證明（約 0.6 s、400 KB 下載）。【推論】

---

## 3. 任務三：信任分級 UI

### 3.1 EUDI ARF 規則（摘要）【確認】

- OIA_05/RPA_06：顯示 RP 身分（WRPAC 中的 trade name）與請求的屬性。
- RPA_10：顯示 intended use 與隱私權政策。
- RPA_05：驗證失敗時，告知「身分無法驗證、此請求不可信」。
- RPA_06a：wallet provider 二選一：直接拒絕，或讓使用者選擇。
- RPRC_17/21：WRPRC 無效或超額請求時要警告，並依風險政策決定是否允許。
- RPA_07b：在警告情境下，必須明確同意（不可預設勾選）。
- RPA_10a（SHOULD）：全部同意或全部拒絕。
- RPA_12（MAY）：標示屬性是否綁定裝置。
- RPA_08：同意前先驗證使用者身分。

### 3.2 實際 UI 文字

**EUDI 參考 App（eudi-app-android-wallet-ui，`resources-logic/.../values/strings.xml`）**【確認】
- 預設名稱：「Unknown Relying Party」；ID 格式：「(ID: %1$s)」；區段標題：「Intended use」、「Privacy policy」、「Requested data」。
- 「Warning: The information registered about the entity could not be obtained. Review carefully before sharing your data.」
- 「Warning: Some of the requested data are not registered with this interacting party. Review carefully before sharing your data.」，搭配逐項標示「Not registered data」。
- 確認勾選：「I understand the risks and agree to share my data」
- 阻擋：「This presentation request has been blocked because the relying party could not be verified by your Wallet.\n\nYour personal information or other data has not been shared with this relying party.」
- 徽章：「Trusted Relying Party — A Relying Party is considered trusted when it meets predefined criteria for security, data protection, compliance, and responsible data handling.」
- 交易紀錄頁：提供向 DPA 檢舉、依 GDPR Art.17 請求刪除的 email 範本。
- 邏輯：`verifierIsFullyVerified == true` 才標示為 isVerified。

**Multipaz（`multipaz-compose/.../values/strings.xml`，`Consent.kt`）**【確認】
- 標題：「Unknown requester」／「Unknown website」
- 「This data will be shared with %1$s:」；「%1$s is requesting this data on behalf of %2$s:」；「…on behalf of an unknown party who will store it:」。這些字串區分了 requester 與加密目標（實際接收者），以及是否保存。
- 警告：
  - 「The identity reader requesting this data is unknown. Make sure you are comfortable sharing this data」
  - 「…is anonymous…」（未簽章）
  - 「The website requesting this data is unknown…」
  - 「The application requesting this data is unknown…」
- 受信任：「The identity reader／website／application requesting this data is trusted」，並附「Review the [%1$s privacy policy](%2$s)」。
- 信任來源：`TrustManager`（X.509、VICAL、RICAL），`TrustMetadata.testOnly` 可標示測試用；匯入時會警告「This certificate was just imported. Please check its fingerprint…」。

**Google Wallet**【確認】
- 線上：RP 須提交 Onboarding Form（含 CSR、logo、display name、隱私與條款 URL、整合影片）；Google 簽發憑證與 `gw_rp_metadata_bytes`，用於顯示品牌。中介者有另一套 Verifier Registrar 流程。
- 近場：通過驗證的 reader 會在同意畫面顯示身分與組織名稱。
- 未驗證時的具體文字：本次未取得。

**Apple Wallet**【確認】
- 顯示名稱與 icon 需透過 Apple Business Register 審核。
- reader 憑證中有 intent-to-retain 擴充；Display Only 與 Data Transfer 兩種模式。
- 未驗證時的具體文字：本次未取得。

### 3.3 Android DC API 的 origin 顯示

- 【推論】Android Credential Manager 的系統選擇器會顯示呼叫端 App 或網站 origin。但 ARF 要求最終的 RP 驗證與同意必須在 wallet 內完成，所以 wallet 要自行顯示「已驗證的 RP 名稱」與「平台提供的 origin」兩者，並在兩者不一致時降級顯示。

### 3.4 建議信任分級（設計）【推論】

| 等級 | 條件 | UI |
|---|---|---|
| T1 官方信任（政府／受監管） | request 簽章鏈到官方 trust list（WRPAC LoTE／在地 RP PKI／RICAL），WRPRC 有效，請求 ⊆ 登記，`public_body` 或 entitlement 吻合 | 綠色盾牌、法定名稱 + trade name + ID、目的、隱私權政策、「公部門」標籤 |
| T2 已驗證身分但目的未登記或超額 | 鏈有效，但 WRPRC 缺漏或無效，或請求超出登記範圍 | 黃色警告（沿用 EUDI 文案）；超額欄位逐項標示；需勾選「我了解風險」；或依政策只送已登記部分 |
| T3 自我聲明（DID／Federation／自訂 PKI，非官方清單） | 密碼學驗證通過，但 trust anchor 不在官方清單；evidence VP 可驗證 | 灰藍色：「此驗證者自稱為…，由 [錨點] 證明」；顯示 evidence 摘要 |
| T4 未知或匿名 | 未簽章（`redirect_uri:`、unsigned DC API）或鏈驗證失敗 | 紅色：「無法驗證請求者身分」；預設不允許高敏感屬性（肖像、身分證號）；可設定為一律阻擋 |
| 加註 | 測試錨點（testOnly）、中介者代理、會保存資料、transaction_data、生物特徵、非裝置綁定 | 獨立 chip 或警示列 |

---

## 4. 可能遇到的問題（風險清單）

1. **ISO 18013-5 第二版仍是 DIS／定稿中**：`ZkRequest` 與 `params` 欄位（`circuitHash` vs. `circuit_hash`、`version` 等）在 Multipaz、EUDI TS13、Google、irmago 之間已有差異，circuit 版本（v6/v7）也會變動。需要做版本協商與相容性測試。【確認：已見不一致】
2. **Longfellow 的 SD-JWT circuit 尚未在上游實作**：如果 TWDIW 或台灣生態以 SD-JWT VC 為主，Longfellow 不能直接套用；需要評估 OpenAC，或自行撰寫 circuit。【確認】
3. **ECCG ACM v2.0 限制（ZKP_08）**：BBS（BLS12-381）、T256、secq256r1、Spartan、Ligero 是否在清單內有疑義；EU 偏好 PQ。若要對齊 EUDI，可能必須等待相關裁定。【確認：要求本身；清單內容未核對】
4. **效能與記憶體**：OpenAC Prepare 峰值 2.27 GiB、proving key 數百 MB，中低階 Android 可能被 OOM kill；Longfellow 約 88 MB，但 circuit 解壓後 88 MB。需要裝置分級與退回機制。【確認數據】
5. **ABI 支援**：`multipaz-longfellow` 只提供 arm64-v8a 與 x86_64 的 JNI，32 位元 armv7 裝置無法使用。【確認】
6. **Multipaz wallet 端缺少 `expected_origins` 檢查**（TODO）。另外未見 wallet 端 `verifier_attestation`、`decentralized_identifier`、`openid_federation` prefix 與 `verifier_info`／WRPRC 的處理，需要自行實作或貢獻上游。【確認：TODO 註解；其餘為 grep 未找到 → 推論】
7. **verifier_info 沒有 VC 格式的標準值**：自訂 `format` 會造成互通性問題，其他 wallet 會忽略（SHOULD ignore）。需要保留 `registration_cert` 相容路徑，並把自訂聲明設計成「可有可無的增益」。
8. **WRPRC 的時程**：wallet 必須驗證 WRPRC 的要求延後 24 個月；在此之前大多數 RP 可能不帶 WRPRC，UI 不能因此把大量合法 RP 標成警告（需要可設定的嚴格度）。
9. **中介者顯示規則與透明度相互衝突**：RPI_07 禁止顯示中介者，但 Multipaz 的 UI 預設會顯示「on behalf of」。若要符合 EUDI，需要切換。
10. **法人與代理建模尚未定案**：EBW 法規仍在立法；ARF Topic I 只處理自然人代理自然人；PoR 的 vct（`urn:eu.europa.ec.eudi:por:1`）是試點值，可能改變。
11. **ZK 驗證者的信任前提**：proof 隱藏 issuer 憑證，驗證者需要預載發行者 key 清單；circuit 支援的 issuer 數量有上限（例如參數 27 把）。跨國或多發行者時要設計 issuer-hiding 的範圍。
12. **撤銷與 ZK 的整合**：Token Status List 會破壞不可連結性；TS13 的 signed-pairs 方案需要發行端配合產出撤銷清單簽章，在台灣生態中可能沒有。
13. **BBS 生態碎片化**：pairing_crypto 停在 draft-03；W3C 可選功能有被移除的風險；JWP 草案預期會有重大變更。不宜過早鎖定。
14. **PQ 遷移**：BBS、Spartan2-on-secq256r1、Groth16（Crescent）都不是 PQ；Longfellow 只依賴雜湊，但 ECDSA circuit 本身證明的是非 PQ 簽章。
15. **原生 App 驗證者的私鑰保管**（OpenID4VP 特別指出）：若支援 W2W 或「驗證者 App」，需要 Android Keystore 或 StrongBox 加上 attestation。

---

## 5. 主要來源

- OpenID4VP 1.0（Final 2025-07-09）：https://openid.net/specs/openid-4-verifiable-presentations-1_0.html ；原始 md：https://raw.githubusercontent.com/openid/OpenID4VP/main/openid-4-verifiable-presentations-1_0.md
- HAIP 1.0 Final：https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html
- OpenID Federation 1.0 Final（2026-02）：https://self-issued.info/?m=202602 ；Wallet Architectures 草案：https://openid.net/specs/openid-federation-wallet-1_0.html
- W3C DC API WD（2026-09-04）：https://www.w3.org/TR/digital-credentials/
- Longfellow：https://ftp.sjtu.edu.cn/pub/internet-drafts/draft-google-cfrg-libzk-02.html ；https://datatracker.ietf.org/meeting/126/materials/slides-126-cfrg-longfellow-zk-00 ；https://datatracker.ietf.org/meeting/125/materials/slides-125-cfrg-longfellow-zk-00 ；https://datatracker.ietf.org/meeting/124/materials/slides-124-dispatch-longfellow-zero-knowledge-credentials-00 ；https://github.com/google/longfellow-zk ；https://eprint.iacr.org/2024/2010
- BBS：https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ ；https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-03 ；https://www.w3.org/TR/2026/CRD-vc-di-bbs-20260407/ ；https://docs.rs/zkryptium/ ；https://github.com/docknetwork/crypto ；https://github.com/mattrglobal/pairing_crypto ；JWP：https://datatracker.ietf.org/doc/draft-ietf-jose-json-proof-algorithms/
- OpenAC/zkID：https://eprint.iacr.org/2026/251 ；https://github.com/privacy-ethereum/zkID ；https://github.com/zkmopro/TWDIW-integration ；Mopro：https://github.com/zkmopro/mopro ；https://zkmopro.org/docs/performance
- Crescent：https://github.com/microsoft/crescent-credentials ；AnonCreds：https://github.com/hyperledger/anoncreds-rs
- EUDI ARF 3.0.0 Annex 2：https://eudi.dev/latest/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/ ；Topic G：https://eudi.dev/latest/discussion-topics/g-zero-knowledge-proof/ ；TS4/TS5/TS6/TS13/TS14：https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/tree/main/docs/technical-specifications ；Topic I/J：https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/tree/main/docs/discussion-topics
- ETSI：TR 119 476-1 V1.3.1：https://www.etsi.org/deliver/etsi_tr/119400_119499/11947601/01.03.01_60/tr_11947601v010301p.pdf ；TS 119 475 V1.2.1：https://etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf ；TS 119 472-2 V1.2.1：https://etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf ；Go 實作參考：https://pkg.go.dev/github.com/gmb-eudi/go-eudi-rpcert
- ISO：27565:2026：https://committee.iso.org/standard/80398.html ；18013-5 第二版 workshop：見 §1.6 連結；RICAL：https://learn.mattr.global/docs/digital-trust-service/rical-overview ；irmago 整理：https://github.com/privacybydesign/irmago/issues/724
- EU 年齡驗證：https://docs.ageverification.dev/Roadmap/
- 德國 EUDI 架構：https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/ecosystem-concepts/trust/wallet-relying-party-authentication/ ；https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/rp/onboarding/registrar_certificate_usage
- LPID／代理：https://docs.igrant.io/regulations/implementing-acts-pid-and-eaass/ ；https://www.weboftrust.org/standard/ewc_rfc005:_issue_legal_person_identification_data_(lpid)-56 ；https://credentials.walt.id/sd-jwt-credentials/asit-power-of-representation ；https://www.bitkom.org/sites/main/files/2026-01/bitkom-statement-proposal-for-a-regulation-establishing-european-busuniess-wallets.pdf ；https://www.evs.ee/et/cen-ts-18098-2026
- 驗證者信任補充：https://www.w3.org/TR/vc-recognized-entities-1.0/ ；https://identity.foundation/linked-vp/ ；https://trustoverip.org/wp-content/uploads/TRQPv2.0-Archival-PDF-2026.04.23.pdf
- Wallet UI：Multipaz https://github.com/openwallet-foundation/multipaz （`multipaz-compose/src/commonMain/composeResources/values/strings.xml`、`Consent.kt`）；EUDI App https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui （`resources-logic/src/main/res/values/strings.xml`）；Google https://developers.google.com/wallet/identity/verify/accepting-ids-from-wallet-online 、https://developers.google.com/pay-wallet/products/wallet/identity/verify/accepting-ids-from-wallet-offline ；Apple https://support.apple.com/guide/security/secb569bf393/web

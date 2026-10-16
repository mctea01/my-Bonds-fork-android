# P1–P3 互通與簽署補強紀錄（2026-10-16）

此文件記錄 PR #11 中可由原始碼驗證的修補項目，以及必須由外部服務或實機驗收的條件。**此清單不是 P1–P3 全部完成的宣告。** 正式機關、公文與簽章服務均不得以測試簽章替代授權。

## 已實作的變更

| 範圍 | 實作 |
| --- | --- |
| OpenID4VCI | 依 `token_endpoint_auth_methods_supported` 協商 `none`、`attest_jwt_client_auth`、`private_key_jwt`；PAR 與 Token Request 使用同一身分方法，重試產生新的 Client Assertion。 |
| Wallet Provider | 可於「互通」設定登記正式 HTTPS 錢包後端與 `client_id`；自訂本機測試 Provider 不再被視為正式 Provider。 |
| 簽章請求 | 遠端 `client-assertion` 請求帶錢包實例簽署的短效 JWT、公開 JWK 與可用的金鑰證明鏈；本機測試後端驗證簽章、主體、受眾、有效期與防重放。 |
| CSC | 對照已登記 `redirect_uri` 檢查 OAuth 回呼；只使用與本地 SHA-256 摘要相符的 ECDSA／RSA 演算法。 |
| 行動自然人憑證 | 驗證 SP 回應完整性及 Ticket 解析的回歸測試；取消網路請求時保留 coroutine cancellation。 |
| CI | 保留 Android R8、Windows／Linux 打包及協定測試。最終測試狀態以 GitHub Actions 為準。 |

## 驗收與外部條件

| 需求 | 狀態 | 驗收條件 |
| --- | --- | --- |
| Multipaz Personal ID 正式發證 | 未完成 | 發證端接受錢包登記的 CA／Client Assertion 或 Wallet Attestation，實機成功領取並驗證 mdoc／SD-JWT VC。 |
| Android App Links | 未完成 | 需可控的 HTTPS 網域、`assetlinks.json`、正式 APK 簽章 SHA-256，並以 Android 驗證。現行自訂 scheme 僅作現有相容回呼。 |
| OpenID Federation | 未完成 | 信任錨點、Entity Statement、Trust Chain、Trust Mark 與快取策略均需獨立驗收，不可直接接受自述公鑰。 |
| OpenID4VP multisigned、加密 Request Object | 未完成 | 所有要求的簽章／收件金鑰均需認證；目前對未支援形狀保持拒絕，不得略過驗證。 |
| mdoc transaction_data | 未完成 | 須按相關規格綁定交易資料與裝置證明，不可直接忽略要求。 |
| Longfellow、VICAL／RICAL | 待補完 | ZK 系統註冊、已簽章信任清單下載／更新、真實裝置證明及驗證測試。 |
| 行動自然人憑證正式簽章 | 既有簽署流程；正式環境未驗收 | 向內政部申請 UAT SP 帳號、AES 金鑰、測試及正式環境核准。憑證與簽章須核對持有人和資料摘要。 |
| CSC 正式遠端簽章 | 既有 CSC v2 流程；正式環境未驗收 | 由信託服務業者提供服務端點、OAuth `client_id`、回呼登記、使用者證書及 SAD 授權；需跨供應商測試。 |
| 公文交換收發 | 未完成正式交換介接 | 先維持對收到的公文檔案匯入、簽章驗證、封裝及匯出。正式交換須機關註冊、專用憑證與對應交換中心的授權介接規格；個人錢包不能自行代替機關收發文。 |
| P1–P3 真實互通 | 待實機 | Android Keystore、TEE／StrongBox、DC API、BLE／NFC、實際服務端與 Release APK 均需測試記錄。 |

## 官方外部條件

- [內政部行動自然人憑證系統機關專區](https://fido.moi.gov.tw/pt/agency)：測試及正式 SP 介接須分階段申請。
- [CSC API 規格](https://cloudsignatureconsortium.org/resources/download-api-specifications/)：本專案目前使用 CSC v2 介面，仍需不同服務商的實際互通。
- [機關公文電子交換作業辦法](https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=A0030049)：收發文須完成機關身分與電子認證。
- [文書及檔案管理電腦化作業規範](https://theme.ndc.gov.tw/lawout/LawContent.aspx?id=GL000198&media=print)：電子交換註冊、交換資訊及憑證校驗皆有正式要求。

## 建置驗收

```bash
./gradlew :core:compileKotlinJvm
./gradlew :app:compileKotlinDesktop
./gradlew :test-servers:test
./gradlew :app:desktopTest
./gradlew :app:assembleRelease
```

- CI 成功不等於正式服務端已登記或通過實機安全驗收。
- 測試憑證與私密金鑰不得寫入儲存庫；正式交換帳號不得使用本機測試 PKI。
- 未取得交換中心核可規格前，不新增自行猜測的收發 REST API 或自動寄送功能。

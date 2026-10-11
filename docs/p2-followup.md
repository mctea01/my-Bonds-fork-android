# P2 後續：狀態、風險與信任錨點（2026-10-11）

分支 `claude/merge-conflict-ui-design-q5s134`，以合併後的 main（#5）為基礎。處理 P2 實機回饋：狀態顯示「有效，狀態清單未經驗證」、mashbean 沙盒狀態無法查詢、Verified ID 出示失敗，以及 jku 驗證、主動狀態更新、自動鏈上查驗與非 TWDIW 信任錨點。

## 修正與新增

1. **Verified ID 出示失敗（invalid_request，required with request_uri）。**
   - 原因：Microsoft Entra Verified ID 的出示連結是 `openid-vc://?request_uri=...`，外層沒有 client_id，client_id 只在已簽章的要求物件內。
   - 修正：從 Verified ID 入口進來時，接受沒有外層 client_id 的 request_uri；未簽章的要求物件仍然必須帶 client_id。
   - 同時支援：
     - 草案 10 的 `claims.vp_token.presentation_definition`（回應要帶 vp_token）；
     - Presentation Exchange v1 的 `schema[].uri`（以憑證類型篩選候選）。
   - 測試：`MsVerifiedIdTest.presentationWithRequestUriOnly`。
2. **jku 驗證：優先綁定發行端，綁不上時降級。** 狀態清單沒有其他金鑰來源時，才使用 jku（`trust/JkuKeys`）。只接受 https 網址，依下列順序綁定：
   1. JWK 的 x5c 連到任一啟用中的信任錨，不限 TWDIW；
   2. jku 主機就是簽署者自己的主機（did:web，或 https 識別碼）；
   3. 信任來源把這個主機綁到該 DID：TWDIW 已列名組織的服務網域與 wallet.gov.tw 平台，或 Linked Domains。

   三者都不成立時，清單仍會驗簽，但保證等級標為 `TLS_ONLY`，畫面顯示「僅經 HTTPS 確認」。測試：`TwdiwPlatformTest.officialIssuanceAndStatus` 涵蓋綁定與降級兩種情況。
3. **狀態依用途風險決定是否接受（`status/StatusPolicy`）。**

   | 狀態 | 低風險 | 中風險 | 高風險 |
   |---|---|---|---|
   | 有效（清單綁定發行端或信任錨） | 接受 | 接受 | 接受 |
   | 有效（僅經 HTTPS 確認） | 接受 | 接受 | 需留意 |
   | 有效（清單簽章未驗證） | 接受 | 需留意 | 拒絕 |
   | 發行端未提供狀態 | 接受 | 接受 | 需留意 |
   | 無法確認（清單讀不到） | 接受 | 需留意 | 拒絕 |
   | 尚未查詢 | 需留意 | 需留意 | 拒絕 |
   | 暫停 | 需留意 | 拒絕 | 拒絕 |
   | 撤銷 | 拒絕 | 拒絕 | 拒絕 |

   查詢結果超過該風險允許的時間（低 6 天、中 1 天、高 1 小時），或清單只在測試環境受信任時，「接受」降為「需留意」。

   風險套用在三個地方：
   - **證件卡片與內容頁**：依證件分類決定風險。身分證件為高，政府皮夾卡片為中，其他為低。
   - **出示前**：請求風險取「要求欄位的敏感度」與「查驗方信任等級」的較高者（`credential/ClaimSensitivity`）：
     - 欄位：身分證號、照片、地址為高，姓名、出生日期為中；
     - 查驗方：T1 為低，T2、T3 為中，T4 為高。

     若有證件的狀態判定為拒絕，同意畫面會顯示判定卡，必須勾選確認才能出示。
   - **查驗他人**：查驗者選擇用途風險。有網路時查詢對方證件的狀態（8 秒逾時）。高風險用途另外要求發行端在信任清單內。
4. **主動狀態更新（`StatusMonitor`）。**
   - 開啟或回到 App 時，在背景查詢逾時的狀態。間隔依證件風險：身分證件 30 分鐘、政府卡片 12 小時、其他 3 天。同時最多查 3 張。
   - 領卡後立即查詢一次。出示前，若結果對這次請求而言太舊，也會先重查。
   - 結果存在儲存區，離線也能顯示。
   - 查詢失敗時保留前一次有意義的結果，並註明失敗原因與時間。
   - 狀態變更（撤銷、暫停、恢復有效）時跳出通知，並在「紀錄」新增「狀態」一筆，只記狀態，不記欄位內容。
   - 設定新增「自動更新證件狀態」（預設開啟）與「立即更新所有證件狀態」。
5. **自動鏈上查驗。**
   - 開啟信任清單時，自動查驗一天內未查驗的組織：DID 文件自簽，以及 Arbitrum One 的註冊。同時最多 3 筆，並顯示進度。
   - 所持 TWDIW 卡片的發行端，每 12 小時重新查驗信任清單與鏈上註冊。信任等級改變時寫回卡片，並通知、記錄。
   - 下列情況卡片的信任不變：離線、平台回傳錯誤、Arbitrum RPC 無法查詢。這樣不會把「暫時查不到」誤判成除名。這次新增的 `TwdiwTrustList.recheck` 在網路失敗時會丟出例外，不會改用離線快照。
6. **信任錨點不限 TWDIW。** 設定新增「信任錨點」頁：
   - 依環境（正式、使用者匯入、測試）列出所有 X.509 錨點，以及每個錨點的用途。
   - 可貼上 PEM 或 https 網址，匯入任何國家、組織或企業的根憑證，用途可選發行端、狀態清單、查驗方、錢包提供者。匯入的錨點不需開啟測試環境就會使用。
   - 可自行信任 DID（`trust/UserDidTrust`），用於信任清單以外的組織，例如企業自建的發行端。
   - 匯入的錨點與信任的 DID 都是 T3（可驗證但非官方），不會顯示為官方。
7. 狀態清單的簽章欄位改為列出保證等級：
   - 已驗證（綁定發行端或信任錨點）；
   - 已驗證，但金鑰只經 HTTPS 確認；
   - 未驗證。
8. App 的設定與卡面圖片儲存表改為整個程式共用一份定義。同一個儲存區開第二個 `WalletModel`（例如重新啟動）時，原本會出現「Multiple table specs」。

## 上游問題（非本 App 可修）

- **TWDIW 金鑰端點不一致。** `https://issuer-vc.wallet.gov.tw/api/keys` 每次回應的 key-2 不同（x 座標開頭 `9CNEmxkQim...` 與 `JvathuWc2Q...` 交替出現），狀態清單只用其中一把簽章，所以約一半的請求會驗簽失敗。錢包在驗簽失敗時重抓金鑰集，最多 4 次。對外測試連續 3 次都通過，其中一次在第 2 次取得時才相符。建議回報數位發展部。
- **mashbean 沙盒狀態查詢失敗。** 回應「Invalid redirect value, must be one of "follow" or "manual" ...」是 Cloudflare Workers 的執行錯誤：該伺服器呼叫 `fetch` 時用了 Workers 不支援的 `redirect: "error"`。錢包把它視為「無法確認」，再依風險判斷：低風險接受、中風險需留意、高風險拒絕。修正需由沙盒維護者把 `redirect` 改為 `"manual"`，再自行檢查狀態碼。

## Verified ID 的組織驗證能做到哪裡

| 層級 | 做法 | 本 App |
|---|---|---|
| 網域擁有權 | DIF Well Known DID Configuration（Linked Domains）。DID 文件的 `LinkedDomains` 服務列出網域，網域根目錄的 `/.well-known/did-configuration.json` 放一份由同一個 DID 簽章的 DomainLinkageCredential。Microsoft Authenticator 的「Verified」標示就是這一層，只證明 DID 控制該網域。 | 已實作，判定為 T3；網域連結失效則為 T4 |
| Verified ID Network | Microsoft 的發行端目錄，只收錄網域已驗證的發行端。查詢 API 需要查詢者自己的 Entra 租戶，以及 Verifiable Credentials Service Admin 權限。 | 終端使用者的錢包無法直接查詢，不實作；組織部署時可在後端查詢 |
| 法人身分 | Verified ID 本身沒有法人身分登錄。可行的補強：使用者自行信任該 DID（已實作）、該組織若在 TWDIW 信任清單則依 TWDIW 判定（已實作，DID 相同時）。以 OV/EV 憑證主體的組織名稱、GLEIF vLEI、EBSI Trusted Issuers Registry 交叉比對，需要另外設計。 | 部分可行，列為後續 |

結論：網域層級的組織驗證已經做到，與 Authenticator 相同。法人層級要靠其他信任來源，Microsoft 目前沒有提供可供錢包查詢的公開登錄。

## 測試結果

| 範圍 | 指令 | 結果 |
|---|---|---|
| 協議與互通 | `:test-servers:test` | 86 項：73 通過，13 項需 `DIW_INTEROP=1` 略過。新增 `StatusPolicyTest` 8 項（風險表、過時、測試環境、欄位敏感度、自行信任 DID），以及 Verified ID 只有 request_uri 的出示 |
| 正式 TWDIW（需網路） | `DIW_INTEROP=1 ./gradlew :test-servers:test --tests 'diw.testservers.InteropTest.twdiw*'` | 通過：信任清單 50 筆，抽樣 3 筆為 T1；97179430 中繼資料；demo 狀態清單經 jku 驗簽為 `TLS_ONLY`（demo 發行端未列名） |
| App 共用模型 | `:app:desktopTest` | 11 項：8 通過、3 項略過。新增兩項：`statusMonitorAnnouncesRevocationAndKeepsResults`（撤銷由背景更新發現、通知並記錄、離線保留結果、重啟後讀回）與 `userAnchorImportAndRemoval` |
| 主要畫面離屏截圖 | `DIW_SCREENSHOTS=<資料夾> ./gradlew :app:desktopTest --tests '*uiScreenshots'` | 13 張 PNG，新增「信任錨點」 |
| Android | `:app:assembleDebug :app:assembleRelease`（R8） | 建置成功，release APK 約 22 MB |

## 需要實機驗證

| 項目 | 步驟 | 預期 |
|---|---|---|
| Verified ID 出示 | 以 Entra 驗證端的 `openid-vc://?request_uri=` QR 出示 Verified ID 卡片 | 不再出現 invalid_request，同意畫面列出要求的卡片，驗證端顯示成功 |
| TWDIW 狀態 | 持有正式 TWDIW 卡片，開啟證件內容頁 | 發行端已列名時顯示「有效」，簽章欄為「已驗證（綁定發行端或信任錨點）」；查詢失敗時保留前一次結果並註明 |
| 自動更新 | 讓卡片在平台端被撤銷，再回到 App | 一段時間內（政府卡片 12 小時，或按「立即更新所有證件狀態」）通知「狀態變更：無效」，「紀錄」的「狀態」篩選有一筆 |
| 出示前警示 | 以被撤銷或狀態無法確認的卡片回應要求身分證號的請求 | 同意畫面出現紅色判定卡，須勾選確認才能同意 |
| 查驗風險 | 「查驗」分頁選高風險，以 Bonds 出示 | 離線時判定為「查驗未通過：證件狀態不符」；連線且有效時通過 |
| 信任清單自動查驗 | 設定 > 信任清單 | 進度條跑完後，各組織顯示鏈上狀態與查驗時間 |
| 匯入根憑證 | 設定 > 信任錨點，貼上其他組織的 PEM | 出現在「使用者匯入」，該組織簽發的證件為 T3 |

## 第二輪：近距離出示與查驗、主動出示、信任補強（2026-10-11）

### 新增

1. **NFC 與 QR 近距離出示（ISO/IEC 18013-5）。**
   - 「使用」分頁的「感應出示」與證件內容頁的「出示這張證件」都可進入。
   - NFC 交握支援 negotiated 與 static handover，資料經 BLE 或 NFC 傳輸；也可改顯示 QR Code，由查驗設備掃描後以 BLE 連線。
   - 查驗設備的要求顯示在共用的同意畫面，含請求風險與各證件的狀態判定，出示後寫入紀錄。
   - 只有畫面開著時，NFC 感應才會回應。
2. **感應查驗（App 作為 mdoc 讀取端）。**
   - 「查驗」分頁的「感應查驗（NFC）」可選擇要求的資料（行動駕照的身分、駕駛資格、年滿 18 歲，或歐盟 PID）、用途風險與讀卡機。
   - 驗證內容：發行端簽章與資料摘要、出示者金鑰的裝置驗證（綁定這次 session）、有效期間、發行端信任、狀態清單。
   - 讀卡機：
     - Android：手機 NFC（讀卡模式），或以 OTG 接上 USB CCID 讀卡機（與電腦 PC/SC 讀卡機同一類 USB 裝置）；
     - 桌面：PC/SC 讀卡機。PC/SC 讀卡機只能讀取、不能模擬卡片，所以電腦不提供 NFC 出示。
3. **DC API 的 `org-iso-mdoc`（ISO/IEC 18013-7 Annex C）。**
   - 網頁以 Digital Credentials API 要求 mdoc 時，使用同一個同意畫面。
   - 回應以 HPKE 加密給網頁，並綁定網頁來源。
4. **主動出示不限 TWDIW。**
   - 離線查驗挑戰新增來源 `a`（本錢包擴充），可出示任何綁定金鑰的證件：
     - IETF SD-JWT VC，可選擇欄位；
     - W3C VC 的 SD-JWT 形式；
     - W3C VC 的 JWT 形式，出示全部欄位。
   - 查驗端依序以 x5c、DID 或發行端中繼資料取得發行端金鑰，再檢查持有者綁定與狀態清單。
   - Bonds 相容的 `g` 挑戰仍只列政府皮夾卡片。
   - 證件內容頁的「出示這張證件」會把該證件排在最前面。
5. **Verified ID 依 Microsoft 規則建立信任。** Linked Domains 驗證成功時判定為 T3（`LINKED_DOMAIN`），與 Microsoft Authenticator 一樣不需要另外勾選警示；驗證失敗為 T4。
6. **X.509 運作中的憑證。**
   - 內建從政府憑證總管理中心（grca.nat.gov.tw）取得的錨點，判定為 T2，只確認身分：
     - GRCA 2002、2012、G3：時戳；
     - GCA、XCA、MOEACA：發行端、狀態清單、查驗方；
     - MOICA：只用於查驗方。
   - HCA 的儲存庫無法連線，沒有內建。
7. **系統憑證庫。** 設定 > 信任錨點可開關，預設開啟。連到系統根憑證的憑證鏈判定為 T3，只確認網域。RSA 憑證鏈在 Multipaz 不支援時改以 PKIX 驗證。

### PR 審查修正

| 項目 | 修正 | 測試 |
|---|---|---|
| 狀態判定為拒絕仍可勾選出示 | 不再提供覆寫；無法確認時可重新查詢，撤銷時不提供 | 介面元件，沒有專屬自動測試 |
| 揭露整張憑證被當成低風險 | 以證件實際含有的全部欄位與證件分類計算 | 沒有專屬自動測試 |
| Linked Domains 失效蓋過使用者信任的 DID | 使用者信任的 DID 排在 Linked Domains 之前 | `userTrustedDidOverridesBrokenDomainLink` |
| 移除信任來源後已持有證件仍顯示原信任 | 匯入或移除錨點、DID 時重新判定並記錄 | `trustSourceChangesReevaluateHeldDocuments` |
| jku 在測試環境可用 http | 無條件只接受 https | `StatusPolicyTest.jkuIsHttpsOnly` |

### 測試結果

| 範圍 | 指令 | 結果 |
|---|---|---|
| 協議與互通 | `:test-servers:test` | 93 項：80 通過，13 項需 `DIW_INTEROP=1` 略過。新增 `BondsAnyCardTest` 3 項（SD-JWT VC 選擇性揭露、他人金鑰與來源不符被拒、JWT VC 以 subject DID 綁定）、`TrustAnchorsTest` 3 項、`StatusPolicyTest.jkuIsHttpsOnly` |
| App 共用模型 | `:app:desktopTest` | 19 項：16 通過、3 項略過。新增：`nfcReaderVerifiesAnotherWallet`、`nfcReaderWithShortApdus`（PC/SC 式短 APDU）、`pcscListWithoutReaders`、`dcApiIsoMdocPresentation`、`offlinePresentationOfAnyKeyBoundCard`、`trustSourceChangesReevaluateHeldDocuments`、`userTrustedDidOverridesBrokenDomainLink` |
| Android | `:app:assembleDebug :app:assembleRelease`（R8） | 建置成功，release APK 約 22.5 MB |

### 需要實機驗證

| 項目 | 步驟 | 預期 |
|---|---|---|
| NFC 出示 | 「使用」>「感應出示」，以另一台手機的 Multipaz 測試 App 或支援 18013-5 的讀取端感應 | 震動後出現同意畫面，同意後讀取端顯示資料；「紀錄」有一筆出示 |
| QR 出示 | 同上改用「改用 QR Code」 | 第一次要求「附近的裝置」權限，讀取端掃描後以藍牙完成 |
| 手機感應查驗 | 「查驗」>「感應查驗」，選「這支手機的 NFC」，讓另一台手機以感應出示 | 判定卡顯示結果，列出發行端信任與欄位 |
| USB 讀卡機 | 以 OTG 接上 ACR122U 等讀卡機，重新尋找讀卡機後選擇它 | 第一次詢問 USB 權限，之後同上 |
| 電腦 PC/SC | 桌面版接上 PC/SC 非接觸式讀卡機（Linux 需 pcscd），「感應查驗」選該讀卡機 | 手機以感應出示後顯示結果；沒有讀卡機時顯示原因 |
| DC API mdoc | 在支援 Digital Credentials API 的 Chrome 開啟要求 `org-iso-mdoc` 的網頁 | 選擇本錢包後出現同意畫面，網頁取得並驗證回應 |
| 非 TWDIW 離線出示 | 「查驗」選「任何綁定金鑰的證件」產生挑戰，另一台手機從證件內容頁「出示這張證件」掃描 | 出示 SD-JWT VC 的部分欄位，查驗端顯示發行端信任與狀態 |
| Verified ID 信任 | 以 Entra 租戶的發行 QR 領卡 | 顯示 Linked Domain 已驗證（T3），不需勾選警示 |
| 系統憑證庫 | 設定 > 信任錨點關閉「系統憑證庫」 | 只連到公開 CA 的發行端改為未列名 |


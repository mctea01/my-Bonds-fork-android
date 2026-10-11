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

# Microsoft Entra Verified ID 專門聲明

版本 1・生效日期 2026-11-05

## 重點摘要

- Verified ID 的領卡與出示經由 Microsoft 的雲端服務進行，Microsoft 與使用它的組織都會收到你的請求。
- 本 App 依 Microsoft 公開的協定與開源程式相容實作，不是 Microsoft Authenticator，與 Microsoft 沒有合作關係。
- Verified ID 卡片共用一把持有者金鑰，不同查驗方可能比對它，把你的出示串連起來。
- 不同意時，本 App 不處理 Verified ID 的領卡與出示請求；已保存的卡片保留。

## 1. 這項功能是什麼

Microsoft Entra Verified ID 是 Microsoft 提供給組織的可驗證憑證服務。同意後，本 App 可以用 openid-vc 連結或 QR Code 領取組織發行的卡片（包括登入組織帳號、填寫自述欄位與出示其他卡片），並出示給使用 Verified ID 的查驗方。

## 2. 營運者與資料流向

- 領卡與出示的請求與回應經由 Microsoft 營運的 Verified ID 服務傳送，再交給發行或查驗的組織。
- 領卡時送出持有者 DID 與公鑰、你登入組織帳號取得的權杖、你填寫的欄位，以及你選擇出示的其他卡片。
- 出示時送出你選擇的卡片與欄位、持有者 DID 與簽章。
- 本 App 會讀取組織網域上的 DID 設定（Linked Domains）確認組織身分，並以 Microsoft 的 DID 解析服務（discover.did.msidentity.com）解析 did:ion。
- Microsoft 依其隱私權聲明處理這些資料，組織依其政策處理。

## 3. 中央化的風險

- Microsoft 可以看到哪個組織在何時向你發卡或查驗；服務變更或停止時，卡片可能無法再出示或驗證。
- 組織可以撤銷卡片，撤銷狀態由 Microsoft 的服務提供。
- Verified ID 卡片使用同一把持有者金鑰，查驗方之間可能比對持有者 DID，把你在不同地方的出示串連起來。

## 4. 非官方的相容實作

本 App 不是 Microsoft Authenticator，與 Microsoft 沒有合作、認證或授權關係；Microsoft、Entra 與 Verified ID 是 Microsoft 的商標。相容功能依 Microsoft 的公開文件與開源錢包程式庫實作，Microsoft 變更協定時可能失效。

## 5. 不同意時

- openid-vc 連結與 QR Code 會提示這項功能已停用，本 App 不連線 Microsoft 的 Verified ID 服務。
- 不處理 Verified ID 形式的出示請求；標準的 OpenID4VP 請求與其他功能不受影響。
- 已保存的卡片保留在裝置上，但不會自動查詢狀態。

## 6. 同意的意思

同意表示你了解上述資料流向與風險，並要求本 App 代你與這項服務互動。同意不是使用本 App 的條件。你可以隨時在「設定 > 法律聲明與同意」撤回，撤回後本 App 立即停止連線這項服務；撤回前已完成的互動不受影響。

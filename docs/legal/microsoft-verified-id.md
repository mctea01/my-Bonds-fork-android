# Microsoft Entra Verified ID 專門聲明

版本 1・生效日期 2026-11-05

## 重點摘要

- Microsoft Entra Verified ID 是 Microsoft 提供的憑證服務；相關組織亦可能參與發行、查驗及保存資料。
- 本 App 依公開文件及相容協定處理 Verified ID 請求，**不是 Microsoft Authenticator，也未獲 Microsoft 認證、授權或背書**。
- Verified ID 相容卡片依目前設計共用持有者金鑰及識別資訊，出示紀錄可能被不同查驗方關聯。
- 不同意時停用 Verified ID 專屬領取、出示與狀態查詢，已存卡片保留；一般標準協定功能不受影響。

## 1. 服務內容

Microsoft Entra Verified ID 是 Microsoft 提供給組織發行及查驗可驗證憑證的服務。你選擇啟用後，本 App 可透過相容的 `openid-vc` 連結或 QR Code 領取組織發行的卡片，包括依流程登入組織、輸入自述欄位或出示其他卡片，亦可回應使用 Verified ID 服務的查驗請求。

## 2. 營運者與資料傳送

- **領取：** 相關請求及回應可能透過 Microsoft 的 Verified ID 雲端服務與組織系統傳遞，內容可包含持有者 DID、公鑰、授權權杖、使用者自述欄位，以及你選擇提供的其他卡片或證明。
- **出示：** 可能傳送選定憑證與欄位、持有者 DID、簽章及必要協定資訊給 Microsoft 的服務與查驗組織。
- **身分與 DID 解析：** 本 App 可能讀取組織網域中的 Linked Domains 設定及 DID 文件；解析 `did:ion` 時可向 Microsoft 解析端點（如 `discover.did.msidentity.com`）發送 DID 查詢。
- **狀態查詢：** 如服務有相關要求，本 App 可能向 Microsoft 或組織端查詢憑證撤銷狀態。

Microsoft 與各組織依其實際收到的資料、服務條款及隱私權政策分別處理；連線時可能取得你的 IP 位址、連線時間及相關識別資訊。

## 3. 服務及可追蹤性風險

- Microsoft 與相關組織可能得知領卡或查驗請求發生的時間與關聯對象；服務變更或停止時，可能無法繼續出示或驗證。
- 憑證可由授權的發行組織撤銷；狀態依相應服務提供的資料及查詢結果而定。
- 依目前相容設計，多張 Verified ID 卡片共用持有者金鑰；相同 DID 或可重複辨識的資訊可能讓查驗方跨情境關聯出示紀錄。只揭露選定欄位並不保證匿名。

## 4. 非官方相容實作

本 App 是獨立開發的相容工具，不是 Microsoft Authenticator，與 Microsoft 沒有隸屬、合作、認證、授權或背書關係。Microsoft、Entra、Verified ID 及 Microsoft Authenticator 等名稱或商標屬其權利人；本 App 僅為識別服務與說明互通用途而提及。

相關協定或安全要求可能更新，Microsoft 或組織亦可能拒絕本 App 的非官方實作，開發者不保證所有請求均可使用。

## 5. 不同意或撤回後

- 本 App 不處理 Verified ID 專屬的 `openid-vc` 領卡連結、QR Code 與特定出示請求，亦不依此整合連線 Microsoft 的 Verified ID 服務。
- 已保存的 Verified ID 卡片不因此刪除，但不會依本項整合進行自動狀態查詢。
- 一般 OpenID4VP 等標準請求仍可運作；如另有獨立 DID 解析或信任查詢功能，應依其一般資料流向及設定辦理，不將本項停用解讀為封鎖所有 Microsoft 網域。

## 6. 同意與撤回

「同意並啟用」表示你了解上述跨服務傳送、非官方相容性及識別可關聯風險，並選擇使用此項整合。你可以在「設定 > 法律聲明與同意」撤回，停止此整合後續請求；撤回前已送出或完成的互動，不因此失效或自動從 Microsoft 或組織系統刪除。其他 App 功能照常使用。

# TWDIW 1.0.14 領卡與簽章分析附件核對（2026-11-02）

本文件核對使用者提供的 `TWDIW_1.0.14_領卡與簽章逆向分析.md`，與本環境已驗證的官方簽署分割 APK、解封 DEX、Dart AOT 及既有量測比較。附件中的 PROVEN／OPEN 是其作者的判定，不直接作為新證據。原始附件保持不變。

最新版狀態：使用者再次提供 313 行修訂版後，本環境已解出簽章 VM 指令序列並追蹤成功路徑的六個建構子參數，將原始 package 名對到 appHash、公鑰 reader 結果對到 keyId。也已離線重現公鑰資產的兩層處理並取得下述具體指紋。先前核對結果保留為歷史紀錄，以「第二份附件與成功路徑值流」一節為最新狀態；appPlatform 明文與第三方准入仍未確認。

第三份 350 行修訂版已對齊上述結果。額外的離線算式搜尋得到 appPlatform 候選 `Android`，但尚未核對四個 native helper 的完整綁定與語意，不能升級為確定值；詳見「第三份附件與平台字串候選」。

後續雲端執行驗證：使用者要求在雲端執行後，已以 unidbg 實際執行該 SO 的初始化與四個 native helper，取得 98 筆註冊及四個確切函式位址。DTO 反射 class-name 表也已核對；七字元還原結果確為 **`Android`**，狀態升為 **native_emulation_verified**。以下 candidate_only 段落保留為當時紀錄，以 [native helper 雲端模擬驗證](twdiw-native-helper-emulation.md) 為最新依據。本輪執行了 JNI，沒有執行完整 APK 或讀取私鑰，第三方准入與正式伺服器接受仍未驗收。

## 核對結果

附件正確區分 holder proof 與 `dwapp-201i` 的應用簽章，也保留了手機註冊契約及 appHash／keyId 的未知部分。但「本機缺少解封後 b- DEX」不適用於目前工作區；該檔案仍在，且已重新核對完整 SHA-256。取得此檔是另一個環境的交接需求，並非本環境繼續分析的前置阻礙。

| 附件敘述 | 核對／校正 | 證據 |
|---|---|---|
| 本機沒有解封後 b- DEX | 目前檔案存在，2,263,872 bytes，SHA-256 `4bac5eefe40ec027a39b9f8e38261d1cec34edd41c110fda1815c84538ed0e2d` | `/workspace/scratch/twdiw-b-stage/classes.dex` |
| Token 的 `grant_type=pre-authorized_code` | wire 值須完整寫為 `urn:ietf:params:oauth:grant-type:pre-authorized_code`；縮寫不可直接抄進請求 | 公開 `http_service.dart` 第 66 行、商店版 AOT PP `0x8958` |
| proof 的 nonce 一律取 token `c_nonce` | 不完整。官方 AOT 在 token 值缺少時讀 metadata `nonce_endpoint`，呼叫 `getCNonce`；endpoint 回應與 token 回應都可能使用 `c_nonce` 欄位，須區分來源 | `vc_operations.dart` 指令 `0x2eabe4`、`0x2eabf8`、`0x2eac40`、`0x2ead18` |
| 改送 jwk 就是 11016 | 不能涵蓋所有組合。既有實測是只放 jwk、不放 kid 時拒絕；kid 加 jwk 曾通過 proof。無法由此推論「任何 jwk 都不接受」 | 既有 repo 實機紀錄，`AGENTS.md` 的 proof 規則；此輪未重送領卡 |
| dwapp 的 DER→raw／Base64URL 細節仍只有 holder 路徑證據 | 已在 dwapp 處理方法找到 helper 直接引用，見下節；完整虛擬分派仍未還原 | b- DEX file offset `0x0b2eac`、`0x0b25e2` |
| 可能重用 `hs415h1b` 同一 helper | 兩者做等價的 DER scalar 正規化，但此處引用 `r3OTB7M`；不宜寫成已證實重用 `hs415h1b` | 兩份主 DEX Java 匯出與 b- 的 invoke 指令 |
| 七欄由 Gson 字母序輸出 | 已證的是此 DTO adapter 明確依序寫出七欄，不是 Gson 對所有物件的普遍排序保證 | `IeeqwtWx.ebZ5jVfe` 的序列化方法 |
| appPlatform 7 字元幾乎可斷為 Android | 長度不能證明字面值；精確大小寫仍應保留待解 | 合成建構子的加密常數尚未在本輪解碼 |
| `libd186` 是 RASP 看門狗、若干命中皆是假陽性、封裝明確屬 DexGuard | 這些是附件提供的新主張，本輪未見其逐指令或工具輸出依據；不提升為已驗證結論。Application 名稱本身也不能排除商業保護工具 | 需另有 loader／JNI／native function 對照證據 |

本錢包對 metadata 公布的 nonce endpoint 優先取值，是既有實作與實機相容性規則；不能把它直接寫成「官方 AOT 在所有情況皆如此」。官方 AOT 的缺少 token nonce 分支和伺服器的實測接受條件須分開描述。proof nonce 與 `type=ecosyst` 的應用簽章 nonce 也不能互換。

11007 的公開錯誤字串是 `Pre-authorized_code not found`；某次 client_id 不符可能觸發此碼，仍不能把所有 11007 都解讀成缺少 `moda_dw`。11016 的公開字串是 `The proofs jwt is invalid:`，不能單靠此碼判定為某一項 DID、JWK 或 nonce 錯誤。

## dwapp 處理方法內的編碼證據

還原 b- DEX 的方法 `o.N3Kf59pP$mbkki7b3.QB1mryx(Object[])` code item 位於 file offset `0x0b1a6c`。原始 DEX 指令可確認兩項直接呼叫：

| DEX file offset | 呼叫 | helper 可確認的行為 |
|---|---|---|
| `0x0b2eac` | `o.r3OTB7M.ISyARpnL(byte[]) : byte[]` | 依 DER INTEGER 長度取 R、S，將各自補零或取尾端成 32 bytes，再串接成 64-byte `R||S` |
| `0x0b25e2` | `o.lJGlmuQP.mbkki7b3(byte[]) : String` | `Base64.encodeToString(input, 11)`，即 URL_SAFE、NO_WRAP、NO_PADDING |

對應目前 JADX 匯出：`N3Kf59pP.java` 第 25,657 行及第 25,377 行。`r3OTB7M.java` 第 123 行起為 DER 轉換，第 160 行起為 scalar 正規化；`lJGlmuQP.java` 第 158 行起為 Base64URL helper。行號只用於定位這份匯出，原始 DEX offset 較適合作交叉核對。

holder 的 `hs415h1b.ISyARpnL(String, String, byte[])` 則自行解析 DER、轉 BigInteger、將 R／S 正規化，再以 flag 11 編碼；不是直接呼叫上述 dwapp helper。

這補足了「dwapp 方法本身是否包含相應編碼 helper」的證據，仍不等於逐條還原整個虛擬指令分派、所有例外與最終值流。appHash／keyId 的精確來源保持 OPEN；有 DEX 不代表 JADX 就能直接輸出完全可讀的程式。

七欄 adapter 的輸出順序已獨立確認為：`appHash`、`appPlatform`、`appVersion`、`bodyHash`、`keyId`、`nonce`、`timestamp`。實際 Header DTO 為 alg／typ；本錢包現在另外放入 header.kid 是既有實作，不能反過來作為官方格式證據。

## 第二份附件與成功路徑值流

新版附件 SHA-256 為 `27be4c616a966cde73e7a8975bdf01f571b15f4c4a342a11cdd2815c31edc4d8`，共 313 行。它已採納前次的 grant_type、proof nonce、JWK、DTO 寫序與 DER helper 校正，但新增的 appHash／keyId 證據分級仍需與實際值流核對。附件引用的 `FINDINGS_stage-b_appHash_keyId.md` 不在此工作區；本輪直接使用相同 SHA-256 的 stage-b DEX 重新推導。

### VM 指令序列與參數映射

從 stage-b 的字串表提取簽章處理類別的 4,954 個 char，取索引 861 起的 4,093 個 char。以逐索引 XOR 算式還原後，得到可完整解析的 1,171 個 VM opcode，範圍為 -200 到 212；其 CSV SHA-256 為 `aa36e45baf86a9fb59709596a3a2127334d537397708b865a6d5997b10c08c42`。算式為：

```text
decoded[i] = table[861 + i] XOR ((i * 8091) AND 0xffff) XOR 25720
```

這是對該段常數資料的離線還原，不是呼叫保護層的 native A／D。Python 符號模型依主 DEX 的 `ObO36DXD` 算術與物件槽操作，從請求已反序列化的成功路徑開始，追到六參數 Payload 建構子。JSON 序列化、Context、公鑰 reader 等外部呼叫以具名符號結果代替；不執行 Application、ClassLoader、APK 或 JNI，也不執行實際簽章。

四組不同的保護狀態整數與兩組不同的 package／public-reader 符號輸入，均得到相同欄位映射：

| 六參數位置 | 符號來源 | 七欄 DTO 欄位 |
|---|---|---|
| 1 | 請求 `.body` | bodyHash |
| 2 | 請求 `.nonce` | nonce |
| 3 | `Context.getPackageName()` 原始結果 | appHash |
| 4 | 字面 `1.0.14` | appVersion |
| 5 | 請求 `.timestamp` | timestamp |
| 6 | `U0kvS8T2 → Qv6H7VWA()` 的公鑰 reader 結果 | keyId |

合成建構子再插入 appPlatform。此成功路徑的 appHash 沒有經過 SHA-256 或其他摘要；官方 manifest 的 package 為 `tw.gov.moda.diw`，故對應原始字串即為該值。這比「方法內沒搜到 MessageDigest」更直接，也補上附件尚標為 STRONG-INFERENCE 的棧槽對應。它是靜態模型與 DEX／DTO 的交叉核對，尚未取得執行時 JWS 或正式伺服器接受結果，不延伸為所有保護分支的執行驗收。

關鍵原始 DEX 核對：`0x0b2788` 是解碼後 `getPackageName` 的反射 invoke；`0x0b2790` 保存結果，`0x0b2796` 跳回共用 VM push。`0x0b2896` 呼叫六參數建構子。JADX simple 把部分例外區塊排在成功結果之後；符號模型依 DEX 的正常 goto 回到 VM，不能誤沿 move-exception 區塊落入下一個處理分支。

### 公鑰資產的第二層與具體指紋

附件的單層 `VVcmSog7_decrypt` 配方不完整。`Qv6H7VWA()` 在 `VVcmSog7` 之後還呼叫 `QB1mryx(InputStream, int, byte[], int, int)`，其結果為 `OQRQ3ZAh(ua7zwMYm(...))`；不能略過該層直接對外層文字做摘要。

本輪僅讀取官方 base APK 的 `assets/dwapp201i_public.txt`，其密文 SHA-256 為 `b3e2f652f23a75a2c729f524d016c3f4c79a5a3026bfb1ecb5308bd79af6fc41`。已按 reader 算術重現：

1. `VVcmSog7` 的 PCG 狀態更新，每 8 bytes 對首 byte 做 XOR。
2. `ua7zwMYm` 的 8-round block 解碼、mode 2 CBC 與 padding 去除；外層 `OQRQ3ZAh` 為緩衝包裝。
3. 將串流讀為 UTF-8，移除空白，得到 124-byte 的 Base64 公鑰文字。
4. 僅為格式交叉核對，以標準公鑰解析器驗證此文字可解成 secp256r1 公鑰；未輸出公鑰內容，未讀取任何 private 資產。
5. `nMP1zGej` 將正規化文字轉 UTF-8，交給摘要／小寫 hex helper；對該文字計算 SHA-256 的結果為：

```text
dfbbc7e88f69844fe449aca4f02ce1d719ddaaad9e3fd9dc25f1934869bc5a82
```

此值對應正規化後的公鑰文字，不是密文資產的 SHA-256，也不是 Base64 解碼後 DER 的 SHA-256。與上述成功路徑第六參數映射合併後，它是本輪得到的靜態 keyId 值；沒有拿它搭配官方私鑰產生或發送請求。精確配方應描述為 `lowercase_hex(SHA-256(UTF-8(strip_whitespace(read_public_asset_through_both_stream_layers)))))`。

摘要 helper 的 7-char 演算法常數亦可用索引 XOR 算式重現為 `SHA-256`，而非只以字串長度猜測。此算式使用 helper 的實際 char 陣列、步長 49043，以及其 static long XOR 常數的低 16 bits；未呼叫其 native 輔助方法。

### native library 的附件錯誤

新版稱「APK 未直接附帶 libd186.so」，但已驗簽的 `split_config.arm64_v8a.apk` 明確含有 `lib/arm64-v8a/libd186.so`，大小 1,612,328 bytes，SHA-256 `58965369093f15eaaad64181744a3bfb2e3e30d9d79b2899a5eec58ce50afbd5`，與合併包相同。

`A6APTThS` clinit 的實際呼叫是反射 `ClassLoader.findLibrary("d186")`，再把回傳路徑傳給 `System.load`；不能簡化為直接執行 `System.load("d186")` 並據此推論缺少檔案。這不自動證明所有 native 方法的行為，也未補上 appPlatform 明文。

### 本輪可重現產物與限制

`/workspace/scratch/twdiw_decode_public_asset.py` 只讀 public 資產，`twdiw-public-asset-result.json` 保存長度、曲線及摘要；`twdiw_trace_payload.py` 保存 VM 解碼與符號模型，`twdiw-payload-trace-*.json` 保存參數對應。本輪補充包為 `/workspace/scratch/twdiw-analysis-handoff-1.0.14-v2.zip`，包括這些結果、可攜式腳本、相關 helper 匯出與原 DEX。

尚未解決 appPlatform 明文、官方應用准入契約與伺服器驗收。這次進展不支持改送猜測的手機註冊 POST，也未修改本錢包的領卡或金鑰實作。

## 第三份附件與平台字串候選

第三份附件共 350 行，SHA-256 為 `31a2cedf9ed5dd543b39bda5ec4f827819bcf328e2b1776a0b0f59dca21fd384`。與前份相比，已採納本輪的 VM 欄位映射、keyId hex、公鑰雙層處理及 libd186 分包內容校正，沒有增加 appPlatform 的實機 JWS、完整 native 語意或應用准入證據。成功路徑結果仍一致。

需區分兩種雜湊：

| 對象 | SHA-256 |
|---|---|
| 正規化公鑰文字，即靜態 keyId | `dfbbc7e88f69844fe449aca4f02ce1d719ddaaad9e3fd9dc25f1934869bc5a82` |
| v2 包內 `evidence/public-asset-result.json` 檔案本身 | `82830b349bd909c342f60316341f07a8db0d36183f96bc6c4605e26a337c9e9e` |
| v2 ZIP 本身 | `d59d92b9558790dc9cf575979b0d351a4ccdbc61a6ef841d9e51aa2623748dc2` |

附件「主要檔案雜湊」表將 `public-asset-result.json` 的欄位值放入 SHA 欄，容易被當成 JSON 檔案雜湊；應改標為正規化公鑰文字摘要。附件所述「v2 ZIP 本機未見」是另一個工作環境的狀態；本環境的 ZIP 存在，2,187,433 bytes，35 個檔案，CRC 核對通過，無需重新取得。

### appPlatform 的算式候選

主 DEX 合成建構子的已知資料包括：初始四槽 `[40134,28111,36685,19654]`、7 個密文 char、步進乘數 32718，以及低 16-bit seed 53148。Java helper 對狀態與密文做 XOR，尾端固定 mask 可化簡為 `0x7ce7`；兩個索引及 remainder／quotient 的實際計算交給 native helper。

`/workspace/scratch/twdiw_platform_candidate.py` 對 modulus `{65535,65536,65537}`、兩個索引偏移各 `{0,1,2,3}`，共 48 組組合做離線算式搜尋。在假設 native n／l 分別使用和數的餘數／商數時，只有一組得到完整可列印字串：

```text
modulus = 65535
first_index = (i + 2) % 4
second_index = (i + 3) % 4
candidate = Android
```

這比僅按 7 字元長度猜測多了可重現的算式，但搜尋範圍與四個 native 語意仍是模型假設。對已驗證的 `libd186.so` 做 Capstone 靜態反組譯，確實可見 `0x59458: mov w9, #0xffff`、`0x5945c: sdiv w8, w8, w9`；尚未把該基本區塊完整綁到本處的 JNI l，也未證實另外三個 helper。因此保持 `candidate_only`，不能聲稱 appPlatform 已閉合或據此改正式請求。

此 Java helper 可見的是四槽乘法、carry 與 XOR 操作；若稱它為 Feistel，仍需說明具體輪函式與交換結構，不能只憑加密常數或 native 呼叫判定。

候選結果保存於 `/workspace/scratch/twdiw-platform-candidate.json`，明列假設與 `native_binding_verified=false`。未執行 APK／JNI、未讀取新的金鑰資產、未發出網路請求。此輪只更新研究紀錄，原始附件及 v2 ZIP 保持不變。

## 第四份附件核對

第四份附件共 370 行，SHA-256 為 `75ed78a829ee91eafd4c471edb34ba3c681008e18a005df851b093d226201e7a`。本次差異已納入第三輪的 appPlatform 算式候選、native 綁定未證、公鑰文字摘要與 JSON／ZIP 檔案雜湊的區分，並校正 v2 ZIP 的跨環境記錄。

此版沒有增加新的 JNI 方法綁定、執行時 JWS、手機裝置註冊端點或第三方准入證據。`Android` 維持 candidate_only；appHash／keyId 的成功路徑靜態結果維持不變。附件所稱另一環境的獨立重現屬該文件的回報，本輪未重新驗證其工作區或據此提升證據等級。

本輪只核對文件差異並記錄版本，未改原始附件、分析包、候選算式或領卡程式，也未重跑沒有變動的 APK 分析。

## 第五份附件與模擬結果核對

第五份附件共 377 行，SHA-256 為 `79da62c339b9c6037ebfff0e12ce58aa976d7ad900c425e525faf62a902ff624`。本輪逐項比較其列出的 `JniProbe.java`、`run-02.log`、`native-verification-result.json` 完整 SHA-256，全部與本環境原始產物一致。

新增的 98 筆 JNI 註冊、四個方法相對位址、七個輸出 codepoint、`jni_executed=true` 及 `full_apk_executed=false` 等敘述均與已保存結果相符。`appPlatform=Android` 的 native_emulation_verified 記錄正確；本輪未重跑沒有變動的目標程式。

需繼續區分後續證據的用途：取得官方 App 的實機 JWS 可核對官方實際輸出，不能單憑它證明第三方皮夾可用自己的應用身分與金鑰領卡。第三方應用准入契約、使用第三方身分的服務端接受結果，以及官方 App 的實機輸出應分別驗收。附件開頭的「均已解決」只適用列出的欄位／簽章路徑研究，不應延伸成官方領卡互通已完成。

## 抓包與實機 Hook 失敗後的替代方法

使用者回報抓包與 Hook 實測皆失敗。本輪先重新搜尋既有官方公開 App／伺服器來源，未取得新生態系簽章的 appPlatform 產生或驗證程式；唯讀取得 `https://frontend.wallet.gov.tw/` 回 HTTP 404，沒有可供繼續追蹤的根頁 script 清單。此結果不代表整個服務不存在前端資源或新版本來源，只表示這次入口沒有補足證據。

### 優先方向：離線 JNI 模擬

可在電腦以 unidbg 建 ARM64／JNI 模擬環境，載入選定 SO，將問題限縮為「取得 native 註冊映射並驗證四個小 helper」。它會執行 `.so` 的機器碼，屬離線動態分析，不是純靜態；不需要先使官方 APK 在手機正常運作、代理解密或讓 Frida 附加成功。本輪未載入／執行目標 SO，也沒有聲稱它已在該框架可運作。

框架能力已直接核對 [unidbg README](https://github.com/zhkl0228/unidbg/blob/master/README.md) 與 [DalvikVM64.java 的 RegisterNatives 實作](https://github.com/zhkl0228/unidbg/blob/master/unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/DalvikVM64.java#L3440)。2026-11-02 取得的實作在模擬器服務內接收 class、methods、count，逐筆讀取 name／signature／fnPtr，保存至 nativesMap，並能輸出映射。若目標初始化確實走到此標準 JNI 介面，就能在該邊界觀察執行時的註冊資料，無需先於檔案中找到明文表。

最小實驗應只涵蓋目標 library 的相依初始化、所需 Class／Field 物件和四個 helper，關閉目標的外部網路並限制可讀檔案與執行步數；以小整數驗證餘數／商數與索引，保留函式位址和傳回值。不要將是否印出 `Android` 作為唯一成功條件，仍要連回實際 JNI 映射。未知的 syscall、相依庫、完整性檢查或初始化 VM 都可能使模擬中止；實機 Hook 失敗不證明模擬一定成功或失敗。

### 純靜態替代路徑

- 針對 JNI 註冊資料做向後切片／符號求值，只處理表位址、筆數、name／signature／fnPtr 的生成與相關跳表；可使用 Ghidra p-code、angr 或自製 ARM64 算術模型。這條路仍可能受間接跳躍與狀態數量限制，但不是只剩整個 JNI_OnLoad 全部反混淆才有進展。
- 以相鄰版本或其他平台的合法 SDK／程式／驗證端契約做交叉核對，尋找未保護的欄位定義或同一 generic helper；最後仍須回對目前 Android 1.0.14 的引用與資料流。舊公開 iOS／Android 來源目前沒有這層簽章，不能直接沿用舊版結論。

即使 appPlatform 最終確認為 `Android`，第三方應用如何取得官方接受的簽章身分仍是獨立缺口。模擬 helper 或解出常數不是官方互通驗收，也不需要讀取私鑰資產或產生官方簽章。

本輪僅核對替代路徑的框架能力與公開入口；工具來源下載保存於 `/workspace/scratch/twdiw-alternative-evidence/`，未安裝或測試 unidbg 的目標 library harness。

## 第一輪可交接的分析包

已建立 `/workspace/scratch/twdiw-analysis-handoff-1.0.14.zip`，內容包含：

- 解封的 stage-a／stage-b DEX，含各檔 SHA-256 清單。
- 內層 SDK 的 `N3Kf59pP`、`G91c5eRH` 既有 JADX 匯出，以及主 DEX 的 DTO、虛擬分派器與編碼 helper 匯出。
- 已註記的 Dart `vc_operations`、`http_service` AOT 指令，以及分割 APK 核對摘要。
- README 說明來源、定位 offset、再匯出方法與仍未解決的欄位；不含金鑰資產或解碼私鑰。

包內 Java 是反編譯偽碼，不能作為可編譯來源；stage-b 的 JADX 1.5.6 simple 匯出完成但有 18 個錯誤。資料流分析應以 DEX 交叉驗證。分析包不提交 repo，原始附件也未修改。

此輪完成的是附件校正、靜態引用核對及產物交接；沒有安裝／執行 APK、沒有新增網路探測、未取出或重用官方私鑰，也沒有修改領卡程式。後續依然需要還原 appHash／keyId 的虛擬分派值流與官方應用准入契約，不能以猜測的手機註冊 POST 補上缺口。

來源與既有驗證詳見 [裝置金鑰註冊查證](twdiw-device-registration.md)。

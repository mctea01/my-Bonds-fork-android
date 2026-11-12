# R09／R10：不啟動 wasm2native／Perry

本輪清冊沒有發現「PC 必需、只有 WASM／JS 實作、且合理原生來源路線不可行」的密碼學依賴。BB 為 C++，Noir/ACVM、OpenAC graph evaluator、TLSNotary、zkPassport 與 OPRF 都有現用 Rust/C++ 原始碼。故本專案目前無必要引入 wasm2native 或 Perry；不新增工具鏈、不做無對象效能比較。

這不代表整個 App 沒有 runtime WASM／JavaScript：

- Android DC API 接收 matcher WASM 位元組並在平台 host 執行；把它轉成 object 無法滿足同一註冊契約，也不會新增 PC 平台能力。來源與呼叫點見清冊。
- PortalWebView 與 OpenCert renderer 使用 DOM、瀏覽器訊息及遠端網頁契約。Perry 不會自動取代 WebView/DOM 或第三方動態頁面；未來桌面技術選型需另處理瀏覽器整合。
- bb.js 與 Circom WASM 的研究／向量生成用途不構成 App runtime 原生化需求。

因此目前轉譯方案沒有可比較的合格依賴，性能、產物大小與維護工時均為 `not-tested`／不適用，不能捏造定量優勢。只有日後找到具體不可替代的 runtime 模組，並證明原生路線不可行，才重新開啟這兩個工作包；當時須固定模組版本並列 imports、memory、SIMD、threads、host APIs、allocator、ABI 和額外 runtime 成本。

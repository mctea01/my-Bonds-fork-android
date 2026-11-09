# 證據保存方式

`baseline.json` 固定專案來源、規格雜湊、工具鏈及已執行命令；各實驗 JSON 保存產物 hash、command、exit status 與測試界線。CSV 的 artifact hash 是原始下載檔／archive entry 的 SHA-256，不是 CSV 本身的 hash。

收入 Git 的 CSV／純文字 log 統一使用 LF，移除行尾空白與多餘 EOF 空行；未刪除失敗節點或改寫命令結果。JSON 內嵌 stdout 保留原字串。離線 Gradle 的 FAILED 節點保留作為初始環境記錄，後續成功的 online 報告另存。

本目錄不保存第三方二進位、真實證件、私鑰或私密輸入。原生產物與下載檔僅在暫存／repo 外研究目錄；重現方法見 [研究工具](../../../../tools/native-research/README.md)。

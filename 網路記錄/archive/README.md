# 歷史擷取存檔

2026-07-02 整理時，發現 Zeek 擷取輸出散落三處（repo 根目錄、`Zeek監控/`、`網路記錄/`），
官方位置應為 `網路記錄/`（見 `文件/系統文件/檔案說明.md`）。整理方式：

| 子目錄 | 內容 | 原始位置 |
|---|---|---|
| `2026-04-25_舊擷取/` | 該日期的 Zeek 擷取（conn/dns/files/http/ntp/packet_filter/reporter/ssl/weird.log） | `網路記錄/`（git 追蹤，initial commit） |
| `2026-05-05_Zeek監控舊擷取/` | 該日期的 Zeek 擷取 | `Zeek監控/`（誤在此目錄啟動 Zeek 產生，非官方位置；亦為 git 追蹤，initial commit） |

當時「即時擷取中」的檔案（repo 根目錄 conn/dns/packet_filter/reporter/weird.log）已搬到
`網路記錄/` 本層（非 archive），為當下最新一次擷取，並移除 git 追蹤（見 `.gitignore`：
`網路記錄/*.log` 不再自動追蹤，證據需要留存時手動 `git add` 到 `archive/` 底下）。

`Zeek監控/test/*.log` 是 `Zeek監控/test/gen_test_pcap.py` 產生的單元測試 fixture，
與這裡的即時擷取無關，未搬動。

日後啟動 Zeek 請先 `cd 網路記錄` 再執行，勿在 repo 根目錄或 `Zeek監控/` 內跑，
避免再度散落（見 `展示指令/README.md` 全開防護啟動流程）。

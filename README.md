# 🛡️ Server Guardian (Windows Server 安全哨兵)

![Rust](https://img.shields.io/badge/Language-Rust-orange)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![License](https://img.shields.io/badge/License-MIT-green)

一個專為 Windows Server (相容 Win10/11, Server 2016/2019/2022) 打造的**在地內網純淨防護盾**。採用 Rust 編寫，輕量、高效、無額外依賴。

---

## 📖 專案簡介

`Server Guardian` 是一個執行在 Windows 伺服器上的主動式防禦工具。它會持續監控系統的安全事件日誌（Event ID 4625 登入失敗），並在發現暴力破解行為時，自動呼叫 Windows 防火牆封鎖惡意 IP 網段。

同時，它具備了**桌面 GUI** 與 **內建 Web 遠端監控** 雙介面，並導入了 **SQLite 資料庫** 進行持久化儲存，方便網管人員隨時審計歷史安全事件。

---

## ✨ 核心功能

- **⚡ 自動防爆破 (Auto Fire Ban)**：5 分鐘內連續登入失敗 3 次，自動封鎖該 IP 所在的 `/24` 網段。
- **👤 惡意帳戶與進程隔離**：掃描非白名單的本機帳戶與可疑 Shell 進程（如 WSL、Cygwin），提供「放行」或「強殺」選項。
- **🖥️ 雙端監控**：原生桌面 GUI (egui)，加上 Axum 搭建的 Web 儀表板，區域網路內任何設備皆可透過瀏覽器監控。
- **💾 SQLite 冷熱資料分離**：資料自動落盤。每日自動將 30 天前的舊資料歸檔至 `db/backups/` 目錄。
- **📅 歷史查詢與沙箱審計**：支援日曆選擇與關鍵字搜尋，並可**唯讀掛載**舊備份庫（沙箱模式），安全審查歷史紀錄而不影響主系統。
- **🛡️ RDP 限制策略**：一鍵套用 Windows 防火牆規則，限制 RDP 僅允許特定內網與公司網段連入。

---

## 🚀 快速開始

### 1. 環境準備
請確保你的開發機已安裝 [Rust](https://rustup.rs/)。建議使用 GNU 編譯目標以獲得最佳的舊系統相容性：

```bash
rustup target add x86_64-pc-windows-gnu

# 複製專案
git clone https://github.com/your-username/server-guardian.git
cd server-guardian

# 編譯 Release 版本
cargo build --release --target x86_64-pc-windows-gnu
# 複製專案
git clone https://github.com/your-username/server-guardian.git
cd server-guardian

# 編譯 Release 版本
cargo build --release --target x86_64-pc-windows-gnu

server_guardian.exe          # 主程式
index.html                   # Web 前端 (需存在)
server_guardian_config.json  # 白名單與系統設定
debug_log.txt                # 黑匣子排錯日誌 (閃退時查看)
db/
 ├── server_guardian.db      # 主資料庫 (即時日誌與封禁記錄)
 └── backups/                # 歸檔目錄 (存放 30 天前的舊庫)

📖 使用說明 (How to Use)
🖥️ 桌面端操作
啟動防禦：點擊主面板的「🟢 啟動防毒攔截防禦」，程式將每 5 秒執行一次掃描。

威脅隔離區：右側面板會顯示攔截到的未授權帳戶或進程，點擊 放行 (加入白名單) 或 封殺 (停用帳戶/結束進程)。

核心設定：可自訂帳戶白名單、開關 Auto Fire Ban、開啟 RDP 限縮模式。

🌐 Web 遠端監控
程式啟動後，桌面端右上角會顯示 Web 連接埠（預設 8080，若被佔用會隨機分配）。

在區域網路內任意裝置的瀏覽器輸入：http://伺服器IP:8080。

提供即時日誌、封禁清單、歷史日期查詢與關鍵字搜尋。

📅 歷史紀錄與沙箱審計
點擊頂部「📅 歷史紀錄」標籤。

沙箱模式：從「📂 查看備份」下拉選單中選擇歸檔的 .db 檔案，系統會以唯讀模式開啟該舊庫，讓你在不影響主系統的情況下，安全地查閱過去的歷史封禁與日誌。

🛠️ 技術架構
GUI 框架: eframe / egui (Glow 渲染)

非同步執行環境: tokio

Web 框架: axum

資料庫: rusqlite (SQLite, WAL 模式)

時間處理: chrono

系統互動: std::process::Command (靜默呼叫 PowerShell 與 CMD)

日曆與表格組件: egui_extras

⚠️ 開發者注意事項 (Git)
本專案已配置 .gitignore，請確保不要將以下檔案提交到版本控制中：

/target (Rust 編譯快取)

db/ (包含 SQLite 資料庫與備份)

*.exe, *.pdb (編譯後的二進位檔)

server_guardian_config.json (本機配置)

// =========================================================================
// 20261029: 項目完整版 - 包含桌面端、SQLite 歷史記錄、Web 服務端
// 20261029: 優化 Web 端口分配 (優先 8080，被佔用則自動隨機分配)
// 20261029: 全面防禦 Panic 崩潰，加入安全錯誤處理
// 20261029: 加入 30 天冷熱數據自動歸檔 (打包至 db/backups/)
// 20261029: 增加歷史記錄沙箱查看模式 (只讀舊庫，不影響當前系統)
// 20261029: 新增「防匿名登入探測 (4624)」自動封禁功能
// 20261029: 修復切換標籤時歷史紀錄不會自動刷新（顯示空）的 Bug
// 20261029: 【優化】修復 4625 與 4624 共用鎖的時間誤差、精準判斷內網 IP
// 20261029: 【最終修復】廢棄容易排版崩潰的 TableBuilder，改用原生 Grid 繪製表格，保證顯示
// =========================================================================

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use chrono::{Local, NaiveDate};
use eframe::egui;
use egui_extras::DatePickerButton;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};

const CREATE_NO_WINDOW: u32 = 0x08000000;
const CONFIG_FILE: &str = "server_guardian_config.json";
const DB_FILE: &str = "db/server_guardian.db";
const BACKUP_DIR: &str = "db/backups";
const MAX_LOG_LINES: usize = 500;

#[derive(Clone, Copy, PartialEq)]
enum ActiveTab {
    Live,
    History,
    Settings,
}

// 精準判斷是否為內網 IP
fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        addr.is_private()
    } else {
        false
    }
}

fn log_to_file(msg: &str) {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    path.pop();
    path.push("debug_log.txt");
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "[{}] {}", Local::now().format("%H:%M:%S"), msg);
    }
}

// ─────────────────────────────────────────────────────────
// SQLite 數據庫模塊
// ─────────────────────────────────────────────────────────
struct Database {
    conn: StdMutex<Connection>,
}

#[derive(Serialize)]
struct WebLog { timestamp: String, message: String }

#[derive(Serialize)]
struct WebBan { ip: String, rule_name: String, banned_at: String, reason: String }

impl Database {
    fn new() -> Self {
        if let Some(parent) = Path::new(DB_FILE).parent() {
            if !parent.exists() { let _ = std::fs::create_dir_all(parent); }
        }
        
        let conn = match Connection::open(DB_FILE) {
            Ok(c) => c,
            Err(e) => {
                log_to_file(&format!("❌ 無法打開資料庫: {}, 嘗試重建...", e));
                let _ = std::fs::rename(DB_FILE, format!("{}.bak", DB_FILE));
                Connection::open(DB_FILE).expect("重建資料庫失敗")
            }
        };

        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;").ok();
        
        if let Err(e) = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS banned_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                rule_name TEXT NOT NULL,
                banned_at TEXT NOT NULL,
                reason TEXT NOT NULL
            );"
        ) {
            log_to_file(&format!("❌ 初始化資料庫表失敗: {}", e));
        }
        
        Self { conn: StdMutex::new(conn) }
    }

    fn insert_log(&self, timestamp: &str, message: &str) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute("INSERT INTO logs (timestamp, message) VALUES (?1, ?2)", params![timestamp, message]);
        }
    }

    fn insert_banned_ip(&self, ip: &str, rule_name: &str, reason: &str) {
        if let Ok(conn) = self.conn.lock() {
            let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let _ = conn.execute(
                "INSERT OR IGNORE INTO banned_ips (ip, rule_name, banned_at, reason) VALUES (?1, ?2, ?3, ?4)",
                params![ip, rule_name, now, reason],
            );
        }
    }

    fn clean_old_data(&self) {
        if let Ok(conn) = self.conn.lock() {
            let thirty_days_ago = (Local::now() - chrono::Duration::days(30)).format("%Y-%m-%d %H:%M:%S").to_string();
            
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM logs WHERE timestamp < ?1", 
                params![thirty_days_ago], 
                |row| row.get(0)
            ).unwrap_or(0);

            if count == 0 { return; }

            log_to_file(&format!("🗄️ 準備歸檔 {} 筆 30 天前的舊日誌...", count));

            if !Path::new(BACKUP_DIR).exists() { 
                let _ = std::fs::create_dir_all(BACKUP_DIR); 
            }
            
            let date_str = Local::now().format("%Y%m%d_%H%M%S").to_string();
            let backup_path = format!("{}/archive_{}.db", BACKUP_DIR, date_str).replace("\\", "/");

            let sql = format!(
                "ATTACH DATABASE '{}' AS backup_db;
                 CREATE TABLE IF NOT EXISTS backup_db.logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, message TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS backup_db.banned_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, rule_name TEXT NOT NULL, banned_at TEXT NOT NULL, reason TEXT NOT NULL);
                 INSERT INTO backup_db.logs SELECT * FROM logs WHERE timestamp < '{}';
                 INSERT INTO backup_db.banned_ips SELECT * FROM banned_ips WHERE banned_at < '{}';
                 DETACH DATABASE backup_db;",
                backup_path, thirty_days_ago, thirty_days_ago
            );

            if conn.execute_batch(&sql).is_ok() {
                let _ = conn.execute("DELETE FROM logs WHERE timestamp < ?1", params![thirty_days_ago]);
                let _ = conn.execute("DELETE FROM banned_ips WHERE banned_at < ?1", params![thirty_days_ago]);
                log_to_file(&format!("✅ 歸檔成功，舊資料已保存至 {}", backup_path));
            } else {
                log_to_file("❌ 舊資料歸檔失敗，主庫資料未刪除。");
            }
        }
    }

    fn get_logs_by_date(&self, date: &str, keyword: &str) -> Vec<(String, String)> {
        let conn = match self.conn.lock() { 
            Ok(c) => c, 
            Err(e) => {
                log_to_file(&format!("❌ 取得資料庫鎖失敗: {}", e));
                return Vec::new() 
            } 
        };
        
        let mut stmt = match conn.prepare("SELECT timestamp, message FROM logs WHERE timestamp LIKE ?1 AND message LIKE ?2 ORDER BY id DESC LIMIT 500") {
            Ok(s) => s, 
            Err(e) => {
                log_to_file(&format!("❌ 準備 SQL 語句失敗: {}", e));
                return Vec::new() 
            },
        };
        
        let date_like = format!("{}%", date);
        let key_like = format!("%{}%", keyword);
        
        let rows = match stmt.query_map(params![date_like, key_like], |row| Ok((row.get(0)?, row.get(1)?))) {
            Ok(r) => r, 
            Err(e) => {
                log_to_file(&format!("❌ 查詢資料失敗: {}", e));
                return Vec::new() 
            },
        };
        rows.filter_map(Result::ok).collect()
    }

    fn get_bans_by_date(&self, date: &str, keyword: &str) -> Vec<(String, String, String, String)> {
        let conn = match self.conn.lock() { 
            Ok(c) => c, 
            Err(e) => {
                log_to_file(&format!("❌ 取得資料庫鎖失敗: {}", e));
                return Vec::new() 
            } 
        };
        
        let mut stmt = match conn.prepare("SELECT ip, rule_name, banned_at, reason FROM banned_ips WHERE banned_at LIKE ?1 AND ip LIKE ?2 ORDER BY id DESC") {
            Ok(s) => s, 
            Err(e) => {
                log_to_file(&format!("❌ 準備 SQL 語句失敗: {}", e));
                return Vec::new() 
            },
        };
        
        let date_like = format!("{}%", date);
        let key_like = format!("%{}%", keyword);
        
        let rows = match stmt.query_map(params![date_like, key_like], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))) {
            Ok(r) => r, 
            Err(e) => {
                log_to_file(&format!("❌ 查詢封禁紀錄失敗: {}", e));
                return Vec::new() 
            },
        };
        rows.filter_map(Result::ok).collect()
    }

    fn get_latest_logs(&self) -> Vec<WebLog> {
        let conn = match self.conn.lock() { Ok(c) => c, Err(_) => return Vec::new() };
        let mut stmt = match conn.prepare("SELECT timestamp, message FROM logs ORDER BY id DESC LIMIT 100") {
            Ok(s) => s, Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| Ok(WebLog { timestamp: row.get(0)?, message: row.get(1)? })) {
            Ok(r) => r, Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }

    fn get_latest_bans(&self) -> Vec<WebBan> {
        let conn = match self.conn.lock() { Ok(c) => c, Err(_) => return Vec::new() };
        let mut stmt = match conn.prepare("SELECT ip, rule_name, banned_at, reason FROM banned_ips ORDER BY id DESC LIMIT 100") {
            Ok(s) => s, Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| Ok(WebBan { ip: row.get(0)?, rule_name: row.get(1)?, banned_at: row.get(2)?, reason: row.get(3)? })) {
            Ok(r) => r, Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }
}

// ─────────────────────────────────────────────────────────
// Web 服務器模塊
// ─────────────────────────────────────────────────────────
#[derive(Deserialize)]
struct WebQuery {
    date: Option<String>,
    keyword: Option<String>,
}

async fn start_web_server(db: Arc<Database>) -> u16 {
    let app = Router::new()
        .route("/", get(web_index))
        .route("/api/logs", get(web_api_logs))
        .route("/api/bans", get(web_api_bans))
        .with_state(db);

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8080").await {
        Ok(l) => l,
        Err(_) => {
            log_to_file("⚠️ 端口 8080 被佔用，正在尋找隨機可用端口...");
            match tokio::net::TcpListener::bind("0.0.0.0:0").await {
                Ok(l) => l,
                Err(e) => {
                    log_to_file(&format!("❌ 無法綁定任何 Web 端口: {}", e));
                    return 0;
                }
            }
        }
    };

    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    log_to_file(&format!("🌐 Web 服務已啟動: http://0.0.0.0:{}", port));

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            log_to_file(&format!("❌ Web 服務運行錯誤: {:?}", e));
        }
    });

    port
}

async fn web_index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn web_api_logs(State(db): State<Arc<Database>>, Query(params): Query<WebQuery>) -> impl IntoResponse {
    if let Some(date) = params.date {
        if !date.is_empty() {
            let keyword = params.keyword.unwrap_or_default();
            let results = db.get_logs_by_date(&date, &keyword);
            let web_logs: Vec<WebLog> = results.into_iter().map(|(t, m)| WebLog { timestamp: t, message: m }).collect();
            return Json(web_logs);
        }
    }
    Json(db.get_latest_logs())
}

async fn web_api_bans(State(db): State<Arc<Database>>, Query(params): Query<WebQuery>) -> impl IntoResponse {
    if let Some(date) = params.date {
        if !date.is_empty() {
            let keyword = params.keyword.unwrap_or_default();
            let results = db.get_bans_by_date(&date, &keyword);
            let web_bans: Vec<WebBan> = results.into_iter().map(|(ip, rule, time, reason)| WebBan {
                ip, rule_name: rule, banned_at: time, reason
            }).collect();
            return Json(web_bans);
        }
    }
    Json(db.get_latest_bans())
}

// ─────────────────────────────────────────────────────────
// PowerShell 定位與執行
// ─────────────────────────────────────────────────────────
fn powershell_exe() -> PathBuf {
    let sysnative = Path::new(r"C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe");
    if sysnative.exists() { return sysnative.to_path_buf(); }
    let system32 = Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    if system32.exists() { return system32.to_path_buf(); }
    PathBuf::from("powershell")
}

const PS_PREFIX: &[&str] = &["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"];

async fn ps_run(script: &str) -> Option<std::process::Output> {
    let mut cmd = Command::new(powershell_exe());
    cmd.creation_flags(CREATE_NO_WINDOW).kill_on_drop(true);
    for a in PS_PREFIX { cmd.arg(a); }
    cmd.args(&["-Command", script]).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.output().await.ok()
}

fn ps_run_sync(script: &str) -> Option<std::process::Output> {
    let mut cmd = std::process::Command::new(powershell_exe());
    cmd.creation_flags(CREATE_NO_WINDOW);
    for a in PS_PREFIX { cmd.arg(a); }
    cmd.args(&["-Command", script]).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.output().ok()
}

fn is_elevated() -> bool {
    std::process::Command::new("whoami").creation_flags(CREATE_NO_WINDOW).args(&["/groups"]).output()
        .map(|o| { let s = String::from_utf8_lossy(&o.stdout); s.contains("S-1-16-12288") || s.contains("S-1-16-16384") }).unwrap_or(false)
}

fn is_server_core() -> bool {
    std::process::Command::new("reg").creation_flags(CREATE_NO_WINDOW)
        .args(&["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "/v", "InstallationType"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Server Core")).unwrap_or(false)
}

fn detect_os_caption() -> String {
    if let Ok(o) = std::process::Command::new("reg").creation_flags(CREATE_NO_WINDOW)
        .args(&["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "/v", "ProductName"]).output()
    {
        let s = String::from_utf8_lossy(&o.stdout);
        for line in s.lines() {
            if line.contains("ProductName") {
                if let Some(v) = line.split("REG_SZ").nth(1) {
                    let v = v.trim(); if !v.is_empty() { return v.to_string(); }
                }
            }
        }
    }
    "Windows (未知版本)".to_string()
}

// ─────────────────────────────────────────────────────────
// 數據模型
// ─────────────────────────────────────────────────────────
#[derive(Clone, PartialEq, Debug)]
enum ThreatType { UnknownAccount(String), SuspiciousShell(String) }

#[derive(Clone, Debug)]
struct PendingThreat { id: u64, threat_type: ThreatType, detected_time: String, description: String }

#[derive(Serialize, Deserialize, Clone)]
struct AppConfig {
    allowed_users_raw: String,
    #[serde(default)] first_run_done: bool,
    #[serde(default)] auto_fire_ban: bool,
    #[serde(default)] strict_net_wall: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self { allowed_users_raw: String::new(), first_run_done: false, auto_fire_ban: false, strict_net_wall: false }
    }
}

struct GuardianApp {
    config: AppConfig,
    db: Arc<Database>,
    allowed_users_live: Arc<RwLock<HashSet<String>>>,
    is_monitoring: bool,
    active_tab: ActiveTab,
    autostart_enabled: bool,
    shutdown_trigger: Arc<AtomicBool>,
    monitor_handle: Option<tokio::task::JoinHandle<()>>,
    logs: Arc<Mutex<Vec<String>>>,
    pending_threats: Arc<Mutex<Vec<PendingThreat>>>,
    last_scan_at: Arc<RwLock<Option<Instant>>>,
    last_4625_check: Arc<RwLock<Option<Instant>>>,
    last_4624_check: Arc<RwLock<Option<Instant>>>,
    elevated: bool,
    
    history_date: NaiveDate,
    history_search: String,
    history_logs: Vec<(String, String)>,
    history_bans: Vec<(String, String, String, String)>,
    web_port: u16,
    
    backup_files: Vec<String>,
    selected_backup: Option<String>,
    is_sandbox: bool,
}

fn parse_users_to_set(raw: &str) -> HashSet<String> {
    raw.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect()
}

async fn add_log(logs: &Arc<Mutex<Vec<String>>>, db: &Arc<Database>, message: &str) {
    let time_str = Local::now().format("%H:%M:%S").to_string();
    let formatted = format!("[{} (HKT)] {}", time_str, message);
    let mut l = logs.lock().await;
    l.push(formatted);
    if l.len() > MAX_LOG_LINES { l.remove(0); }
    drop(l);
    let full_time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    db.insert_log(&full_time, message);
}

const SCRIPT_LIST_USERS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$users = @()
try {
    $users = Get-LocalUser -ErrorAction Stop | Select-Object -ExpandProperty Name
} catch {
    try {
        $users = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch {
        try {
            $users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop | Select-Object -ExpandProperty Name
        } catch {
            $raw = & net user 2>$null
            if ($raw) {
                $inList = $false
                foreach ($line in $raw) {
                    if ($line -match '^-{5,}') { $inList = $true; continue }
                    if ($line -match '^The command|^命令成功|^命令已完成') { $inList = $false }
                    if ($inList -and $line.Trim()) { $line -split '\s+' | Where-Object { $_ } }
                }
            }
        }
    }
}
if ($users) { $users | ForEach-Object { $_ } }
"#;

async fn scan_and_intercept_threats(
    allowed_set: &Arc<RwLock<HashSet<String>>>, logs: &Arc<Mutex<Vec<String>>>, db: &Arc<Database>,
    threats_queue: &Arc<Mutex<Vec<PendingThreat>>>, last_scan: &Arc<RwLock<Option<Instant>>>,
) {
    if let Some(output) = ps_run(SCRIPT_LIST_USERS).await {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let allowed: HashSet<String> = allowed_set.read().await.clone();
        for line in stdout.lines() {
            let user_name = line.trim();
            if user_name.is_empty() || user_name.contains('\'') || user_name.contains('"') || user_name.contains('\\') { continue; }
            if user_name.starts_with("S-1-") || user_name.ends_with('$') { continue; }
            if !allowed.contains(&user_name.to_lowercase()) {
                let mut queue = threats_queue.lock().await;
                if !queue.iter().any(|t| matches!(&t.threat_type, ThreatType::UnknownAccount(n) if n == user_name)) {
                    let id = rand::random::<u64>();
                    queue.push(PendingThreat { id, threat_type: ThreatType::UnknownAccount(user_name.to_string()), detected_time: Local::now().format("%H:%M:%S").to_string(), description: format!("發現未授權的本機帳戶 [ {} ] 試圖在背景潛伏！", user_name) });
                    drop(queue);
                    add_log(logs, db, &format!("⚠️ [隔離區提示] 攔截不明帳戶: {}，等待網管決策。", user_name)).await;
                }
            }
        }
    }
    let shell_script = r#"Get-Process -Name sh,bash -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id):$($_.ProcessName)" }"#;
    if let Some(output) = ps_run(shell_script).await {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.trim().split(':').collect();
            if parts.len() < 2 { continue; }
            let pid = parts[0]; let proc_name = parts[1];
            let mut queue = threats_queue.lock().await;
            if !queue.iter().any(|t| matches!(&t.threat_type, ThreatType::SuspiciousShell(p) if p == pid)) {
                let id = rand::random::<u64>();
                queue.push(PendingThreat { id, threat_type: ThreatType::SuspiciousShell(pid.to_string()), detected_time: Local::now().format("%H:%M:%S").to_string(), description: format!("發現可疑的 Shell 進程 [ {}.exe ] (PID: {})，可能為 WSL/Cygwin/Git Bash。", proc_name, pid) });
                drop(queue);
                add_log(logs, db, &format!("⚠️ [隔離區提示] 攔截活動中的 Shell 行程 PID: {}，等待決策。", pid)).await;
            }
        }
    }
    *last_scan.write().await = Some(Instant::now());
}

async fn check_and_execute_auto_fire_ban(logs: &Arc<Mutex<Vec<String>>>, db: &Arc<Database>, last_check: &Arc<RwLock<Option<Instant>>>) {
    let window_secs = { let g = last_check.read().await; g.map(|t| t.elapsed().as_secs().max(60)).unwrap_or(300) };
    let script = format!(r#"
$ErrorActionPreference = 'SilentlyContinue'
$since = (Get-Date).AddSeconds(-{w})
try {{
    $events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625; StartTime=$since}} -MaxEvents 500 -ErrorAction Ignore
    if ($events) {{
        $events | ForEach-Object {{
            try {{ $x = [xml]$_.ToXml(); $x.Event.EventData.Data | Where-Object {{ $_.Name -eq 'IpAddress' }} | Select-Object -ExpandProperty '#text' }} catch {{ }}
        }}
    }}
}} catch {{ if ($_.Exception.GetType().Name -eq 'UnauthorizedAccessException') {{ Write-Output "PS_ERROR_ACCESS_DENIED" }} }}
"#, w = window_secs);

    let output = match ps_run(&script).await { Some(o) => o, None => return };
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    if stdout.contains("PS_ERROR_ACCESS_DENIED") {
        let mut l = logs.lock().await;
        if !l.iter().any(|x| x.contains("無法讀取 Security 日誌")) {
            let msg = "⚠️ [Auto Ban] 無法讀取 Security 日誌！請確認程式已「以系統管理員身分執行」。";
            l.push(format!("[{} (HKT)] {}", Local::now().format("%H:%M:%S"), msg));
            db.insert_log(&Local::now().format("%Y-%m-%d %H:%M:%S").to_string(), msg);
        }
        drop(l); *last_check.write().await = Some(Instant::now()); return;
    }

    let mut bad_ips: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let ip = line.trim();
        if ip.is_empty() || ip == "-" || ip == "::1" || ip == "127.0.0.1" { continue; }
        if is_private_ip(ip) { continue; }
        if !ip.contains('.') { continue; }
        bad_ips.push(ip.to_string());
    }
    *last_check.write().await = Some(Instant::now());

    for unique_ip in bad_ips.iter() {
        let count = bad_ips.iter().filter(|&x| x == unique_ip).count();
        if count < 3 { continue; }
        let rule_name = format!("AUTO_BAN_{}", unique_ip.replace('.', "_"));
        let check = ps_run(&format!("if (Get-NetFirewallRule -Name '{}' -ErrorAction SilentlyContinue) {{ 'EXISTS' }} else {{ 'MISSING' }}", rule_name)).await;
        let exists = check.map(|o| String::from_utf8_lossy(&o.stdout).contains("EXISTS")).unwrap_or(false);
        if exists { continue; }

        add_log(logs, db, &format!("🔥 [主動防禦] 偵測到惡意 IP {} 暴力破解達 {} 次！正在嘗試封鎖網段...", unique_ip, count)).await;
        let target_range = format!("{}.0/24", unique_ip.split('.').take(3).collect::<Vec<&str>>().join("."));
        let create_res = ps_run(&format!("New-NetFirewallRule -Name '{}' -DisplayName '{}' -Direction Inbound -RemoteAddress '{}' -Action Block", rule_name, rule_name, target_range)).await;

        if let Some(out) = create_res {
            if out.status.success() {
                add_log(logs, db, &format!("✅ [主動防禦] 成功封鎖 IP 網段: {}", target_range)).await;
                db.insert_banned_ip(unique_ip, &rule_name, &format!("暴力破解 (5分钟内失败 {} 次)", count));
            } else {
                add_log(logs, db, &format!("❌ [主動防禦] 封鎖失敗！請確認是否為管理員權限。")).await;
            }
        }
    }
}

async fn check_and_ban_anonymous_logon(logs: &Arc<Mutex<Vec<String>>>, db: &Arc<Database>, last_check: &Arc<RwLock<Option<Instant>>>) {
    let window_secs = { let g = last_check.read().await; g.map(|t| t.elapsed().as_secs().max(60)).unwrap_or(300) };
    let script = format!(r#"
$ErrorActionPreference = 'SilentlyContinue'
$since = (Get-Date).AddSeconds(-{w})
try {{
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624; StartTime=$since}} -MaxEvents 500 -ErrorAction Ignore |
    ForEach-Object {{
        try {{
            $x = [xml]$_.ToXml()
            $logonType = ($x.Event.EventData.Data | Where-Object {{ $_.Name -eq 'LogonType' }}).'#text'
            $targetUser = ($x.Event.EventData.Data | Where-Object {{ $_.Name -eq 'TargetUserName' }}).'#text'
            $ipAddress = ($x.Event.EventData.Data | Where-Object {{ $_.Name -eq 'IpAddress' }}).'#text'
            
            if ($logonType -eq '3' -and $targetUser -eq 'ANONYMOUS LOGON' -and $ipAddress -match '^\d+\.\d+\.\d+\.\d+$') {{
                $ipAddress
            }}
        }} catch {{ }}
    }}
}} catch {{ }}
"#, w = window_secs);

    let output = match ps_run(&script).await { Some(o) => o, None => return };
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let mut bad_ips: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let ip = line.trim();
        if !ip.is_empty() && ip != "-" && ip != "127.0.0.1" { 
            if !is_private_ip(ip) { bad_ips.push(ip.to_string()); }
        }
    }

    for unique_ip in bad_ips.iter() {
        let rule_name = format!("BAN_ANON_{}", unique_ip.replace('.', "_"));
        let check = ps_run(&format!("if (Get-NetFirewallRule -Name '{}' -ErrorAction SilentlyContinue) {{ 'EXISTS' }} else {{ 'MISSING' }}", rule_name)).await;
        let exists = check.map(|o| String::from_utf8_lossy(&o.stdout).contains("EXISTS")).unwrap_or(false);
        if exists { continue; }

        add_log(logs, db, &format!("🚫 [主動防禦] 偵測到匿名登入探測 IP {}！直接封鎖。", unique_ip)).await;
        let target_range = format!("{}.0/24", unique_ip.split('.').take(3).collect::<Vec<&str>>().join("."));
        let _ = ps_run(&format!("New-NetFirewallRule -Name '{}' -DisplayName '{}' -Direction Inbound -RemoteAddress '{}' -Action Block", rule_name, rule_name, target_range)).await;
        db.insert_banned_ip(unique_ip, &rule_name, "匿名登入探測 (4624)");
    }
}

fn fetch_all_current_system_users() -> String {
    if let Some(o) = ps_run_sync(SCRIPT_LIST_USERS) {
        let stdout = String::from_utf8_lossy(&o.stdout);
        let mut list = Vec::new();
        for line in stdout.lines() {
            let n = line.trim();
            if !n.is_empty() && !n.contains(',') { list.push(n.to_string()); }
        }
        if !list.is_empty() { return list.join(", "); }
    }
    String::new()
}

fn check_current_autostart_status() -> bool {
    let o = std::process::Command::new("reg").creation_flags(CREATE_NO_WINDOW)
        .args(&["query", r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "ServerGuardian"]).output();
    match o {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                if line.contains("ServerGuardian") && line.contains("REG_SZ") {
                    let val = line.split("REG_SZ").nth(1).map(|v| v.trim().trim_matches('"')).unwrap_or("");
                    if let Ok(exe) = std::env::current_exe() { return val.eq_ignore_ascii_case(&exe.to_string_lossy()); }
                    return !val.is_empty();
                }
            }
            false
        }
        _ => false,
    }
}

fn set_windows_autostart(enable: bool) -> bool {
    let key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run";
    if enable {
        let exe = match std::env::current_exe() { Ok(e) => e, Err(_) => return false };
        std::process::Command::new("reg").creation_flags(CREATE_NO_WINDOW)
            .args(&["add", key, "/v", "ServerGuardian", "/t", "REG_SZ", "/d", &exe.to_string_lossy(), "/f"])
            .status().map(|s| s.success()).unwrap_or(false)
    } else {
        std::process::Command::new("reg").creation_flags(CREATE_NO_WINDOW)
            .args(&["delete", key, "/v", "ServerGuardian", "/f"])
            .status().map(|s| s.success()).unwrap_or(false)
    }
}

async fn apply_strict_firewall_wall(enable: bool) -> bool {
    let addr = if enable { "'192.168.0.0/16', '210.3.33.0/24', '221.127.18.0/24'" } else { "'Any'" };
    ps_run(&format!("Set-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP' -RemoteAddress {}", addr)).await.map(|o| o.status.success()).unwrap_or(false)
}

fn save_config_file(config: &AppConfig) {
    if let Ok(mut file) = File::create(CONFIG_FILE) {
        if let Ok(json) = serde_json::to_string_pretty(config) { let _ = file.write_all(json.as_bytes()); }
    }
}

fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let font_paths = [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\msjh.ttc", r"C:\Windows\Fonts\simsun.ttc"];
    for path in font_paths {
        if let Ok(font_data) = std::fs::read(path) {
            fonts.font_data.insert("windows_chinese".to_owned(), egui::FontData::from_owned(font_data));
            fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap().insert(0, "windows_chinese".to_owned());
            fonts.families.get_mut(&egui::FontFamily::Monospace).unwrap().insert(0, "windows_chinese".to_owned());
            break;
        }
    }
    ctx.set_fonts(fonts);
}

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    log_to_file("=== 程序启动 ===");
    std::panic::set_hook(Box::new(|info| { log_to_file(&format!("❌ 發生致命崩潰 (Panic): {:?}", info)); }));

    if is_server_core() { std::process::exit(1); }

    let db = Arc::new(Database::new());
    
    let db_web = Arc::clone(&db);
    let web_port = start_web_server(db_web).await;

    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: egui::ViewportBuilder::default().with_inner_size([850.0, 600.0]).with_resizable(true),
        ..Default::default()
    };

    let db_app = Arc::clone(&db);
    let result = eframe::run_native(
        "Windows Server 安全哨兵控制器",
        options,
        Box::new(move |cc| {
            setup_custom_fonts(&cc.egui_ctx);
            Box::new(GuardianApp::new(db_app, web_port))
        }),
    );

    result
}

impl GuardianApp {
    fn new(db: Arc<Database>, web_port: u16) -> Self {
        let elevated = is_elevated();
        let os_info = detect_os_caption();
        let initial_autostart = check_current_autostart_status();
        
        let db_clone = Arc::clone(&db);
        tokio::spawn(async move { db_clone.clean_old_data(); });

        let mut config = match File::open(CONFIG_FILE) {
            Ok(mut file) => { let mut content = String::new(); if file.read_to_string(&mut content).is_ok() { serde_json::from_str(&content).unwrap_or_else(|_| AppConfig::default()) } else { AppConfig::default() } }
            Err(_) => AppConfig::default(),
        };

        if !config.first_run_done {
            let users = fetch_all_current_system_users();
            config.allowed_users_raw = users;
            config.first_run_done = true;
            save_config_file(&config);
        }

        let allowed_set = parse_users_to_set(&config.allowed_users_raw);
        let initial_strict = config.strict_net_wall;

        let mut initial_logs: Vec<String> = vec![
            "[🛡️ 系統] 內網純淨防護盾初始化就緒。".to_string(),
            format!("[🖥️ 環境] 作業系統: {}", os_info),
            format!("[🖥️ 環境] PowerShell: {}", powershell_exe().to_string_lossy()),
            format!("[👥 白名單] 已載入 {} 個授權帳戶", allowed_set.len()),
            format!("[🌐 Web] 已啟動網頁端監控，請用瀏覽器訪問 http://本機IP:{}", web_port),
        ];
        if elevated { initial_logs.push("[✅ 權限] 以系統管理員身分執行，全部功能可用。".to_string()); }
        else { initial_logs.push("[⚠️ 權限] 未以系統管理員身分執行！部分功能將失效。".to_string()); }

        let logs = Arc::new(Mutex::new(initial_logs));

        if initial_strict && elevated {
            let logs_bg = Arc::clone(&logs);
            let db_bg = Arc::clone(&db);
            tokio::spawn(async move {
                if apply_strict_firewall_wall(true).await { add_log(&logs_bg, &db_bg, "⚙️ [啟動恢復] 已重新套用持久化的 RDP 限縮策略").await; }
            });
        }

        Self {
            config, db, allowed_users_live: Arc::new(RwLock::new(allowed_set)),
            is_monitoring: false, active_tab: ActiveTab::Live, autostart_enabled: initial_autostart,
            shutdown_trigger: Arc::new(AtomicBool::new(false)), monitor_handle: None,
            logs, pending_threats: Arc::new(Mutex::new(Vec::new())),
            last_scan_at: Arc::new(RwLock::new(None)), 
            last_4625_check: Arc::new(RwLock::new(None)), 
            last_4624_check: Arc::new(RwLock::new(None)),
            elevated,
            history_date: Local::now().date_naive(), history_search: String::new(),
            history_logs: Vec::new(), history_bans: Vec::new(),
            web_port,
            backup_files: Vec::new(),
            selected_backup: None,
            is_sandbox: false,
        }
    }
}

impl eframe::App for GuardianApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let old_tab = self.active_tab;
                ui.selectable_value(&mut self.active_tab, ActiveTab::Live, "🟢 即時監控");
                ui.selectable_value(&mut self.active_tab, ActiveTab::History, "📅 歷史紀錄");
                ui.selectable_value(&mut self.active_tab, ActiveTab::Settings, "⚙️ 核心設定");
                
                if old_tab != ActiveTab::History && self.active_tab == ActiveTab::History {
                    self.refresh_history();
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !self.elevated {
                        ui.colored_label(egui::Color32::from_rgb(255, 180, 0), "⚠ 非管理員模式");
                    }
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new(format!("🌐 Web 端口: {}", self.web_port)).color(egui::Color32::LIGHT_BLUE));
                });
            });
        });

        match self.active_tab {
            ActiveTab::Live => self.render_live_ui(ctx),
            ActiveTab::History => self.render_history_ui(ctx),
            ActiveTab::Settings => self.render_settings_ui(ctx),
        }

        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

impl GuardianApp {
    fn render_live_ui(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("quarantine_panel").width_range(280.0..=280.0).show(ctx, |ui| {
            let threat_count = self.pending_threats.try_lock().map(|q| q.len()).unwrap_or(0);
            ui.heading(format!("☣️ 威脅隔離區 ({})", threat_count));
            ui.separator();
            let mut threats = Vec::new();
            if let Ok(q) = self.pending_threats.try_lock() { threats = q.clone(); }

            if threats.is_empty() {
                ui.add_space(20.0);
                ui.colored_label(egui::Color32::GREEN, "🟢 系統目前安全無虞，未發現未知威脅");
            } else {
                egui::ScrollArea::vertical().max_height(450.0).show(ui, |ui| {
                    for threat in threats.iter() {
                        ui.group(|ui| {
                            ui.colored_label(egui::Color32::LIGHT_RED, format!("⏱️ 偵測時間: {}", threat.detected_time));
                            ui.label(egui::RichText::new(&threat.description).size(12.0));
                            ui.add_space(5.0);
                            ui.horizontal(|ui| {
                                if ui.small_button(egui::RichText::new("放行").color(egui::Color32::GREEN)).clicked() {
                                    if let ThreatType::UnknownAccount(name) = &threat.threat_type {
                                        if self.config.allowed_users_raw.is_empty() { self.config.allowed_users_raw = name.clone(); }
                                        else { self.config.allowed_users_raw.push_str(&format!(", {}", name)); }
                                        if let Ok(mut w) = self.allowed_users_live.try_write() { w.insert(name.to_lowercase()); }
                                    }
                                    let new_config = self.config.clone();
                                    let q = Arc::clone(&self.pending_threats);
                                    let l = Arc::clone(&self.logs);
                                    let d = Arc::clone(&self.db);
                                    let t = threat.clone();
                                    tokio::spawn(async move {
                                        { let mut qq = q.lock().await; qq.retain(|x| x.id != t.id); }
                                        match &t.threat_type {
                                            ThreatType::UnknownAccount(name) => { save_config_file(&new_config); add_log(&l, &d, &format!("🟢 [放行] 信任帳戶: {}", name)).await; }
                                            ThreatType::SuspiciousShell(pid) => { add_log(&l, &d, &format!("🟢 [放行] 允許 PID: {}", pid)).await; }
                                        }
                                    });
                                }
                                if ui.small_button(egui::RichText::new("封殺").color(egui::Color32::LIGHT_RED)).clicked() {
                                    let q = Arc::clone(&self.pending_threats);
                                    let l = Arc::clone(&self.logs);
                                    let d = Arc::clone(&self.db);
                                    let t = threat.clone();
                                    tokio::spawn(async move {
                                        { let mut qq = q.lock().await; qq.retain(|x| x.id != t.id); }
                                        match &t.threat_type {
                                            ThreatType::UnknownAccount(name) => {
                                                let script = format!(r#"$name = '{name}'; $ok = $false; try {{ Disable-LocalUser -Name $name -ErrorAction Stop; Remove-LocalUser -Name $name -ErrorAction Stop; $ok = $true }} catch {{ & net user $name /delete 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) {{ $ok = $true }} }}; if ($ok) {{ 'OK' }} else {{ 'FAIL' }}"#, name = name);
                                                let out = ps_run(&script).await;
                                                let ok = out.map(|o| String::from_utf8_lossy(&o.stdout).contains("OK")).unwrap_or(false);
                                                if ok { add_log(&l, &d, &format!("🔥 [強殺] 已抹除帳戶: {}", name)).await; }
                                                else { add_log(&l, &d, &format!("❌ [強殺失敗] 無法移除: {}", name)).await; }
                                            }
                                            ThreatType::SuspiciousShell(pid) => {
                                                add_log(&l, &d, &format!("🔥 [強殺] 已結束進程 PID: {}", pid)).await;
                                                let _ = Command::new("taskkill").creation_flags(CREATE_NO_WINDOW).args(&["/F", "/PID", pid]).status().await;
                                            }
                                        }
                                    });
                                }
                            });
                        });
                        ui.add_space(5.0);
                    }
                });
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("目前的防毒守護狀態：");
                if self.is_monitoring {
                    ui.colored_label(egui::Color32::GREEN, "● 內網純淨防護盾全天候巡邏中");
                    if let Ok(last) = self.last_scan_at.try_read() {
                        if let Some(t) = *last {
                            let secs = t.elapsed().as_secs();
                            ui.colored_label(if secs < 15 { egui::Color32::GREEN } else { egui::Color32::YELLOW }, format!("(上次掃描 {}s 前)", secs));
                        }
                    }
                } else {
                    ui.colored_label(egui::Color32::LIGHT_RED, "● 暫停防禦中");
                }
            });
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if !self.is_monitoring {
                    if ui.button(egui::RichText::new("🟢 啟動防毒攔截防禦").size(14.0)).clicked() {
                        self.is_monitoring = true;
                        self.shutdown_trigger.store(false, Ordering::SeqCst);
                        let ban_enabled = self.config.auto_fire_ban;
                        let logs_clone = Arc::clone(&self.logs);
                        let db_clone = Arc::clone(&self.db);
                        let shutdown_clone = Arc::clone(&self.shutdown_trigger);
                        let threats_clone = Arc::clone(&self.pending_threats);
                        let allowed_live = Arc::clone(&self.allowed_users_live);
                        let last_scan = Arc::clone(&self.last_scan_at);
                        let last_4625 = Arc::clone(&self.last_4625_check);
                        let last_4624 = Arc::clone(&self.last_4624_check);
                        self.monitor_handle = Some(tokio::spawn(async move {
                            while !shutdown_clone.load(Ordering::SeqCst) {
                                scan_and_intercept_threats(&allowed_live, &logs_clone, &db_clone, &threats_clone, &last_scan).await;
                                if ban_enabled { 
                                    check_and_execute_auto_fire_ban(&logs_clone, &db_clone, &last_4625).await; 
                                    check_and_ban_anonymous_logon(&logs_clone, &db_clone, &last_4624).await;
                                }
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }));
                    }
                } else if ui.button(egui::RichText::new("🛑 停止防禦").size(14.0)).clicked() {
                    self.is_monitoring = false;
                    self.shutdown_trigger.store(true, Ordering::SeqCst);
                    if let Some(h) = self.monitor_handle.take() { h.abort(); }
                }
            });

            ui.add_space(15.0);
            ui.label("📝 即時網管防毒事件日誌:");
            egui::Frame::default().fill(egui::Color32::from_rgb(25, 25, 25)).inner_margin(8.0).show(ui, |ui| {
                egui::ScrollArea::vertical().max_height(320.0).stick_to_bottom(true).show(ui, |ui| {
                    if let Ok(logs) = self.logs.try_lock() {
                        for log in logs.iter() {
                            let color = if log.contains("🚨") || log.contains("❌") || log.contains("🔥") || log.contains("⚠️") || log.contains("⚠") || log.contains("🚫") { egui::Color32::LIGHT_RED }
                                else if log.contains("✅") || log.contains("🟢") || log.contains("🛑") || log.contains("⚙️") { egui::Color32::GREEN }
                                else { egui::Color32::LIGHT_GRAY };
                            ui.colored_label(color, log);
                        }
                    }
                });
            });
        });
    }

    fn render_history_ui(&mut self, ctx: &egui::Context) {
        self.backup_files.clear();
        if let Ok(entries) = std::fs::read_dir(BACKUP_DIR) {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if name.ends_with(".db") { self.backup_files.push(name); }
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.is_sandbox {
                ui.colored_label(egui::Color32::YELLOW, "⚠️ 您目前正在【沙箱模式】查看歷史歸檔資料（唯讀，不影響主系統）。");
                if ui.button("🔙 返回主系統歷史紀錄").clicked() {
                    self.is_sandbox = false;
                    self.selected_backup = None;
                    self.refresh_history();
                }
                ui.separator();
            }

            ui.horizontal(|ui| {
                ui.label("📅 選擇日期:");
                if ui.add(DatePickerButton::new(&mut self.history_date)).changed() && !self.is_sandbox {
                    self.refresh_history();
                }
                ui.add_space(20.0);
                ui.label("🔍 搜尋:");
                if ui.text_edit_singleline(&mut self.history_search).changed() && !self.is_sandbox {
                    self.refresh_history();
                }
                
                ui.add_space(10.0);
                ui.label("📂 查看備份:");
                let selected_text = self.selected_backup.clone().unwrap_or_else(|| "當前主庫 (Live)".to_string());
                
                let files_clone = self.backup_files.clone();
                
                egui::ComboBox::from_id_source("backup_combo")
                    .selected_text(selected_text)
                    .show_ui(ui, |ui| {
                        if ui.selectable_value(&mut self.selected_backup, None, "當前主庫 (Live)").clicked() {
                            self.is_sandbox = false;
                            self.refresh_history();
                        }
                        for file in &files_clone {
                            if ui.selectable_value(&mut self.selected_backup, Some(file.clone()), file).clicked() {
                                self.is_sandbox = true;
                                self.load_sandbox_data(file);
                            }
                        }
                    });

                if !self.is_sandbox && ui.button("🔄 重新整理").clicked() {
                    self.refresh_history();
                }
                if ui.button("📤 匯出 CSV").clicked() {
                    self.export_csv();
                }
            });
            ui.separator();

            let date_str = self.history_date.format("%Y-%m-%d").to_string();
            ui.heading(format!("📆 {} 的紀錄", if self.is_sandbox { "沙箱歸檔" } else { &date_str }));
            
            ui.add_space(10.0);

            // 1. 封禁 IP 紀錄 (改用極度穩定的 Grid 佈局)
            ui.label("🔥 封禁 IP 紀錄:");
            if self.history_bans.is_empty() {
                ui.colored_label(egui::Color32::GRAY, "當日無封禁紀錄。");
            } else {
                egui::ScrollArea::vertical().id_source("bans_scroll").max_height(200.0).show(ui, |ui| {
                    egui::Grid::new("bans_grid").striped(true).min_col_width(100.0).show(ui, |ui| {
                        ui.strong("IP 位址");
                        ui.strong("防火牆規則");
                        ui.strong("封禁時間");
                        ui.strong("原因");
                        ui.end_row();

                        for ban in &self.history_bans {
                            ui.colored_label(egui::Color32::LIGHT_RED, &ban.0);
                            ui.label(&ban.1);
                            ui.label(&ban.2);
                            ui.label(&ban.3);
                            ui.end_row();
                        }
                    });
                });
            }

            ui.add_space(20.0);

            // 2. 系統事件日誌 (改用極度穩定的 Grid 佈局)
            ui.label("📝 系統事件日誌:");
            if self.history_logs.is_empty() {
                ui.colored_label(egui::Color32::GRAY, "當日無系統事件。");
            } else {
                egui::ScrollArea::vertical().id_source("logs_scroll").max_height(200.0).show(ui, |ui| {
                    egui::Grid::new("logs_grid").striped(true).min_col_width(100.0).show(ui, |ui| {
                        ui.strong("時間");
                        ui.strong("事件內容");
                        ui.end_row();

                        for log in &self.history_logs {
                            ui.label(&log.0);
                            ui.label(&log.1);
                            ui.end_row();
                        }
                    });
                });
            }
        });
    }

    fn refresh_history(&mut self) {
        if self.is_sandbox { return; }
        let date_str = self.history_date.format("%Y-%m-%d").to_string();
        self.history_logs = self.db.get_logs_by_date(&date_str, &self.history_search);
        self.history_bans = self.db.get_bans_by_date(&date_str, &self.history_search);
    }

    fn load_sandbox_data(&mut self, filename: &str) {
        let full_path = format!("{}/{}", BACKUP_DIR, filename);
        let conn = match Connection::open_with_flags(&full_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(c) => c,
            Err(e) => {
                log_to_file(&format!("❌ 無法打開沙箱檔案 {}: {}", full_path, e));
                return;
            }
        };

        self.history_logs.clear();
        self.history_bans.clear();

        {
            let mut stmt_logs = match conn.prepare("SELECT timestamp, message FROM logs ORDER BY id DESC LIMIT 1000") {
                Ok(s) => s,
                Err(_) => return,
            };
            let rows_result = stmt_logs.query_map([], |row| Ok((row.get(0)?, row.get(1)?)));
            if let Ok(rows) = rows_result {
                self.history_logs = rows.filter_map(Result::ok).collect();
            }
        }

        {
            let mut stmt_bans = match conn.prepare("SELECT ip, rule_name, banned_at, reason FROM banned_ips ORDER BY id DESC LIMIT 1000") {
                Ok(s) => s,
                Err(_) => return,
            };
            let rows_result = stmt_bans.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)));
            if let Ok(rows) = rows_result {
                self.history_bans = rows.filter_map(Result::ok).collect();
            }
        }
    }

    fn export_csv(&self) {
        let date_str = self.history_date.format("%Y-%m-%d").to_string();
        let filename = format!("report_{}.csv", date_str);
        if let Ok(mut file) = File::create(&filename) {
            let _ = writeln!(file, "Type,Time,IP/Message,Rule,Reason");
            for b in &self.history_bans {
                let _ = writeln!(file, "Banned_IP,{},{},{},{}", b.2, b.0, b.1, b.3);
            }
            for l in &self.history_logs {
                let _ = writeln!(file, "Log,{},{}", l.0, l.1.replace(',', " "));
            }
            println!("已导出: {}", filename);
        }
    }

    fn render_settings_ui(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("👤 安全帳戶白名單參數");
                let mut changed = false;
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("多個帳戶請用英文逗號隔開").small());
                    ui.add_space(20.0);
                    if ui.button("🔄 Clean & Reload").clicked() {
                        let users = fetch_all_current_system_users();
                        self.config.allowed_users_raw = users.clone();
                        if let Ok(mut w) = self.allowed_users_live.try_write() { *w = parse_users_to_set(&users); }
                        changed = true;
                    }
                });
                if ui.add(egui::TextEdit::multiline(&mut self.config.allowed_users_raw).desired_width(f32::INFINITY).desired_rows(6)).changed() {
                    if let Ok(mut w) = self.allowed_users_live.try_write() { *w = parse_users_to_set(&self.config.allowed_users_raw); }
                    changed = true;
                }

                ui.separator();
                ui.heading("🧱 主動式防火牆與策略控制");

                if ui.checkbox(&mut self.config.auto_fire_ban, "🔥 開啟智慧型 IP 自動強殺封鎖 (Auto Fire Ban)").changed() { changed = true; }

                if ui.checkbox(&mut self.config.strict_net_wall, "🛡️ RDP 限制僅允許內網與公司雙網段連入").changed() {
                    changed = true;
                    let target_state = self.config.strict_net_wall;
                    let logs_clone = Arc::clone(&self.logs);
                    let db_clone = Arc::clone(&self.db);
                    tokio::spawn(async move {
                        if apply_strict_firewall_wall(target_state).await { add_log(&logs_clone, &db_clone, "⚙️ [防火牆] RDP 策略已切換").await; }
                        else { add_log(&logs_clone, &db_clone, "❌ [防火牆] 策略套用失敗").await; }
                    });
                }

                if ui.checkbox(&mut self.autostart_enabled, "隨機啟動 (開機桌面載入時自動執行監控)").changed() {
                    let target = self.autostart_enabled;
                    if !set_windows_autostart(target) {
                        self.autostart_enabled = !target;
                        let logs_clone = Arc::clone(&self.logs);
                        let db_clone = Arc::clone(&self.db);
                        tokio::spawn(async move { add_log(&logs_clone, &db_clone, "❌ [設定] 自啟動設定失敗").await; });
                    }
                }

                if changed { 
                    save_config_file(&self.config); 
                }
            });
        });
    }
}
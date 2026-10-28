use rusqlite::{Connection, Result, params};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new() -> Self {
        let conn = Connection::open("server_guardian.db").expect("无法打开数据库");
        
        // 开启 WAL 模式，提升并发读写性能，并防止程序崩溃时损坏数据
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;"
        ).expect("无法设置 WAL 模式");

        // 初始化表结构
        conn.execute_batch(
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
        ).expect("无法初始化数据库表");

        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    // 插入日志
    pub fn insert_log(&self, timestamp: &str, message: &str) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO logs (timestamp, message) VALUES (?1, ?2)",
            params![timestamp, message],
        );
    }

    // 插入封禁记录
    pub fn insert_banned_ip(&self, ip: &str, rule_name: &str, reason: &str) {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = conn.execute(
            "INSERT OR IGNORE INTO banned_ips (ip, rule_name, banned_at, reason) VALUES (?1, ?2, ?3, ?4)",
            params![ip, rule_name, now, reason],
        );
    }

    // 清理 30 天前的旧日志，防止数据库无限膨胀
    pub fn clean_old_data(&self) {
        let conn = self.conn.lock().unwrap();
        let thirty_days_ago = (chrono::Local::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = conn.execute("DELETE FROM logs WHERE timestamp < ?1", params![thirty_days_ago]);
        let _ = conn.execute("DELETE FROM banned_ips WHERE banned_at < ?1", params![thirty_days_ago]);
    }

        // 查询指定日期的日志 (例如 "2023-10-27")
    fn get_logs_by_date(&self, date: &str) -> Vec<(String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT timestamp, message FROM logs WHERE timestamp LIKE ?1 ORDER BY id DESC LIMIT 500"
        ).unwrap();
        let date_like = format!("{}%", date);
        let rows = stmt.query_map(params![date_like], |row| {
            Ok((row.get(0)?, row.get(1)?))
        }).unwrap();
        rows.filter_map(Result::ok).collect()
    }

    // 查询指定日期的封禁记录
    fn get_bans_by_date(&self, date: &str) -> Vec<(String, String, String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, rule_name, banned_at, reason FROM banned_ips WHERE banned_at LIKE ?1 ORDER BY id DESC"
        ).unwrap();
        let date_like = format!("{}%", date);
        let rows = stmt.query_map(params![date_like], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        }).unwrap();
        rows.filter_map(Result::ok).collect()
    }
}

import sqlite3
import os
from datetime import datetime
from selectinf import get_logger

logger = get_logger("output.sqlite_manager")

DB_PATH = os.path.join("output", "selectinf.db")


def get_db():
    """获取 SQLite 数据库连接"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库表结构"""
    conn = get_db()
    cursor = conn.cursor()

    # 任务表：每次运行创建一条任务记录
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS task (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_domain TEXT NOT NULL,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            status TEXT DEFAULT 'running',
            total_subdomains INTEGER DEFAULT 0,
            note TEXT
        )
    """)

    # 模块扫描结果表：记录各工具的原始输出
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS module_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            module_name TEXT NOT NULL,
            output_file TEXT,
            raw_output TEXT,
            domain_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'success',
            error_msg TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES task (id)
        )
    """)

    # 最终去重后的域名结果表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS final_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            source_module TEXT,
            ip TEXT,
            port INTEGER,
            url TEXT,
            title TEXT,
            status_code INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES task (id)
        )
    """)

    # JSFinder 发现的子域名表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS jsfinder_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            parent_url TEXT,
            discovered_domain TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES task (id)
        )
    """)

    # 为已存在的 task 表添加新字段（兼容重复初始化）
    try:
        cursor.execute("ALTER TABLE task ADD COLUMN total_fingerprints INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 字段已存在
    try:
        cursor.execute("ALTER TABLE task ADD COLUMN total_vulns INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 字段已存在

    # 资产表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            resolved_ip TEXT,
            source_module TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(task_id, domain, source_module)
        )
    """)

    # 指纹表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            ip TEXT,
            port INTEGER DEFAULT 443,
            status_code INTEGER,
            title TEXT,
            content_type TEXT,
            server_header TEXT,
            tech_stack TEXT,
            waf_detected TEXT,
            response_time_ms INTEGER,
            first_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            fingerprint_id_fingerprint TEXT,
            UNIQUE(task_id, url, port)
        )
    """)

    # 漏洞表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            vuln_id TEXT NOT NULL,
            url TEXT NOT NULL,
            template TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL,
            description TEXT,
            matched_at TEXT,
            extracted_results TEXT,
            nuclei_output_json TEXT,
            ai_validated INTEGER DEFAULT NULL,
            ai_confidence REAL DEFAULT NULL,
            first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(task_id, vuln_id, url, template)
        )
    """)

    # AI 分析表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            analysis_type TEXT NOT NULL,
            input_data TEXT,
            model_used TEXT,
            prompt_tokens INTEGER,
            completion_tokens INTEGER,
            result_text TEXT,
            cost_usd REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES task (id)
        )
    """)

    # 索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_task ON assets(task_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fingerprints_task ON fingerprints(task_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_task_severity ON vulnerabilities(task_id, severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_analysis_task ON ai_analysis(task_id)")

    conn.commit()
    conn.close()
    logger.info("SQLite 数据库初始化完成: %s", DB_PATH)


def create_task(target_domain: str) -> int:
    """创建新任务，返回 task_id"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO task (target_domain, status) VALUES (?, ?)",
        (target_domain, "running")
    )
    task_id = cursor.lastrowid
    conn.commit()
    conn.close()
    logger.info("[SQLite] 任务创建: id=%d, domain=%s", task_id, target_domain)
    return task_id


def finish_task(task_id: int, total_subdomains: int = 0, total_fingerprints: int = 0, total_vulns: int = 0, note: str = ""):
    """标记任务完成"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE task SET end_time = CURRENT_TIMESTAMP, status = 'completed', total_subdomains = ?, total_fingerprints = ?, total_vulns = ?, note = ? WHERE id = ?",
        (total_subdomains, total_fingerprints, total_vulns, note, task_id)
    )
    conn.commit()
    conn.close()
    logger.info("[SQLite] 任务完成: id=%d, 子域名总数=%d, 指纹总数=%d, 漏洞总数=%d", task_id, total_subdomains, total_fingerprints, total_vulns)


def save_module_result(task_id: int, module_name: str, output_file: str = None,
                       raw_output: str = None, domain_count: int = 0,
                       status: str = "success", error_msg: str = None):
    """保存模块扫描结果"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO module_results
           (task_id, module_name, output_file, raw_output, domain_count, status, error_msg)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (task_id, module_name, output_file, raw_output, domain_count, status, error_msg)
    )
    conn.commit()
    conn.close()
    logger.info("[SQLite] %s 结果已入库: task_id=%d, 域名数=%d", module_name, task_id, domain_count)


def save_final_domain(task_id: int, domain: str, source_module: str = "",
                      ip: str = None, port: int = None, url: str = None,
                      title: str = None, status_code: int = None):
    """保存最终去重后的域名"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO final_results
           (task_id, domain, source_module, ip, port, url, title, status_code)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (task_id, domain, source_module, ip, port, url, title, status_code)
    )
    conn.commit()
    conn.close()


def save_jsfinder_result(task_id: int, parent_url: str, discovered_domain: str):
    """保存 JSFinder 发现的子域名"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO jsfinder_results (task_id, parent_url, discovered_domain) VALUES (?, ?, ?)",
        (task_id, parent_url, discovered_domain)
    )
    conn.commit()
    conn.close()


def get_task_summary(task_id: int) -> dict:
    """获取任务统计摘要"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM task WHERE id = ?", (task_id,))
    task = cursor.fetchone()

    cursor.execute("SELECT module_name, domain_count FROM module_results WHERE task_id = ?", (task_id,))
    modules = cursor.fetchall()

    cursor.execute("SELECT COUNT(DISTINCT domain) FROM final_results WHERE task_id = ?", (task_id,))
    total_domains = cursor.fetchone()[0]

    conn.close()

    return {
        "task_id": task_id,
        "target_domain": task["target_domain"] if task else "",
        "modules": {row["module_name"]: row["domain_count"] for row in modules},
        "total_unique_domains": total_domains
    }


def save_asset(task_id: int, domain: str, resolved_ip: str = None, source_module: str = ""):
    """保存资产"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO assets (task_id, domain, resolved_ip, source_module) VALUES (?, ?, ?, ?)",
        (task_id, domain, resolved_ip, source_module)
    )
    conn.commit()
    conn.close()


def save_fingerprint(task_id: int, url: str, ip: str = None, port: int = 443,
                     status_code: int = None, title: str = None, content_type: str = None,
                     server_header: str = None, tech_stack: str = None, waf_detected: str = None,
                     response_time_ms: int = None, fingerprint_id: str = None):
    """保存指纹"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR IGNORE INTO fingerprints
           (task_id, url, ip, port, status_code, title, content_type, server_header,
            tech_stack, waf_detected, response_time_ms, fingerprint_id_fingerprint)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (task_id, url, ip, port, status_code, title, content_type, server_header,
         tech_stack, waf_detected, response_time_ms, fingerprint_id)
    )
    conn.commit()
    conn.close()


def save_vulnerability(task_id: int, vuln_id: str, url: str, template: str,
                        severity: str, cvss_score: float = None, description: str = None,
                        matched_at: str = None, extracted_results: str = None,
                        nuclei_output_json: str = None):
    """保存漏洞"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR IGNORE INTO vulnerabilities
           (task_id, vuln_id, url, template, severity, cvss_score, description,
            matched_at, extracted_results, nuclei_output_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (task_id, vuln_id, url, template, severity, cvss_score, description,
         matched_at, extracted_results, nuclei_output_json)
    )
    conn.commit()
    conn.close()


def save_ai_analysis(task_id: int, analysis_type: str, input_data: str = None,
                      model_used: str = None, prompt_tokens: int = None,
                      completion_tokens: int = None, result_text: str = None,
                      cost_usd: float = 0.0):
    """保存 AI 分析结果"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO ai_analysis
           (task_id, analysis_type, input_data, model_used, prompt_tokens,
            completion_tokens, result_text, cost_usd)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (task_id, analysis_type, input_data, model_used, prompt_tokens,
         completion_tokens, result_text, cost_usd)
    )
    conn.commit()
    conn.close()


def get_assets(task_id: int) -> list:
    """获取资产列表"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE task_id = ?", (task_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_fingerprints(task_id: int) -> list:
    """获取指纹列表"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM fingerprints WHERE task_id = ?", (task_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def count_fingerprints(task_id: int) -> int:
    """获取任务指纹数量"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM fingerprints WHERE task_id = ?", (task_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def count_vulnerabilities(task_id: int) -> int:
    """获取任务漏洞数量"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE task_id = ?", (task_id,))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_vulnerabilities(task_id: int, severity: str = None) -> list:
    """获取漏洞列表"""
    conn = get_db()
    cursor = conn.cursor()
    if severity:
        cursor.execute("SELECT * FROM vulnerabilities WHERE task_id = ? AND severity = ?",
                       (task_id, severity))
    else:
        cursor.execute("SELECT * FROM vulnerabilities WHERE task_id = ?", (task_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

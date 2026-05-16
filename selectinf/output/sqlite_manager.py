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


def finish_task(task_id: int, total_subdomains: int = 0, note: str = ""):
    """标记任务完成"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE task SET end_time = CURRENT_TIMESTAMP, status = 'completed', total_subdomains = ?, note = ? WHERE id = ?",
        (total_subdomains, note, task_id)
    )
    conn.commit()
    conn.close()
    logger.info("[SQLite] 任务完成: id=%d, 子域名总数=%d", task_id, total_subdomains)


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

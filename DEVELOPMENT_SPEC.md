# selectinf 安全扫描框架开发规范文档

**版本:** 2.0  
**日期:** 2026-05-16  
**目标:** 从资产收集 → 指纹识别 → 漏洞扫描 → AI 分析 四阶段流水线

---

## 1. 系统概述

### 1.1 架构目标

- **流水线化:** 将资产收集、指纹识别、漏洞扫描、AI 分析串联为四阶段管道，每阶段产出结构化数据供下一阶段消费
- **可扩展性:** 通过插件化工具接口，允许新增工具无需修改核心编排逻辑
- **容错优先:** 单一工具失败不影响整体流程，结果通过 SQLite 持久化
- **Windows 兼容:** 所有子进程调用、路径操作、并发策略均针对 Windows 10/11 验证

### 1.2 设计原则

| 原则 | 说明 |
|------|------|
| Strangler Pattern | 保留现有 `run.py` 行为不动，新建 `selectinf/pipeline/` 逐步接管 |
| 文件→数据库双层存储 | 中间结果以 `.txt`/`.json` 落盘方便调试，最终结果入库保证一致性 |
| 幂等执行 | 同一任务重复执行不产生脏数据，通过 `task_id` + `status` 去重 |
| 最小依赖引入 | 仅新增 PyYAML（配置）和 httpx（HTTP 指纹），不引入重量级框架 |

### 1.3 技术栈

```
Python 3.10+ (需保持 3.8 兼容)
SQLite 3 (中间状态 + 最终结果)
PyYAML (pipeline_config.yaml)
concurrent.futures (并行编排)
httpx (HTTP 指纹探测 — 新增)
nuclei (漏洞扫描 — 新增)
OpenAI API / Ollama (AI 分析 — 新增)
```

### 1.4 四阶段流水线

```
┌───────────────┐   ┌──────────────┐   ┌────────────────┐   ┌──────────────┐
│  Stage 1      │   │  Stage 2     │   │  Stage 3       │   │  Stage 4     │
│  Asset        │──▶│  Fingerprint │──▶│  Vuln Scan     │──▶│  AI Analysis │
│  Collection   │   │              │   │  (Nuclei)      │   │              │
│               │   │              │   │                │   │              │
│  subfinder    │   │  httpx       │   │  nuclei        │   │  LLM client  │
│  amass        │   │  port scan   │   │  custom tmpl   │   │  prompt eng  │
│  OneForAll    │   │  tech detect │   │  severity      │   │  report gen  │
│  massdns      │   │  waf detect  │   │  filtering     │   │  FP check    │
│  ksubdomain   │   │              │   │                │   │              │
│  JSFinder     │   │              │   │                │   │              │
└───────────────┘   └──────────────┘   └────────────────┘   └──────────────┘
       │                    │                    │                    │
  domains.txt         fingerprints.db       vulns.db            report.md
```

---

## 2. 详细架构设计

### 2.1 阶段数据流

| 阶段 | 输入 | 输出 | 消费者 |
|------|------|------|--------|
| **Collect** | 目标根域名 (string) | `{target}.txt` 域名列表 + `module_results` 表 | Fingerprint |
| **Fingerprint** | 域名列表 | `fingerprints` 表：端口、服务、技术栈、WAF | VulnScan |
| **VulnScan** | 带端口的 URL 列表 | `vulnerabilities` 表：漏洞详情 + 严重等级 | AI Analysis |
| **AI Analysis** | 漏洞列表 + 指纹上下文 | `ai_analysis` 表 + `report.md` | 用户 |

### 2.2 输入/输出契约

每个阶段实现一个统一的接口：

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

@dataclass
class StageResult:
    status: str            # "success" | "partial" | "failed"
    items_processed: int
    items_output: int
    errors: List[str]
    output_path: str       # 产出文件/数据源路径

class PipelineStage(ABC):
    @abstractmethod
    def execute(self, task_id: int, input_path: str) -> StageResult: ...
```

### 2.3 工具→阶段映射

| 工具 | 阶段 | 说明 |
|------|------|------|
| subfinder | Collect | 被动子域名发现 |
| amass | Collect | 主动+被动综合枚举 |
| OneForAll | Collect | 多源聚合框架 |
| massdns | Collect | 高性能 DNS 验证 |
| ksubdomain | Collect | 高速爆破验证 |
| JSFinder | Collect | JS 页面资产挖掘 |
| httpx | Fingerprint | HTTP 服务探测与技术栈识别 |
| nuclei | VulnScan | 基于模板的漏洞扫描 |
| LLM API | AI Analysis | 报告生成与误报验证 |

---

## 3. 模块设计

### 3.1 核心模块

#### 3.1.1 Pipeline Orchestrator (`selectinf/pipeline/orchestrator.py`)

```python
class PipelineOrchestrator:
    """
    读取 pipeline_config.yaml，按顺序或条件触发各阶段。
    支持 stage 级别的 enable/disable 和 skip_on_failure。
    """
    def __init__(self, config_path: str): ...
    def run(self, target: str) -> dict:
        """返回每个 stage 的 StageResult"""
```

**关键职责:**
- 创建 `task_id`
- 按配置顺序调用各 stage
- 处理 stage 间的输入/输出路径传递
- 收集全局统计并写入 `task` 表

#### 3.1.2 Task State Machine (`selectinf/pipeline/task_fsm.py`)

```
States: created → collecting → collecting_done
      → fingerprinting → fingerprinting_done
      → vulnscanning → vulnscanning_done
      → ai_analyzing → completed
      ↓
      failed (from any state)
```

状态变更通过 `UPDATE task SET status = ? WHERE id = ?` 持久化。

#### 3.1.3 Config Manager (`selectinf/core/config.py`)

```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class ToolConfig:
    enabled: bool = True
    timeout: int = 300
    retries: int = 1
    extra_args: List[str] = field(default_factory=list)

@dataclass
class PipelineConfig:
    collect: Dict[str, ToolConfig]
    fingerprint: Dict[str, ToolConfig]
    vulnscan: Dict[str, ToolConfig]
    ai: Dict[str, ToolConfig]
    concurrency: int = 4
    output_dir: str = "output"
    work_dir: str = "work"
```

从 `pipeline_config.yaml` 反序列化，提供类型安全的配置访问。

### 3.2 阶段模块

#### 3.2.1 Collect Stage (`selectinf/stages/collect.py`)

封装现有 `run.py` 中的扫描逻辑为可并行调用的工具执行器：

```python
class CollectStage(PipelineStage):
    TOOLS = ["subfinder", "amass", "OneForAll", "massdns", "ksubdomain", "jsfinder"]

    def execute(self, task_id, input_path):
        # 并行组1: amass + OneForAll (CPU-heavy, 重任务)
        # 并行组2: massdns + ksubdomain (I/O-heavy, 网络任务)
        # 串行: subfinder (依赖轻量)
        # 迭代: jsfinder (依赖前序产出)
        ...
```

#### 3.2.2 Fingerprint Stage (`selectinf/stages/fingerprint.py`) — **新增**

```python
class FingerprintStage(PipelineStage):
    def execute(self, task_id, input_path):
        # 读取域名列表 → 转换为 http(s):// URL
        # 并发探测端口、HTTP 响应头、技术栈
        # 写入 fingerprints 表
```

#### 3.2.3 VulnScan Stage (`selectinf/stages/vulnscan.py`) — **新增**

```python
class VulnScanStage(PipelineStage):
    def execute(self, task_id, input_path):
        # 读取指纹结果 → 生成 nuclei 目标列表
        # 调用 nuclei -l targets.txt -o output.json
        # 解析 JSON 输出 → 写入 vulnerabilities 表
```

#### 3.2.4 AI Stage (`selectinf/stages/ai_analysis.py`) — **新增**

```python
class AIAnalysisStage(PipelineStage):
    def execute(self, task_id, input_path):
        # 读取 vulnerabilities + fingerprints
        # 调用 LLM 生成报告 + 误报评估
        # 写入 ai_analysis 表 + report.md
```

### 3.3 Stage 中间文件管理规范（新增）

为保持项目根目录整洁并支持多任务并行，所有阶段中间产物统一隔离到 `work/{task_id}/` 目录。

#### 3.3.1 目录结构约定

```
work/
  └── {task_id}/
        ├── subfinder.txt        ← 工具原始输出
        ├── amass.txt
        ├── massdns.txt
        ├── ksubdomain.txt
        ├── {domain}.txt          ← 合并后的域名列表
        ├── subdomain.txt         ← JSFinder 中间产物
        ├── url.txt               ← URL 转换中间产物
        └── nuclei_targets.txt    ← VulnScan 阶段生成
output/
  └── domain_{domain}.txt       ← 最终产物（ARL/MySQL 导出来源）
  └── {domain}.csv
```

#### 3.3.2 文件生命周期

| 阶段 | 文件 | 创建者 | 消费者 | 清理时机 |
|------|------|--------|--------|----------|
| Collect | `subfinder.txt` | `subfinder_scan()` | `extract_domains.py` | `extract_all_domains()` 执行后删除 |
| Collect | `amass.txt` | `amass_scan()` | `extract_domains.py` | 同上 |
| Collect | `massdns.txt` | `massdns_scan()` | `extract_domains.py` | 同上 |
| Collect | `ksubdomain.txt` | `ksubdomain_scan()` | `extract_domains.py` | 同上 |
| Collect | `{domain}.txt` | `extract_all_domains()` | JSFinder loop, dedup, url_converter | 最终合并为 `domain_{domain}.txt` 后删除 |
| Collect | `subdomain.txt` | JSFinder | dedup, url_converter | 每轮迭代后合并删除 |
| Collect | `url.txt` | JSFinder / url_converter | 最终输出 | 合并后删除 |
| Fingerprint | `httpx_input.txt` | CollectStage | FingerprintStage | FingerprintStage 执行后保留或删除（配置决定） |
| VulnScan | `nuclei_targets.txt` | FingerprintStage | VulnScanStage | VulnScanStage 执行后删除 |

#### 3.3.3 Orchestrator 职责

```python
# PipelineOrchestrator.run() 伪代码
work_dir = os.path.join(config.work_dir, str(task_id))
os.makedirs(work_dir, exist_ok=True)

try:
    for stage in stages:
        stage.execute(task_id, work_dir)
finally:
    if not config.keep_work_dir:
        shutil.rmtree(work_dir, ignore_errors=True)
```

- **默认行为**：流水线完成后自动清理 `work/{task_id}/`
- **调试模式**：`pipeline_config.yaml` 增加 `keep_work_dir: true` 保留中间文件
- **Backward compat**：`run.py` 在改为薄包装层之前，仍使用根目录；`CollectStage` 首次实现即采用 `work_dir` 模式

#### 3.3.4 现有脚本适配

`extract_domains.py`、`deduplicate.py`、`url_converter.py` 等脚本当前使用硬编码根目录路径。Phase 2 重构时统一改为接受 `work_dir` 参数：

```python
def extract_domain_subfinder(url, work_dir="."):
    ksubdomain_path = os.path.join(work_dir, "ksubdomain.txt")
    ...
```

**注意**：OneForAll 的 CSV 输出路径由 OneForAll 自身决定（`engines/OneForAll/results/{domain}.csv`），不在 `work_dir` 管理范围内。`extract_domain_OneForAll()` 读取后应立即删除。

---

## 4. 数据模型规范

### 4.1 完整 SQLite Schema

在现有 `sqlite_manager.py` 的 `init_db()` 中扩展以下表：

```sql
-- ── 已有表 ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS task (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_domain   TEXT    NOT NULL,
    start_time      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time        TIMESTAMP,
    status          TEXT    DEFAULT 'running',
    total_subdomains INTEGER DEFAULT 0,
    total_fingerprints INTEGER DEFAULT 0,
    total_vulns     INTEGER DEFAULT 0,
    note            TEXT
);

CREATE TABLE IF NOT EXISTS module_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    module_name     TEXT    NOT NULL,
    output_file     TEXT,
    raw_output      TEXT,
    domain_count    INTEGER DEFAULT 0,
    status          TEXT    DEFAULT 'success',
    error_msg       TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES task (id)
);

CREATE TABLE IF NOT EXISTS final_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    domain          TEXT    NOT NULL,
    source_module   TEXT,
    ip              TEXT,
    port            INTEGER,
    url             TEXT,
    title           TEXT,
    status_code     INTEGER,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES task (id)
);

CREATE TABLE IF NOT EXISTS jsfinder_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    parent_url      TEXT,
    discovered_domain TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES task (id)
);

-- ── 新增: assets 表 (标准化存储收集到的域名) ─────

CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    domain          TEXT    NOT NULL,
    resolved_ip     TEXT,
    source_module   TEXT    NOT NULL,   -- subfinder|amass|OneForAll|massdns|ksubdomain|jsfinder
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(task_id, domain, source_module)
);

-- ── 新增: fingerprints 表 ────────────────────────────

CREATE TABLE IF NOT EXISTS fingerprints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    url             TEXT    NOT NULL,     -- https://sub.example.com
    ip              TEXT,
    port            INTEGER DEFAULT 443,
    status_code     INTEGER,
    title           TEXT,
    content_type    TEXT,
    server_header   TEXT,                 -- Nginx, Apache, etc.
    tech_stack      TEXT,                 -- JSON array: ["React","WordPress","jQuery"]
    waf_detected    TEXT,                 -- WAF 名称或 NULL
    response_time_ms INTEGER,
    first_scanned   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fingerprint_id_fingerprint TEXT,      -- httpx 原始指纹 hash
    UNIQUE(task_id, url, port)
);

-- ── 新增: vulnerabilities 表 ─────────────────────────

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    vuln_id         TEXT    NOT NULL,     -- nuclei template ID (e.g., "CVE-2024-1234")
    url             TEXT    NOT NULL,     -- 受影响的具体 URL
    template        TEXT    NOT NULL,     -- nuclei template name
    severity        TEXT    NOT NULL,     -- critical|high|medium|low|info
    cvss_score      REAL,
    description     TEXT,
    matched_at      TEXT,                 -- 匹配到的具体响应
    extracted_results TEXT,               -- 提取的敏感信息 (JSON)
    nuclei_output_json TEXT,             -- nuclei 原始 JSON 行 (截断 ≤8KB)
    ai_validated    INTEGER DEFAULT NULL, -- NULL=未评估, 1=确认, 0=误报
    ai_confidence   REAL DEFAULT NULL,    -- 0.0-1.0 AI 置信度
    first_detected  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(task_id, vuln_id, url, template)
);

-- ── 新增: ai_analysis 表 ─────────────────────────────

CREATE TABLE IF NOT EXISTS ai_analysis (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL,
    analysis_type   TEXT    NOT NULL,     -- "report" | "fp_check" | "summary"
    input_data      TEXT,                 -- 输入的漏洞/指纹数据摘要
    model_used      TEXT,                 -- 模型标识 (e.g., "gpt-4", "ollama/llama3")
    prompt_tokens   INTEGER,
    completion_tokens INTEGER,
    result_text     TEXT,                 -- LLM 输出结果 (≤16KB)
    cost_usd        REAL DEFAULT 0.0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES task (id)
);

-- ── 索引优化 ─────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_assets_task ON assets(task_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_task ON fingerprints(task_id);
CREATE INDEX IF NOT EXISTS idx_vulns_task_severity ON vulnerabilities(task_id, severity);
CREATE INDEX IF NOT EXISTS idx_ai_analysis_task ON ai_analysis(task_id);
```

### 4.2 Python 数据类

```python
# selectinf/models/entities.py
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Asset:
    task_id: int
    domain: str
    resolved_ip: Optional[str] = None
    source_module: str = ""
    first_seen: datetime = field(default_factory=datetime.now)

@dataclass
class Fingerprint:
    task_id: int
    url: str
    ip: Optional[str] = None
    port: int = 443
    status_code: Optional[int] = None
    title: Optional[str] = None
    content_type: Optional[str] = None
    server_header: Optional[str] = None
    tech_stack: list = field(default_factory=list)
    waf_detected: Optional[str] = None
    response_time_ms: Optional[int] = None

@dataclass
class Vulnerability:
    task_id: int
    vuln_id: str
    url: str
    template: str
    severity: Severity
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    matched_at: Optional[str] = None
    extracted_results: Optional[dict] = None
    ai_validated: Optional[bool] = None
    ai_confidence: Optional[float] = None
```

---

## 5. 配置规范

### 5.1 pipeline_config.yaml

```yaml
# ── 全局设置 ─────────────────────────
pipeline:
  concurrency: 4              # 全局最大并发数
  work_dir: "work"            # 每任务的临时目录
  output_dir: "output"        # 最终结果目录
  stages:
    collect: true
    fingerprint: true
    vulnscan: true
    ai_analysis: true

# ── Stage 1: 资产收集 ──────────────
collect:
  tools:
    subfinder:
      enabled: true
      timeout: 300
      retries: 1
      extra_args: ["-silent", "-all"]
    amass:
      enabled: true
      timeout: 600
      retries: 1
      extra_args: ["-v", "-src", "-ip", "-brute", "-active"]
    oneforall:
      enabled: true
      timeout: 900
      retries: 1
    massdns:
      enabled: true
      timeout: 300
      retries: 1
      names_file: "tools/massdns/lists/names.txt"
      resolvers_file: "tools/massdns/lists/resolvers.txt"
    ksubdomain:
      enabled: true
      timeout: 300
      retries: 1
      extra_args: ["-b", "20M"]
    jsfinder:
      enabled: true
      timeout: 600
      retries: 1
      max_iterations: 5       # JSFinder 最大迭代次数

# ── Stage 2: 指纹识别 ──────────────
fingerprint:
  httpx:
    enabled: true
    timeout: 30
    retries: 2
    ports: [80, 443, 8080, 8443]
    tech_detect: true
    follow_redirects: true
    threads: 20               # httpx 内部并发
  port_scan:
    enabled: false            # 可选: 自定义端口扫描
    ports: [22, 3306, 6379]

# ── Stage 3: 漏洞扫描 ──────────────
vulnscan:
  nuclei:
    enabled: true
    timeout: 1800
    retries: 1
    templates_dir: ""             # 留空 = 使用 nuclei 默认路径 (%USERPROFILE%\nuclei-templates)
    severity_filter: ["critical", "high", "medium"]  # 排除 low/info
    rate_limit: 50            # 每秒请求数
    threads: 10
    bulk_size: 100            # 每批目标数量

# ── Stage 4: AI 分析 ───────────────
ai:
  provider: "openai"          # openai | ollama
  openai:
    api_key_env: "OPENAI_API_KEY"
    model: "gpt-4o"
    temperature: 0.3
    max_tokens: 4096
  ollama:
    base_url: "http://localhost:11434"
    model: "llama3"
  fp_validation:
    enabled: true
    threshold: 0.7            # 置信度低于此值标记为疑似误报
  report:
    format: "markdown"        # markdown | json | html
    include_remediation: true
    language: "zh-CN"
```

### 5.2 配置加载

```python
# selectinf/core/config.py
import yaml

def load_config(path: str = "pipeline_config.yaml") -> PipelineConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return PipelineConfig.from_dict(raw)
```

---

## 6. 外部工具集成规范

### 6.1 统一工具抽象

```python
# selectinf/core/tool_runner.py
@dataclass
class ToolResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    elapsed: float

def run_tool(
    cmd: List[str],
    description: str,
    timeout: int = 300,
    cwd: str = None,
    env: dict = None,
    retries: int = 1,
) -> Optional[ToolResult]:
    """统一的工具执行入口，封装 _run_cmd 逻辑。"""
```

### 6.2 各工具集成参数

| 工具 | 调用方式 | 输入格式 | 输出格式 | 超时(秒) | 关键错误 |
|------|----------|----------|----------|----------|----------|
| **subfinder** | `subfinder.exe -d {domain} -o {out} -silent` | 域名 (string) | 每行一个域名 | 300 | 二进制不存在 |
| **amass** | `amass.exe enum -d {domain} -o {out} -brute -active` | 域名 (string) | 每行一个域名 | 600 | 网络超时 |
| **OneForAll** | `python oneforall.py --target {domain} run` | 域名 (string) | CSV 结果文件 | 900 | PYTHONPATH 错误 |
| **massdns** | `subbrute.py \| massdns.exe -r resolvers.txt -o S -w {out}` | 域名 (string) | DNS 响应文本 | 300 | pipe 断裂 |
| **ksubdomain** | `ksubdomain.exe -d {domain} -b 20M -o {out}` | 域名 (string) | 每行一个域名 | 300 | wpcap.dll 缺失 |
| **JSFinder** | `python JSFinder.py -u {url} -ou url.txt -os subdomain.txt` | URL (string) | url.txt + subdomain.txt | 600 | 目标不可达 |
| **httpx** | `httpx -l {list} -o {out}.json -json -threads 20` | 域名列表 (file) | JSON Lines | 300 | 无在线主机 |
| **nuclei** | `nuclei -l {list} -t {templates} -o {out}.json -jsonl -severity critical,high,medium` | URL 列表 (file) | JSON Lines | 1800 | 模板加载失败 |

### 6.3 错误处理约定

```python
ERROR_PATTERNS = {
    "wpcap.dll": "Npcap/WinPcap 未安装，请安装 https://npcap.com/",
    "couldn't load wpcap": "同上",
    "FileNotFoundError": "工具二进制文件缺失，检查 tools/ 目录",
    "TimeoutExpired": "工具执行超时，考虑减少目标范围或增加 timeout",
    "returncode != 0": "工具执行失败，检查 stderr 输出",
}
```

### 6.4 重试逻辑

```python
def run_with_retry(cmd, description, timeout, retries=1):
    for attempt in range(1, retries + 2):  # 1 initial + N retries
        result = run_cmd(cmd, description, timeout)
        if result and result.exit_code == 0:
            return result
        logger.warning("[%s] 第 %d/%d 次重试", description, attempt, retries)
    return None
```

---

## 7. 并发模型

### 7.1 线程池 vs 进程池选择

| 场景 | 推荐 executor | 理由 |
|------|---------------|------|
| 调用外部工具 (subprocess) | **ThreadPoolExecutor** | 工具本身是独立进程，I/O 等待为主，线程足矣 |
| 数据处理 (去重、过滤、提取) | **ThreadPoolExecutor** | GIL 不阻塞 I/O 操作 |
| 大量文件读写 | **ThreadPoolExecutor** | 操作本身由 OS 处理 |
| CPU 密集计算 (如正则匹配大量文本) | **ProcessPoolExecutor** | 但本项目中不常见 |
| httpx 内部并发 | httpx 自带 `-threads` | 不额外包裹 |

**结论:** 本项目 99% 场景使用 `ThreadPoolExecutor`，不引入 `ProcessPoolExecutor`。

### 7.2 并发层级

```python
# 并行级别设计
LEVEL_1  # Stage 间串行 (Collect → Fingerprint → VulnScan → AI)
LEVEL_2  # Stage 内工具可并行 (e.g., amass + OneForAll 同时跑)
LEVEL_3  # 工具内部并发 (httpx -threads 20, nuclei -rate-limit 50)
```

### 7.3 资源限制

```yaml
# 并发限制写在配置中
pipeline:
  concurrency: 4               # 同时运行的最大工具数
fingerprint:
  httpx:
    threads: 20                # httpx 内部线程
vulnscan:
  nuclei:
    rate_limit: 50             # 每秒请求
    threads: 10                # nuclei 模板并发
```

### 7.4 Windows 特定考量

- **subprocess.CREATE_NO_WINDOW:** 调用外部工具时添加，避免弹出控制台窗口
- **Shell = False:** 始终使用列表形式 `["exe", "arg1"]` 避免命令注入
- **Path separators:** 使用 `os.path.join` 或 `pathlib.Path`，不使用硬编码 `\`
- **Signal handling:** Windows 不支持 `SIGTERM`，超时使用 `proc.kill()` 而非 `terminate()`

---

## 8. AI 集成规范

### 8.1 LLM 客户端接口

```python
# selectinf/ai/client.py
from abc import ABC, abstractmethod

class LLMClient(ABC):
    @abstractmethod
    def chat(self, messages: list, **kwargs) -> str: ...
    @abstractmethod
    def cost_estimate(self, prompt_tokens: int, completion_tokens: int) -> float: ...

class OpenAIClient(LLMClient): ...
class OllamaClient(LLMClient): ...
```

工厂方法根据 `pipeline_config.yaml` 的 `ai.provider` 字段返回对应客户端。

### 8.2 Prompt 模板

```python
# selectinf/ai/prompts.py

REPORT_TEMPLATE = """\
你是一个网络安全分析师。根据以下漏洞扫描结果，生成一份结构化的安全报告。

语言: {language}
目标: {target_domain}
发现时间: {scan_date}

## 漏洞列表
{vulnerabilities_summary}

## 指纹信息
{fingerprint_summary}

## 要求
1. 用 {language} 撰写报告
2. 按严重程度排序列出所有确认的漏洞
3. 为每个漏洞提供简要的修复建议
4. 排除已标记为误报的条目
5. 输出 Markdown 格式
"""

FP_CHECK_TEMPLATE = """\
你是一个安全漏洞验证专家。请评估以下 Nuclei 扫描结果是否可能是误报。

## 漏洞信息
- 模板: {template}
- 严重等级: {severity}
- 匹配内容: {matched_at}
- 提取结果: {extracted_results}

## 指纹上下文
- 技术栈: {tech_stack}
- 服务器: {server_header}

## 任务
判断这是否是误报，给出:
1. 判断结果: true (确认漏洞) / false (误报)
2. 置信度: 0.0-1.0
3. 简短理由

返回 JSON 格式: {{"is_vuln": bool, "confidence": float, "reason": "string"}}
"""
```

### 8.3 误报验证流程

```python
async def validate_finding(vuln: Vulnerability, fp_client: LLMClient) -> dict:
    """
    1. 组装 FP_CHECK_TEMPLATE prompt
    2. 调用 LLM 获取 JSON 结果
    3. 解析响应，更新 vuln.ai_validated 和 vuln.ai_confidence
    4. 当 confidence < threshold (默认 0.7) 时标记为 "疑似误报"
    """
```

### 8.4 置信度评分逻辑

```python
def compute_effective_severity(vuln: Vulnerability) -> str:
    """
    结合原始严重等级和 AI 评估结果计算有效等级:
    - ai_validated == 0 → 降低一级 (high → medium)
    - ai_confidence < 0.5 → 标记为 "疑似"
    - ai_validated == 1 → 保持原始等级
    - ai_validated == None → 未评估，使用原始等级
    """
```

### 8.5 防幻觉策略

- **结构化输出约束:** 要求 LLM 返回 JSON 而非自由文本，使用 `response_format={"type": "json_object"}`
- **温度控制:** `temperature=0.3` 确保输出稳定可预测
- **输入裁剪:** 仅输入 `matched_at` + 关键元数据，不输入完整 HTTP 响应
- **验证规则:** LLM 输出需通过 JSON Schema 校验才入库

---

## 9. 从现有代码迁移

### 9.1 Strangler Pattern 实现步骤

```
Step 1: 创建 selectinf/pipeline/ 目录和 orchestrator.py
Step 2: 将 run.py 中的工具调用函数迁移到 selectinf/stages/collect.py
Step 3: 新 orchestrator 调用 collect stage，其余 stage 为 stub (pass)
Step 4: 验证: python -m selectinf 行为与 python run.py 完全一致
Step 5: 逐步启用 fingerprint → vulnscan → ai_analysis stages
Step 6: run.py 改为 orchestrator.run() 的薄包装层
Step 7: 删除已迁移的遗留逻辑（或保留为 backward_compat 模式）
```

### 9.2 包装 run.py

```python
# 修改后的 run.py — 保留向后兼容
def main():
    logger.info("=" * 50)
    logger.info("selectinf 资产收集框架启动")
    logger.info("=" * 50)

    init_db()
    raw_input = input("请输入URL: ")
    domain = sanitize_target(raw_input)

    # 新路径: 通过 pipeline orchestrator
    config = load_config()
    orchestrator = PipelineOrchestrator(config)
    result = orchestrator.run(domain)

    # 保留原有导出逻辑 (ARL + MySQL)
    _legacy_export(domain)

    logger.info("selectinf 任务完成!")
    input("按任意键退出...")
    sys.exit(0)
```

### 9.3 向后兼容保证

| 项目 | 兼容策略 |
|------|----------|
| 输出文件 | 继续生成 `{domain}.txt`, `domain_{domain}.txt` |
| SQLite 表 | 新增表不删除旧表 (`final_results`, `module_results` 保持) |
| MySQL 导出 | 保留 `csvToDatabase.csvToDatabase()` 调用 |
| ARL 导出 | 保留 `arl_exporter` 调用链 |
| 命令行交互 | 保持 `input("请输入URL: ")` 不变 |

---

## 10. 开发任务分解

### Phase 1: 基础设施 (2-3 天)

| # | 任务 | 描述 | 依赖 | 工时 | 验收标准 |
|---|------|------|------|------|----------|
| 1 | 创建目录结构 | `selectinf/pipeline/`, `selectinf/stages/`, `selectinf/core/`, `selectinf/ai/`, `selectinf/models/` | 无 | 0.5h | 所有 `__init__.py` 就位 |
| 2 | Config Manager | 实现 `PipelineConfig` 数据类 + YAML 加载 | 1 | 1h | 从 yaml 正确反序列化 |
| 3 | Tool Runner | 重构 `_run_cmd` 为统一 `run_tool()` | 无 | 2h | 现有工具调用全部通过新接口 |
| 4 | SQLite Schema 扩展 | 添加 `assets`, `fingerprints`, `vulnerabilities`, `ai_analysis` 表 | 无 | 1h | `init_db()` 后表存在，索引创建 |
| 5 | Entity Models | 实现 `Asset`, `Fingerprint`, `Vulnerability` dataclass | 4 | 1h | 单元测试可通过 |

### Phase 2: Collect Stage 重构 (1-2 天)

| # | 任务 | 描述 | 依赖 | 工时 | 验收标准 |
|---|------|------|------|------|----------|
| 6 | Collect Stage | 将现有扫描逻辑封装为 `CollectStage`；**所有工具中间输出写入 `work/{task_id}/` 而非根目录** | 2, 3 | 3h | 产出与现有 run.py 一致，根目录无残留 .txt |
| 7 | Pipeline Orchestrator | 实现 stage 调度 + task FSM；**运行时创建 `work/{task_id}/`，完成后自动清理** | 2, 6 | 3h | 可执行 collect 阶段 |
| 8 | 集成测试: Collect | 用已知域名验证 collect 阶段完整流程 | 6, 7 | 2h | 数据库中有 correct assets |

### Phase 3: Fingerprint Stage (1-2 天)

| # | 任务 | 描述 | 依赖 | 工时 | 验收标准 |
|---|------|------|------|------|----------|
| 9 | Fingerprint Stage | 实现 httpx 集成: 端口探测、技术栈识别 | 4, 7 | 3h | fingerprints 表有数据 |
| 10 | URL 转换改进 | 替换现有 url_converter.py 为 stage 内逻辑 | 9 | 1h | URL 转换正确 |
| 11 | 集成测试: Fingerprint | 对已知域名验证指纹识别准确度 | 9 | 1h | 能识别常见技术栈 |

### Phase 4: VulnScan Stage (1-2 天)

| # | 任务 | 描述 | 依赖 | 工时 | 验收标准 |
|---|------|------|------|------|----------|
| 12 | VulnScan Stage | nuclei 集成: 目标生成、调用、JSON 解析 | 5, 9 | 4h | vulnerabilities 表有数据 |
| 13 | Severity 过滤 | 按配置过滤 severity，支持自定义模板路径 | 12 | 1h | 仅录入配置等级 |
| 14 | 集成测试: VulnScan | 带已知漏洞环境验证 | 12 | 2h | 已知漏洞被检出 |

### Phase 5: AI Analysis Stage (2-3 天)

| # | 任务 | 描述 | 依赖 | 工时 | 验收标准 |
|---|------|------|------|------|----------|
| 15 | LLM Client | OpenAI + Ollama 双客户端实现 | 2 | 3h | 两种 provider 均可调用 |
| 16 | Prompt 模板 | 报告生成 + 误报验证 prompt | 15 | 2h | 输出格式正确 |
| 17 | AI Stage | 编排 LLM 调用 + 结果入库 | 15, 16, 12 | 3h | ai_analysis 表有数据 |
| 18 | 报告生成 | 输出 Markdown 报告文件 | 17 | 1h | report.md 可读 |

### Phase 6: 集成与收尾 (1 天)

| # | 任务 | 描述 | 依赖 | 工时 | 验收标准 |
|---|------|------|------|------|----------|
| 19 | 端到端测试 | 完整四阶段流水线 | 8, 11, 14, 17 | 2h | 全流程无报错 |
| 20 | 文档更新 | README + pipeline_config.yaml 示例 | 19 | 1h | 新用户可以上手 |

---

## 11. 风险与限制

### 11.1 Windows 子进程问题

| 风险 | 影响 | 缓解 |
|------|------|------|
| `subprocess` 编码异常 | 中文输出的 STDERR 解码失败 | 使用 `errors="replace"` + `encoding="utf-8"` (已实现) |
| 控制台窗口弹出 | 用户体验差 | 添加 `creationflags=subprocess.CREATE_NO_WINDOW` |
| 进程杀死不彻底 | 僵尸进程残留 | 使用 `proc.kill()` + Windows Job Object (可选) |
| Path 长度限制 | 深层临时目录路径超 260 字符 | `work_dir` 保持扁平结构 |

### 11.2 SQLite 并发写入

| 风险 | 影响 | 缓解 |
|------|------|------|
| `SQLITE_BUSY` 锁冲突 | 多线程同时写入失败 | WAL 模式: `PRAGMA journal_mode=WAL` |
| 连接共享 | 跨线程 `sqlite3.Connection` 不安全 | 每线程 `get_db()` 创建新连接 |
| 写入批量慢 | 逐条 INSERT 性能差 | 使用 `executemany` + `BEGIN IMMEDIATE` |

```python
# 在 get_db() 中添加:
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA busy_timeout=5000")
```

### 11.3 工具可靠性差异

| 工具 | 可靠性 | 常见问题 | 对策 |
|------|--------|----------|------|
| subfinder | 高 | API key 限流 | 静默重试，不阻塞其他工具 |
| amass | 中 | 内存占用大 | 独立超时，失败不重试 |
| OneForAll | 中 | Python 依赖冲突 | 隔离 PYTHONPATH 检查 |
| massdns | 高 | names.txt 过大时慢 | 限制字典大小或超时 |
| ksubdomain | 低 | 依赖 Npcap，Windows 兼容差 | 降级为可选工具 |
| nuclei | 中 | 模板加载慢 | 预加载模板缓存 |

### 11.4 AI 幻觉缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| LLM 编造漏洞 | 报告中出现不存在的 CVE | 严格基于 nuclei 实际输出，不自行推断 |
| JSON 解析失败 | 误报验证无法入库 | Schema 验证 + 降级为 "unknown" |
| 成本失控 | API 调用费用超预期 | 每日配额限制 + `cost_usd` 记录 |
| 延迟过高 | LLM 响应慢阻塞 pipeline | 异步调用 + 超时控制 (30s) |

---

## 12. 附录

### 12.1 目录结构 (规划)

```
selectinf/
├── __init__.py
├── __main__.py
├── core/
│   ├── __init__.py
│   ├── config.py          # PipelineConfig + YAML 加载
│   ├── tool_runner.py     # 统一工具执行
│   └── exceptions.py      # 自定义异常
├── models/
│   ├── __init__.py
│   └── entities.py        # Asset, Fingerprint, Vulnerability
├── stages/
│   ├── __init__.py
│   ├── base.py            # PipelineStage ABC
│   ├── collect.py         # 资产收集
│   ├── fingerprint.py     # 指纹识别 (新增)
│   ├── vulnscan.py        # 漏洞扫描 (新增)
│   └── ai_analysis.py     # AI 分析 (新增)
├── pipeline/
│   ├── __init__.py
│   ├── orchestrator.py    # 流水线编排
│   └── task_fsm.py        # 任务状态机
├── ai/
│   ├── __init__.py
│   ├── client.py          # LLM 客户端接口 + 实现
│   └── prompts.py         # Prompt 模板
├── collect/               # 现有，逐步迁移
├── process/               # 现有，逐步迁移
└── output/                # 现有，逐步迁移
pipeline_config.yaml       # 流水线配置
run.py                     # 入口 (薄包装)
```

### 12.2 迁移 Checklist

- [x] `pipeline_config.yaml` 创建并验证
- [x] SQLite WAL 模式启用
- [x] Phase 1: 基础设施 (config, tool_runner, SQLite schema, entities, ABC stubs)
- [x] Phase 2: Collect Stage (`selectinf/stages/collect.py`) — 工具中间输出写入 `work/{task_id}/`
- [x] Phase 2: Pipeline Orchestrator (`selectinf/pipeline/orchestrator.py`) — stage 调度 + FSM + work_dir 生命周期
- [x] Phase 2: 集成测试 (`tests/test_collect_stage.py`, `tests/test_orchestrator.py`) — 12/12 pass
- [x] Phase 2: 向后兼容 — `final_results` / `module_results` 表仍写入，ARL/MySQL 导出未改动
- [x] Phase 3: Fingerprint Stage (`httpx` 集成)
- [x] Phase 4: VulnScan Stage (`nuclei` 集成)
- [x] Phase 5: AI Analysis Stage (LLM client + prompts)
- [x] Phase 6: `run.py` 薄包装层 + 端到端验证
- [x] README 更新四阶段说明

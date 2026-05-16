## selectinf - 从资产收集到漏洞扫描与结果输出的一体化自动化框架

**selectinf** 是一个将多种子域名/资产收集与漏洞扫描工具统一编排的自动化框架，通过并行调度 OneForAll、amass、massdns、ksubdomain、subfinder、JSFinder 等组件，完成从资产发现、清洗、DNS 分析、URL 抽取，到后续漏洞扫描与结果输出的完整安全测试流水线。

> 目标：**从资产收集 → 漏洞扫描 → 结构化结果输出，全流程尽量减少人工干预。**

---

## ✨ 功能特性

- **多引擎资产/子域名收集（整合多款工具）**
  - 集成 `amass`、`subfinder`、`ksubdomain`、`massdns`、`OneForAll` 等常见资产收集工具
  - 并行运行不同引擎，尽可能覆盖更多子域名来源

- **域名与 URL 全流程处理（资产侧）**
  - 自动提取域名、去重、合并结果
  - 通过 `JSFinder` 从目标站点及其下游 URL 中持续挖掘新的子域名
  - 将域名转换为可访问 URL 进行进一步探测

- **结果清洗与去重（数据侧）**
  - 针对域名和 URL 做多轮去重、合并
  - 支持对泛解析域名进行过滤（脚本中已预留逻辑）

- **漏洞扫描集成（Nuclei 模块）**
  - 在资产收集完成后，对收集到的域名/URL 进行批量 `nuclei` 扫描（规划/集成中）
  - 支持自定义模板目录与严重程度过滤，将“资产发现 + 漏洞探测”串成一条流水线

- **结果汇总与结构化输出**
  - 把资产与漏洞扫描结果统一整理为 `csv` / 数据库形式，方便后续统计与二次分析
  - 预留与安全运营平台/可视化平台对接的接口位置

- **Agent 驱动的自动化扫描（规划中）**
  - 引入 Agent（智能代理）编排思路，根据任务配置自动调度：
    - 资产发现 → JS 扫描 → Nuclei 漏扫 → 漏洞验证（如 POC/EXP）→ 结果入库
  - 通过配置文件或简单指令描述扫描策略，降低人工参与度，实现批量目标的无人值守扫描（仅限合法授权环境）

- **一键式交互体验**
  - 通过 `python run.py`，仅需输入一次目标域名即可启动“资产收集 → 扫描 → 结果输出”的整条链路（当前已实现以资产收集与结果入库为主，漏洞扫描在逐步集成）

---

## 🧩 整体架构与工作流程

整体逻辑由 `run.py` 及一系列脚本/外部工具共同完成，可以抽象为三个阶段：

1. **资产收集阶段**
   - 运行 `python run.py`
   - 输入目标根域名，例如：`example.com`
   - 顺序/并行调用：
     - `subfinder`（`subfinder\subfinder.exe`）
     - `amass`（`amass\amass.exe`）
     - `OneForAll`（`OneForAll\oneforall.py`）
     - `massdns`（`massdns\scripts\subbrute.py` + `massdns\bin\massdns`）
     - `ksubdomain`（`ksubdomain\ksubdomain.exe`）
   - 使用 `extract_domains.py`、`deduplicate.py`、`filterWildcardDomains.py` 等脚本对域名做提取、去重与过滤
   - 利用 `GetUrl.py`、`dnsgrep.py`、`JSFinder\JSFinder.py` 对 URL/JS 继续扩展资产面

2. **漏洞扫描阶段（规划/集成中）**
   - 使用资产收集阶段产出的 `domain_<target>.txt`、`<target>.txt` 作为输入
   - 调用 `nuclei` 等漏洞扫描工具执行批量扫描
   - 后续可扩展不同类型模板（如 Web 漏洞、弱口令、信息泄露等）

3. **结果汇总与输出阶段**
   - 利用 `arl_output.py`、`csvToDatabase.py` 等脚本：
     - 将资产（以及未来的漏洞结果）导出为 `csv`
     - 清洗后写入数据库，形成统一数据源
   - 控制台提示任务结束，可查看文件与数据库中的结果

---

## 🛠️ 集成工具一览

- **子域名收集**
  - `subfinder`：被动/主动综合子域名发现
  - `amass`：多数据源的子域名收集与枚举
  - `OneForAll`：综合性子域名收集框架
  - `ksubdomain`：高性能子域名爆破/验证
  - `massdns`：高性能 DNS 批量解析

- **JS/URL 分析**
  - `JSFinder`：从页面与 JS 文件中提取 URL 和子域名

- **漏洞扫描（规划/集成中）**
  - `nuclei`：基于模板的快速漏洞扫描引擎（计划对收集到的资产批量执行 PoC）

- **数据处理与入库**
  - 自研脚本：`deduplicate.py`、`filterWildcardDomains.py`、`extract_domains.py`、`GetUrl.py`、`dnsgrep.py`、`arl_output.py`、`csvToDatabase.py` 等

> 具体脚本与第三方工具的使用细节，可参考对应目录中的 `README` / `help`。

---

## 📋 环境要求

- **操作系统**
  - 推荐：Windows 10/11（仓库中已包含若干 `.exe` 与 Windows 路径）

- **运行环境**
  - Python 3.8+（建议使用虚拟环境）
  - `pip` 包管理器

- **第三方工具**
  - `subfinder`、`amass`、`ksubdomain`、`massdns` 等执行文件已放置于仓库对应目录：
    - `subfinder\subfinder.exe`
    - `amass\amass.exe`
    - `ksubdomain\ksubdomain.exe`
    - `massdns\bin\massdns`（或 `massdns\windows\*`）
  - 若缺失或版本不兼容，请根据官方文档自行替换/更新。

---

## 🚀 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/yourname/selectinf.git
cd selectinf
```

> 请将上面的仓库地址替换为你实际使用的 Git 仓库地址。

### 2. 安装 Python 依赖

项目中主要使用 Python 作为编排语言，同时依赖 OneForAll 自身的依赖：

```bash
# 建议先创建虚拟环境（可选）
python -m venv venv
venv\Scripts\activate

# 安装 OneForAll 所需依赖
pip install -r OneForAll/requirements.txt
```

如果你在其他脚本运行中遇到缺少第三方库的报错（如 `requests`、`tqdm` 等），请根据提示使用 `pip install xxx` 补齐。

### 3. 准备第三方二进制工具

- 确认以下文件存在且可执行（路径相对于项目根目录）：
  - `subfinder\subfinder.exe`
  - `amass\amass.exe`
  - `ksubdomain\ksubdomain.exe`
  - `massdns\bin\massdns` 或 `massdns\windows\*\massdns.exe`
- 如需更新版本：
  - 可根据各工具官方文档下载新版替换对应文件
  - 保持路径与 `run.py` 中调用命令一致，或自行修改命令行参数

### 4. 配置数据库等参数（可选）

- `database.conf`：数据库连接相关配置（如地址、库名、账号密码等）
- `application\add.json` / `application\task.json`：任务与资产添加策略相关配置

根据你的实际环境调整上述文件，确保数据库可连接、任务配置符合预期。

### 5. 启动资产收集

```bash
python run.py
```

按照提示输入目标根域名，例如：

```text
请输入URL: example.com
```

脚本会自动启动多个工具进行资产收集，过程耗时取决于目标规模与网络状况。

---

## 🔍 结果输出与使用方式

当前版本在“资产收集 → 结果输出”已经打通，后续会在此基础上补充漏洞扫描结果的数据链路。

### 1. 文件输出

运行结束后，你通常可以在项目根目录看到如下类型的文件（名称与流程可能根据后续修改有所变化）：

- **资产相关文本文件**
  - `<target>.txt`：与目标相关的 URL/域名集合（多轮合并和去重后的结果）
  - `domain_<target>.txt`：与目标相关的子域名列表
  - `subdomain.txt`：`JSFinder` 等过程中的中间子域名结果文件

- **结构化数据文件**
  - `output_file.csv`：中间导出的 CSV 结果
  - `<target>.csv`：与目标相关的资产 CSV 结果
  - （规划中）漏洞扫描结果合并后的 CSV（如 `vuln_<target>.csv`）

### 2. 数据库存储

- `csvToDatabase.py` 会将资产（以及未来的漏洞扫描结果）写入数据库
- 你可以基于数据库：
  - 按目标/域名/风险等级做检索
  - 与自己的安全平台或看板对接做可视化

### 3. 典型使用方式

- 资产梳理：快速拉全某个域名的子域名和 URL 资产
- 漏洞初筛（规划中）：在资产收集结束后，自动对资产做模板化批量漏洞扫描
- 结果导出：通过 CSV 或数据库接口把结果导入到其他系统（如资产平台、漏洞管理平台等）

---

## 🧱 目录结构（节选）

```text
.
├── run.py                       # 主入口脚本，执行资产收集与整体编排
├── GetUrl.py                    # 域名转 URL 相关逻辑
├── deduplicate.py               # 域名/URL 去重逻辑
├── extract_domains.py           # 从文件中提取域名
├── filterWildcardDomains.py     # 泛解析域名过滤（可按需开启）
├── dnsgrep.py                   # DNS 记录相关处理
├── arl_output.py                # 结果导出为 CSV 等
├── csvToDatabase.py             # CSV 写入数据库
├── database.conf                # 数据库配置
├── application/
│   ├── add.json                 # 资产添加配置
│   └── task.json                # 任务相关配置
├── OneForAll/                   # 集成的 OneForAll 子域名收集框架
├── amass/                       # amass 可执行文件及示例配置
├── ksubdomain/                  # ksubdomain 可执行文件
├── massdns/                     # massdns 脚本与配置
├── jsfinder/                    # JSFinder 脚本及相关字典
└── ...
```

---

## 📌 注意事项

- 本项目主要面向**合法授权范围内的安全测试与资产梳理**，请严格遵守相关法律法规及合规要求。
- 对于稳定性、性能或准确度有更高要求的场景，建议：
  - 根据自身环境调整各工具的参数（并发、超时、字典大小等）
  - 增加异常处理与日志记录，便于排查问题

---

## 📅 后续规划（TODO）

- **整合更多资产收集工具并统一编排**
- **在收集结果基础上无缝接入 Nuclei 等漏洞扫描模块，并将扫描结果纳入统一输出**
- **引入 Agent 机制，实现从资产收集到漏洞扫描到入库的自动化流水线**

欢迎根据自己的需求进行二次开发或提交 PR，共同完善这个资产收集整合框架。

---

**Happy Hunting!** 🎯

*让繁琐的资产收集流程自动化，把时间留给真正有价值的安全分析。*
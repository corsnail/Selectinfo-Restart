"""Prompt templates for AI analysis stage."""

# ── 报告生成 Prompt ──────────────────────────────────────────────
REPORT_PROMPT = """\
你是一名资深网络安全分析师。请根据以下资产指纹和漏洞扫描结果，生成一份专业的安全评估报告。

## 配置要求
- 报告语言: {language}
- 是否包含修复建议: {include_remediation}
- 输出格式: Markdown

## 资产指纹摘要
{fingerprints_summary}

## 漏洞列表 (severity >= medium)
{vulnerabilities_summary}

## 报告结构要求
请按以下结构组织报告:

1. **执行摘要** — 总体风险评级、关键发现数量、受影响资产范围
2. **资产概览** — 扫描目标数量、存活服务统计、技术栈分布
3. **漏洞详情** — 按 severity 降序排列，每个漏洞包含:
   - 漏洞名称 / 模板 ID
   - 严重程度
   - 受影响 URL
   - 简要描述
   - {remediation_section}
4. **风险趋势与建议** — 整体安全态势评估和优先级修复建议
5. **附录** — 扫描工具、时间范围、置信度说明

## 注意事项
- 使用表格呈现结构化数据
- 对 critical/high 级别漏洞提供详细分析
- 如果漏洞数量为 0，明确说明"未发现中危及以上漏洞"
- 不要编造未提供的数据；如果某字段缺失，标注为"未知"
- 保持专业、客观的语气
"""

# ── 误报验证 Prompt ──────────────────────────────────────────────
FP_VALIDATION_PROMPT = """\
你是一名安全漏洞验证专家。请分析以下漏洞信息，判断其是否为误报 (false positive)。

## 漏洞信息
- 模板 ID: {template}
- 严重程度: {severity}
- 目标 URL: {url}
- 匹配位置: {matched_at}
- 提取结果: {extracted_results}
- CVSS 评分: {cvss_score}
- 漏洞描述: {description}

## 资产上下文
- 服务器类型: {server_header}
- 技术栈: {tech_stack}
- WAF 检测: {waf_detected}
- 响应状态码: {status_code}

## 判断要求
请输出严格的 JSON 格式（不要包含 markdown 代码块或其他文本），格式如下:
{{"is_vuln": true/false, "confidence": 0.0-1.0, "reason": "判断理由"}}

字段说明:
- is_vuln: true 表示确认是真实漏洞，false 表示疑似误报
- confidence: 置信度 (0.0-1.0)，越高越确定
- reason: 用 {language} 简要说明判断依据，不超过 100 字

## 判断准则
1. 如果提取结果为空或无实质性证据，降低置信度
2. 如果目标有 WAF 防护且匹配模式模糊，可能是误报
3. 如果 CVSS 评分与严重程度不匹配，需要特别说明
4. 考虑技术栈是否真的存在该漏洞对应的组件
"""

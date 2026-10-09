# Schema 统一数据契约

本目录包含 Trusted Agent Hub 平台所有模块共享的 JSON Schema 定义。

## 文件

| 文件 | 说明 | 使用者 |
|------|------|--------|
| `agent-package.schema.json` | 统一能力包元数据 Schema | Web 提交表单、API 校验、CLI 渲染、扫描器输入 |
| `scan-report.schema.json` | 自动扫描报告 Schema | 扫描器输出、审核页渲染、评分模型输入 |
| `trust-score.schema.json` | 信任评分结果 Schema | 评分模型输出、Web 详情页、CLI 安装提示 |

## 示例

`examples/` 目录包含 4 个典型能力包的元数据示例：

- `skill-basic.json` — 高可信 Skill（代码审查）
- `mcp-server-basic.json` — 中可信 MCP Server（PostgreSQL 数据库）
- `plugin-basic.json` — 高可信 Plugin（开发者工具箱）
- `risky-skill.json` — 高风险 Skill（供扫描测试）

## 校验

```bash
# 安装 ajv-cli
npm install -g ajv-cli

# 校验示例文件
ajv validate -s agent-package.schema.json -d examples/skill-basic.json
ajv validate -s agent-package.schema.json -d examples/mcp-server-basic.json
ajv validate -s agent-package.schema.json -d examples/plugin-basic.json
ajv validate -s agent-package.schema.json -d examples/risky-skill.json
```

## 作者声明的用途（`use_cases`）

`agent-package.schema.json` 支持可选的 `use_cases` 字段，用来回答「这个包能做什么、
什么时候有用」，会公开显示在详情页的「这个包是干什么的」板块：

```json
"use_cases": [
  {
    "title": "提交 PR 前自查",
    "description": "在请求评审前先跑一遍，提前发现正确性与安全问题。"
  }
]
```

- 可选字段，最多 6 条；`title` ≤ 40 字符，`description` ≤ 160 字符，超出会被截断。
- 可以写在仓库的 `manifest.json` / `plugin.json`，也可以写在 `SKILL.md` frontmatter 里。
- 只允许声明事实性用途，不要写审核结论、内部证据或敏感路径——该字段是公开的。
- 未声明时详情页会回退到「声明的工具 + 权限用途 + 关键词」。

## 版本

### 扫描报告的版本与历史兼容性

`scan-report.schema.json` 对应扫描器 0.15.0 起的证据契约，`$id` 为
`https://trusted-agent-hub.dev/schemas/scan-report/0.15.0.schema.json`。
这是对位置值约束的收紧，不是对所有历史报告的无损兼容升级。

0.15.0 之前的报告应继续使用归档的 `scan-report.v0.14.schema.json`
（保留旧 `$id` `https://trusted-agent-hub.dev/schemas/scan-report.schema.json`），
或使用生成报告时固定的 schema 版本。消费者应按 `scanner_version` 选择契约；
版本缺失或无法识别时，不应默认按新契约重校验。不要因旧报告不满足新 pattern
而将其原有审核结论改判为通过或失败。

旧报告中的 `.`、`(unknown)`、反斜杠路径会被新契约拒绝；
看似合法的 `manifest.json` 回退名或含 `…` 的截断路径可能仍通过语法校验，
但 schema 无法证明文件存在，也不能恢复被截断的真实路径。历史快照存在时应
重新扫描生成新报告；没有快照时保留旧报告与旧契约，显示位置不可核验。
不得仅修改 `scanner_version`、替换默认文件名或补造行号来迁移。

### 0.15.0 证据契约

扫描器 0.15.0 起，finding 使用统一的证据位置契约：

- `evidence_type` 区分源码（`source`）、依赖（`dependency`）、来源策略（`registry_policy`）、文件级事实（`file`）和无源码位置的合成证据（`synthetic`）。旧报告可以省略新增字段。
- `location.file` 为仓库相对路径，统一使用 `/`；禁止绝对路径、路径穿越和控制字符。不存在证据位置时保留空 `location` 和 `evidence_missing_reason`，不生成 `SKILL.md` 或 `unknown` 位置。
- `line` / `end_line` 及可用的 `column` / `end_column` 从 1 开始，结束位置包含在区间内。列号对应脱敏前的原始内容；脱敏保持行数。
- 依赖位置保留准确的 `source_ref`（JSON Pointer fragment，如 `#/packages/node_modules~1demo`）、依赖名和版本。指针逐段转义 `~` 和 `/`，含斜杠的键与嵌套字段明确区分。`field_locations` 保存 `version`、`resolved`、`integrity` 字段位置，未声明的字段明确标记 `field_missing`。
- `source_ref` 最长 2048 字符。超过上限时省略完整标识，保留 `source_ref_sha256`、`source_ref_length` 和 `missing_reason=source_ref_too_long`，finding/advisory 同步标记 `evidence_missing_reason`。适用于主位置、出现项、字段及依赖查询来源；不得把截断文本当成有效指针。路径和正常指针不截断，展示用值仍受长度限制。
- 文件名或指针含高置信凭据格式时，使用 `sensitive_identifier` 显式标记隐藏：不输出该文件位置；指针仅保留 `source_ref_sha256`，不将替代文本当作原始指针。此类证据不投递给模型，不生成源码链接；普通的 `token=example.py` 等名称仍保持精确匹配。所有主位置和出现项的证据缺失均要求人工复核，包括免于 LLM 复核的 finding。
- 聚合的 `occurrences.items` 与 `detector_hits.location` 保留上述位置，按文件、行列和字段指针去重。同一文件里的不同依赖记录不会被合并掉。没有有效位置且没有被截断的出现项时，`occurrences` 为 `{"count": 0, "items": [], "truncated": false}`；finding 本身仍计入风险汇总。
- advisory 的 `registry_policy.occurrence_count` 统计已观察到的来源策略记录。无效路径的记录不输出空 occurrence；总数保留，`truncated=true` 明确标识省略，advisory 记录缺失原因并要求人工复核。有效路径上的源码或字段缺失保存在该 occurrence 的 `missing_reason` 中。
- `llm_context_audit` 记录原始位置、实际投递行范围、覆盖率和逐 finding 的缺失原因。`llm_context_reasons` 区分 `source_missing`、`location_unresolved`（文件存在但行号锚点缺失或无效）、`evidence_limit`（证据标识超限）、`context_budget`、`delivery_missing` 和 `provider_failure`。计数与阶段进度以全部语义候选为口径。`top_finding_files` 从规范位置统计，不读取易丢失的顶层 `file`。
- 模型上下文只包含缓存中 finding 指向的文件；按完整行限制字节预算。引用必须匹配实际投递的文件、行号和整行文本（允许首尾空白差异），缺失或部分投递不能支持自动 benign 裁决。人工预览另行允许长行前缀，并用 `partial_line=true` 和界面提示标识，不能作为完整行引用。
- 系统写入 `llm_missing_context` 的消息使用 `llm-context-messages.json` 中的稳定原因码；前端据此翻译，不匹配英文句子。provider 返回的自由文本仍按原文展示。`llm_context_reasons` 中的 `evidence_redacted` 与缺源码、预算不足分别统计。

- 其他包元数据契约版本：v0.1（扫描报告版本见上文）
- 冻结时间：第 2 周中
- 变更策略：普通字段新增保持向后兼容；值约束收紧须明确版本与历史校验方式。废弃字段保留至少一个版本过渡期。

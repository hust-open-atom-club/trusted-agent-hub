# Trusted Agent Hub 双人实习分工文档

> 基于《俱乐部开源实习课题任务书》7 项任务，采用方案二：**供给链 / 分发链纵向切分**。成员 A 负责能力包“提交—校验—扫描—审核—上线”的 Producer 链路；成员 B 负责能力包“浏览—评分—安装—更新—反馈”的 Consumer 链路。两人共同维护统一 Schema、数据库事实来源、接口契约与最终验收演示。

---

## 一、项目定位与验收主线

本项目实现一个面向 **Agent Skills、MCP Server、Plugin、Subagent、Command、Prompt** 等智能体能力单元的可信分发平台，类似内部版 Skill / MCP Hub。

平台不是普通插件市场，而是一个具备以下能力的可信能力包 Registry：

- 统一元数据规范与示例包。
- 能力包提交、版本管理、自动扫描和人工审核。
- 风险扫描报告、审核记录、审计日志和可信证据链。
- 0-100 信任度评分与可解释扣分原因。
- Web Hub 浏览、搜索、筛选、详情展示和审核管理。
- 可通过 `npx trusted-agent-hub` 运行的 CLI 安装与管理工具。
- 本地或云环境部署、测试报告和完整验收演示。

核心验收链路：

```txt
提交 Skill / MCP / Plugin 能力包
→ 元数据与结构校验
→ 自动风险扫描
→ 生成扫描报告
→ 计算信任度评分与解释
→ 审核员人工 Review
→ 审核通过并发布到 Web Hub
→ 用户搜索、筛选、查看详情
→ CLI 展示风险并安装到本地客户端
→ verify 校验安装结果
→ 管理员可下架并查看审计日志
```

---

## 二、分工原则：供给链 / 分发链纵向切分

两人不按“前端 / 后端”简单拆分，而按平台业务主线纵向拆分：

| 角色 | 链路 | 核心定位 | 核心目标 |
|---|---|---|---|
| 成员 A：供给与审核链路负责人（Producer） | 入库链路 | 负责能力包从提交到上线的完整“供给侧”闭环 | 让能力包提交得进来、校验得清楚、扫描得出来、审核得可信 |
| 成员 B：分发与消费链路负责人（Consumer） | 出库链路 | 负责能力包从平台到用户本地终端的完整“消费侧”闭环 | 让用户搜得到、看得懂、评得明白、装得安全 |

这样拆分的好处：

1. 每个人都拥有一个可演示闭环，而不是只做某一层技术栈。
2. Producer 侧与 Consumer 侧通过统一元数据、数据库、扫描报告、评分解释和状态机强制对齐。
3. 每周都能进行端到端联调，避免最后一周才集成。
4. 与任务书 7 项任务逐项对应，便于导师验收时说明责任边界。

---

## 三、推荐总体技术架构

推荐仓库结构：

```txt
trusted-agent-hub/
  apps/
    web/              # TypeScript, Next.js / React
    api/              # Python, FastAPI
    cli/              # TypeScript, npx CLI
  packages/
    schema/           # 统一元数据 JSON Schema / Zod Schema
    client-sdk/       # Web / CLI 共用 API Client
    trust-score/      # 信任评分模型
  scanners/
    risk-scanner/     # Python 风险扫描器
  examples/
    skills/
    mcp-servers/
    plugins/
    risky-packages/
  docs/
  deploy/
```

推荐技术栈：

| 模块 | 推荐技术 | 主要负责人 |
|---|---|---|
| Web 前端 | Next.js / React / TypeScript | A 审核页为主，B 门户页为主，统一应用集成 |
| CLI | TypeScript + Commander | B |
| 后端 API | FastAPI / Python | A 供给侧接口，B 分发侧接口，共同维护 OpenAPI |
| 数据库 | PostgreSQL | A + B 共同设计，按领域实现 |
| 缓存 / 队列 | Redis，可选用于扫描任务队列 | A 主导扫描任务触发，B 配合状态展示 |
| 扫描器 | Python 规则引擎 | A |
| 评分模型 | TypeScript 或 Python 模块 | B |
| 部署 | Docker Compose + Nginx | A + B，共同验收 |
| 文档 | Markdown + OpenAPI | A + B |

> 注：具体技术栈可按实际实现调整，但必须保证 Web、API、CLI、扫描器、评分模块和部署文档可独立启动与演示。

---

## 四、任务书 7 项任务与双人职责总览

| 任务书任务 | 任务主题 | 成员 A：Producer 侧职责 | 成员 B：Consumer 侧职责 | 共同产出 |
|---|---|---|---|---|
| 任务 1 | 调研 Skills / MCP 分发生态并完成需求设计 | 调研提交、审核、扫描、安全治理流程 | 调研浏览、搜索、安装、CLI、用户体验流程 | 需求分析文档、角色流程、MVP 范围 |
| 任务 2 | 元数据规范与仓库结构 | Skill / MCP / Plugin 最小提交规范、解析校验、风险标签 | 安装方式、适配客户端、展示字段、CLI 所需 manifest | `agent-package.schema.json`、示例包规范 |
| 任务 3 | Hub 后端与数据模型 | 包提交、版本管理、审核流转、扫描报告 API | 搜索过滤、详情查询、安装统计、评分查询 API | 数据库 ER 图、OpenAPI、权限模型 |
| 任务 4 | Web Hub 浏览与审核界面 | 提交表单、审核 Diff 视图、扫描报告与风险提示 | 首页列表、搜索筛选、详情页、评分趋势和安装说明 | 同一 Web 应用、统一路由与组件 |
| 任务 5 | CLI / NPX 安装与管理工具 | 提供安装包产物、审核状态和权限数据接口支持 | `search/info/install/update/uninstall/verify` 命令 | CLI 与 API 联调、安装 manifest |
| 任务 6 | 自动审核、风险扫描与信任评分 | 自动扫描流水线、规则引擎、结构化扫描报告 | 0-100 信任评分模型、评分解释、风险展示摘要 | 扫描报告 Schema、评分 JSON Schema |
| 任务 7 | 测试、部署与示范数据 | 风险样例、审核流测试、扫描规则测试 | 高可信样例、CLI 安装测试、用户手册 | 10+ 示例包、部署文档、测试报告、演示脚本 |

---

## 五、成员 A：供给与审核链路负责人（Producer）

### 5.1 核心定位

成员 A 负责能力包从提交到上线的完整“入库”链路，是平台安全可信的第一道防线。

A 的验收目标：

```txt
提交者可以上传或登记一个 Skill / MCP / Plugin 能力包，平台能解析元数据、校验结构、触发风险扫描、生成扫描报告，并让审核员基于证据完成通过、驳回或要求修改。
```

### 5.2 具体职责一：元数据规范与提交校验（任务 2）

A 主导定义能力包的提交规范与校验逻辑，包括：

- 统一能力包元数据格式：
  - 名称、版本、作者、描述。
  - 来源仓库、提交 hash、发布 tag、许可证。
  - 能力类型：`skill`、`mcp_server`、`plugin`、`subagent`、`command`、`prompt`。
  - 适配客户端：Claude Code、MCP 客户端、Cursor、OpenAI Agents SDK 等。
  - 安装方式：目录复制、配置写入、`npm`、`pip`、Docker、手动步骤。
  - 权限声明：文件系统、网络、shell、环境变量、凭据、数据库、浏览器等。
  - 依赖声明：npm、pip、Docker image、系统命令、MCP server URL。
  - 入口文件、配置模板、风险标签、审核要求。
- 定义不同包类型的最小提交规范：
  - Claude Code Skill：`SKILL.md`、附属脚本、资源文件、元数据声明。
  - Claude Code Plugin：`.claude-plugin/plugin.json`、命令、hooks、权限声明。
  - MCP Server：manifest、启动命令、transport 类型、工具列表、配置模板。
  - Subagent / Command / Prompt：入口说明、参数、适配范围、权限边界。
- 实现或设计解析与格式校验逻辑：
  - JSON / YAML / Markdown frontmatter 解析。
  - 必填字段校验。
  - SemVer 校验。
  - 来源 URL 与 hash 校验。
  - 权限声明完整性校验。
  - 包目录结构校验。

A 需要输出：

```txt
docs/metadata-spec.md
packages/schema/agent-package.schema.json
packages/schema/examples/*.json
examples/* 的最小可提交样例
```

### 5.3 具体职责二：后端 API——供给侧（任务 3）

A 负责供给侧 RESTful 接口，重点覆盖提交、版本、扫描和审核状态流转：

```txt
POST   /packages
POST   /packages/{id}/versions
POST   /versions/{id}/submit
POST   /versions/{id}/scan
GET    /versions/{id}/scan-report
GET    /versions/{id}/diff
POST   /versions/{id}/reviews
POST   /versions/{id}/request-changes
POST   /versions/{id}/approve
POST   /versions/{id}/reject
POST   /versions/{id}/publish
POST   /versions/{id}/yank
GET    /audit-logs?packageId=...
```

A 重点操作或维护的数据表：

```txt
packages
package_versions
review_records
scan_reports
scan_findings
audit_logs
```

供给侧 API 需要保证：

- 每个能力包版本有明确生命周期状态。
- 提交后自动进入扫描或等待扫描队列。
- 扫描完成后进入人工审核状态。
- 审核结论可追踪、可复查、可审计。
- 发布和下架必须写入审计日志。
- API 字段与 B 的 Web 门户、CLI、评分模型保持一致。

### 5.4 具体职责三：风险扫描流水线（任务 6）

A 主导自动化安全扫描引擎，覆盖任务书要求的主要风险：

- 结构校验：
  - 是否存在 `SKILL.md`、`.claude-plugin/plugin.json`、MCP manifest 等关键文件。
  - 入口文件是否存在。
  - 配置模板是否可解析。
- 元数据校验：
  - 名称、版本、作者、来源、许可证、入口、权限声明是否完整。
  - 适配客户端是否明确。
  - 安装方式是否可执行。
- 提示注入扫描：
  - 要求模型忽略系统 / 用户指令。
  - 要求读取凭据、泄漏环境变量或绕过安全策略。
  - 要求隐藏行为、静默执行、规避审核。
- 危险命令扫描：
  - `rm -rf`、`curl | sh`、`wget | bash`、`eval`、`exec`、`chmod 777`、`sudo`、`dd` 等危险模式。
- 网络外连扫描：
  - 未声明外部域名。
  - 远程代码下载。
  - 动态请求外部脚本。
- 凭据与环境变量风险：
  - `.env`、token、secret、password、private key。
  - `process.env` / `os.environ` / shell 环境变量读取。
  - 读取 `GITHUB_TOKEN`、`ANTHROPIC_API_KEY`、云服务密钥等敏感变量。
- 文件系统权限扫描：
  - 过宽读写范围。
  - 访问 home、SSH、浏览器配置、系统目录等敏感路径。
- 依赖风险扫描：
  - 未锁定版本。
  - 可疑 npm / pip 依赖。
  - 依赖混淆、typosquatting、install script 风险。

A 需要输出结构化扫描报告，供 B 的评分模型和前端展示消费：

```json
{
  "scanId": "scan_xxx",
  "versionId": "ver_xxx",
  "status": "passed | warning | failed",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 2
  },
  "findings": [
    {
      "ruleId": "dangerous-shell-curl-pipe-sh",
      "severity": "high",
      "category": "dangerous_shell",
      "file": "install.sh",
      "line": 12,
      "message": "检测到 curl | sh 远程脚本执行模式",
      "evidence": "curl https://example.com/install.sh | sh",
      "recommendation": "改为固定版本下载并校验 hash"
    }
  ]
}
```

### 5.5 具体职责四：Web 提交与审核界面（任务 4）

A 负责供给侧页面：

- 提交者视图：
  - 新建能力包。
  - 上传压缩包或填写 GitHub / npm / PyPI / Docker 来源。
  - 填写元数据与权限声明。
  - 查看提交校验结果。
  - 查看扫描进度与问题反馈。
- 审核员视图：
  - 待审核列表。
  - 版本 Diff 视图。
  - 元数据变更对比。
  - 权限声明对比。
  - 扫描报告详情。
  - 风险提示和规则命中证据。
  - 审核结论：通过、驳回、要求修改。
- 管理员供给侧能力：
  - 下架能力包。
  - 查看发布 / 下架审计日志。
  - 调整可信标签或风险标签。

### 5.6 A 的主要交付物

```txt
metadata-spec.md
agent-package.schema.json
提交校验逻辑
供给侧 API
扫描器规则引擎
扫描报告 JSON Schema
提交页面
审核页面
管理员审核 / 下架视图
风险样例包
审核流测试用例
安全设计说明中的扫描与审核部分
```

---

## 六、成员 B：分发与消费链路负责人（Consumer）

### 6.1 核心定位

成员 B 负责能力包从平台到用户本地终端的完整“出库”链路，是平台可用性和用户体验的最终承载者。

B 的验收目标：

```txt
用户可以在 Web Hub 搜索和理解能力包风险，并通过 npx CLI 安全安装、更新、卸载和校验一个已发布的 Skill / MCP / Plugin 能力包。
```

### 6.2 具体职责一：后端 API——分发侧（任务 3）

B 负责分发侧 RESTful 接口，重点覆盖浏览、搜索、详情、安装统计和评分查询：

```txt
GET    /packages
GET    /packages/{name}
GET    /packages/{name}/versions
GET    /packages/{name}/versions/{version}
GET    /packages/{name}/install
POST   /installs
GET    /trust-scores/{versionId}
GET    /ratings/{versionId}
POST   /comments
GET    /comments?packageId=...
GET    /stats/packages/{name}
```

B 重点操作或维护的数据表：

```txt
packages
package_versions
trust_scores
install_records
comments
ratings 或 feedback
```

分发侧 API 需要支持：

- 按类型、标签、适配客户端、评分、更新时间筛选。
- 包详情查询，包含最新发布版本和历史版本。
- 安装命令和目标客户端配置模板查询。
- 信任评分和评分解释查询。
- 安装统计写入。
- 用户评论与反馈。
- CLI 需要的机器可读安装 manifest。

### 6.3 具体职责二：信任度评分模型（任务 6）

B 主导设计 0-100 信任度评分模型，综合 A 的扫描报告和平台数据生成可解释评分。

建议评分维度：

| 指标 | 建议分值 | 数据来源 | 说明 |
|---|---:|---|---|
| 来源可信度 | 20 | 元数据、仓库信息 | 官方来源、可追溯仓库、固定 commit / tag |
| 作者信誉 | 10 | 用户与提交历史 | 历史提交质量、被驳回记录、维护活跃度 |
| 元数据完整性 | 10 | A 的提交校验 | 字段完整、许可证清晰、入口明确 |
| 权限最小化 | 15 | 权限声明、manifest | 权限是否与功能匹配，是否过宽 |
| 扫描结果 | 20 | A 的 scan_report | 高危 / 中危 / 低危 findings 扣分 |
| 人工审核 | 10 | review_records | 是否人工审核通过，是否要求修改 |
| 版本稳定性 | 5 | package_versions | SemVer、发布频率、回滚 / 下架记录 |
| 安装与反馈 | 5 | install_records、comments | 安装量、用户反馈、问题率 |
| 签名与可追溯性 | 5 | hash、签名、SBOM 可选 | hash、tag、release artifact、签名 |

评分输出必须包含解释，而不是黑盒数字：

```json
{
  "score": 72,
  "level": "medium",
  "summary": "存在高权限声明和未锁定依赖，建议安装前确认用途。",
  "deductions": [
    {
      "dimension": "permission_minimization",
      "points": -8,
      "reason": "权限声明包含 shell 执行能力"
    },
    {
      "dimension": "scan_result",
      "points": -5,
      "reason": "MCP Server 读取 GITHUB_TOKEN"
    }
  ],
  "bonuses": [
    {
      "dimension": "manual_review",
      "points": 10,
      "reason": "已通过人工审核"
    }
  ]
}
```

B 需要保证评分模型可被三处复用：

1. Web 包详情页。
2. CLI 安装前风险提示。
3. 审核员查看扫描报告时的辅助判断。

### 6.4 具体职责三：CLI / NPX 安装与管理工具（任务 5）

B 负责开发可通过 `npx` 运行的 CLI：

```bash
npx trusted-agent-hub search <keyword>
npx trusted-agent-hub info <name>
npx trusted-agent-hub install <name>
npx trusted-agent-hub update <name>
npx trusted-agent-hub uninstall <name>
npx trusted-agent-hub verify <name>
```

CLI 必须实现：

- `search`：按关键词、类型、标签、客户端筛选能力包。
- `info`：展示包详情、版本、来源、权限、扫描摘要、评分解释。
- `install`：下载或拉取包内容，写入目标客户端目录或配置。
- `update`：检查版本并更新本地安装。
- `uninstall`：移除本地安装文件和配置项。
- `verify`：校验 hash、manifest、版本和配置是否仍匹配 Hub 记录。

安装前必须展示：

```txt
包名称
类型
最新版本
来源
审核状态
信任评分
权限声明
主要风险
安装目标
将要写入或修改的本地路径
```

对于以下情况必须显式确认：

- 低信任度包。
- 未审核包。
- 高权限能力包。
- 包含 shell 执行、网络外连、凭据读取、文件系统广泛访问等风险。
- 将写入已有配置文件。

CLI 至少支持：

- Claude Code Skills 目录安装。
- Claude Code 插件目录安装。
- MCP 客户端配置文件生成或更新。
- 本地安装记录：用于后续 update、uninstall、verify。

建议本地安装记录：

```json
{
  "name": "example-skill",
  "version": "1.0.0",
  "type": "skill",
  "installedAt": "2026-07-04T00:00:00Z",
  "targetClient": "claude-code",
  "targetPath": "~/.claude/skills/example-skill",
  "manifestHash": "sha256:...",
  "sourceVersionId": "ver_xxx"
}
```

### 6.5 具体职责四：Web 门户界面（任务 4）

B 负责消费侧 Web Hub 页面：

- 首页 / 列表页：
  - 包名称、描述、类型、标签。
  - 审核状态。
  - 信任评分。
  - 更新时间。
  - 安装量。
- 搜索与筛选：
  - 关键词。
  - 类型：Skill / MCP Server / Plugin / Subagent / Command / Prompt。
  - 标签。
  - 适配客户端。
  - 审核状态。
  - 评分区间。
  - 更新时间。
- 包详情页：
  - 描述、版本、来源、许可证。
  - 安装命令。
  - 权限声明。
  - 审核状态。
  - 扫描结果摘要。
  - 信任度评分和趋势。
  - 评分解释。
  - 更新记录。
  - 评论与反馈。
- 用户风险理解体验：
  - 将 A 的 scan findings 转换为用户可理解语言。
  - 展示“为什么扣分”。
  - 展示安装前注意事项。
  - 展示适合安装 / 谨慎安装 / 不建议安装的风险等级。

### 6.6 B 的主要交付物

```txt
分发侧 API
搜索 / 详情 / 安装 manifest 接口
信任评分模型
评分解释 JSON Schema
Web Hub 首页 / 列表页 / 详情页
CLI / NPX 工具
本地安装记录与 verify 逻辑
高可信 Skill / MCP / Plugin 示例包
用户使用手册
CLI 使用文档
汇报材料中的用户流程和安装流程部分
```

---

## 七、共同负责内容与关键对接点

以下内容必须共同完成，不能完全交给某一人。

| 内容 | A 侧重点 | B 侧重点 | 必须冻结时间 |
|---|---|---|---|
| 需求分析文档 | 提交、扫描、审核、安全流程 | 浏览、搜索、安装、用户流程 | 第 1 周末 |
| 统一元数据 Schema | 结构、来源、权限、风险标签 | 安装方式、客户端适配、展示字段 | 第 2 周中 |
| 数据库 ER 图 | 提交、版本、审核、扫描、审计 | 评分、安装、评论、统计 | 第 2 周中 |
| OpenAPI 契约 | 供给侧接口 | 分发侧接口 | 第 2 周末 |
| 审核状态枚举 | 状态流转实现 | 前端展示和 CLI 风险提示 | 第 2 周末 |
| 扫描报告 Schema | 扫描结果结构 | 评分模型输入、前端摘要 | 第 2 周末 |
| 评分解释 Schema | 扫描 findings 对齐 | 分数计算和用户解释 | 第 2 周末 |
| 示例包 | 风险样例、审核测试样例 | 高可信样例、安装测试样例 | 第 6 周前完成 10+ |
| 集成测试 | 提交、扫描、审核、发布 | 搜索、详情、CLI 安装、verify | 第 7 周 |
| 最终演示 | 审核可信机制 | 用户安装体验 | 第 8 周 |

### 7.1 三个最重要的对接点

#### 对接点 1：扫描报告 JSON Schema

A 必须提前给 B 一个稳定的扫描报告格式，B 的评分模型基于 mock scan report 并行开发。

最少字段：

```txt
scanId
versionId
status
summary
findings[].ruleId
findings[].severity
findings[].category
findings[].file
findings[].line
findings[].message
findings[].evidence
findings[].recommendation
```

#### 对接点 2：审核状态枚举

A 实现状态机，B 负责展示和 CLI 风险提示。必须维护单一枚举来源。

建议状态：

```txt
draft
submitted
scanning
scan_failed
pending_review
changes_requested
approved
rejected
published
yanked
```

状态解释：

| 状态 | 含义 | 是否可被用户安装 |
|---|---|---|
| draft | 草稿 | 否 |
| submitted | 已提交 | 否 |
| scanning | 自动扫描中 | 否 |
| scan_failed | 扫描失败 | 否，除非管理员特批 |
| pending_review | 等待人工审核 | 默认否 |
| changes_requested | 要求修改 | 否 |
| approved | 审核通过但未发布 | 否 |
| rejected | 审核驳回 | 否 |
| published | 已发布 | 是 |
| yanked | 已下架 | 否，已安装用户可提示风险 |

#### 对接点 3：数据库 Schema 单一事实来源

A 和 B 都会操作 `packages`、`package_versions` 等核心表，因此必须共同维护迁移文件或 Prisma / SQLAlchemy 模型，避免各自定义一套字段。

建议核心表：

```txt
users
packages
package_versions
review_records
scan_reports
scan_findings
trust_scores
install_records
comments
audit_logs
```

---

## 八、接口契约优先原则

第 2 周结束前必须冻结 `v0.1` 契约，避免后期联调混乱。

必须包含：

```txt
agent-package.schema.json
OpenAPI 初版
数据库 ER 图
扫描报告 JSON Schema
信任评分 JSON Schema
审核状态枚举
CLI 输出格式
安装 manifest 格式
Web 路由与页面清单
```

并行开发方式：

- A 可以先用 mock metadata、mock scan report 开发提交和审核页面。
- B 可以先用 mock package、mock trust score 开发 Web 门户和 CLI。
- A 的扫描器先输出固定 JSON 文件，B 的评分模型先读取该 JSON。
- B 的 CLI 先从 mock API 或本地 JSON 获取包详情，随后切换真实 API。
- 双方每周至少联调一次完整链路。

---

## 九、8 周排期与阶段目标

| 周次 | 阶段目标 | A：Producer 侧产出 | B：Consumer 侧产出 | 集成检查点 |
|---|---|---|---|---|
| 第 1 周 | 调研与需求设计 | 提交 / 审核 / 扫描调研，风险清单 | 浏览 / CLI / 安装调研，用户流程 | 需求文档、角色流程、MVP 范围 |
| 第 2 周 | 元数据与接口契约 | 元数据 Schema、扫描报告 Schema、审核状态机 | 评分 Schema、CLI 输出格式、安装 manifest | Web / CLI 可读取 mock manifest |
| 第 3 周 | 后端与 Web 骨架 | 包提交、版本 API、提交页骨架 | 搜索 / 详情 API、首页 / 详情页骨架 | Web 能调用真实包列表 API |
| 第 4 周 | 提交与审核闭环 | 提交校验、扫描触发、审核页面、审计日志初版 | 详情页展示审核状态和扫描摘要 | 提交后能生成扫描报告 |
| 第 5 周 | 扫描与评分 | 风险规则、扫描报告详情、风险样例 | 评分模型、评分解释、评分展示 | 详情页能展示真实评分解释 |
| 第 6 周 | CLI 安装工具 | 提供安装包产物、发布状态、权限数据接口 | CLI search/info/install/update/uninstall/verify | CLI 能安装一个已发布示例包 |
| 第 7 周 | 示例、测试、部署 | 风险样例、扫描规则测试、审核流测试 | 高可信样例、CLI 安装测试、用户手册 | Docker 一键启动完整链路 |
| 第 8 周 | 验收打磨 | 安全设计说明、审核演示脚本 | CLI 文档、用户流程 PPT / 博客 | 完整验收演示彩排 |

---

## 十、120 小时工时分配

两人总计 120 小时，按每人约 60 小时规划。

### 10.1 按任务模块分配

| 模块 | 总工时 | A 工时 | B 工时 | 说明 |
|---|---:|---:|---:|---|
| 调研与需求设计 | 10h | 5h | 5h | 任务 1，共同完成 |
| 元数据规范与接口契约 | 12h | 7h | 5h | A 主 Schema 与校验，B 主安装 manifest 与展示字段 |
| 数据库与后端 API | 18h | 9h | 9h | A 供给侧，B 分发侧 |
| 认证授权与权限控制 | 6h | 3h | 3h | 角色：普通用户、提交者、审核员、管理员 |
| 自动扫描流水线 | 12h | 12h | 0h | A 主导，B 提供评分所需字段反馈 |
| 信任评分模型 | 10h | 2h | 8h | B 主导，A 提供扫描报告输入 |
| Web 页面 | 16h | 8h | 8h | A 提交 / 审核，B 首页 / 详情 |
| CLI / NPX 工具 | 12h | 2h | 10h | B 主导，A 提供安装数据接口 |
| 示例能力包 | 8h | 4h | 4h | A 风险样例，B 高可信 / 安装样例 |
| 测试与部署 | 10h | 5h | 5h | A 审核 / 扫描测试，B CLI / Web / 部署测试 |
| 文档与汇报材料 | 6h | 3h | 3h | 按负责链路分别撰写 |
| **合计** | **120h** | **60h** | **60h** | 双人均衡 |

### 10.2 按任务书 7 项任务映射

| 任务书任务 | A 预计工时 | B 预计工时 | 合计 |
|---|---:|---:|---:|
| 任务 1：调研与需求设计 | 5h | 5h | 10h |
| 任务 2：元数据规范与仓库结构 | 7h | 5h | 12h |
| 任务 3：后端与数据模型 | 12h | 12h | 24h |
| 任务 4：Web Hub 浏览与审核界面 | 8h | 8h | 16h |
| 任务 5：CLI / NPX 工具 | 2h | 10h | 12h |
| 任务 6：自动审核、扫描与评分 | 14h | 10h | 24h |
| 任务 7：测试、部署与示范数据 | 12h | 10h | 22h |
| **合计** | **60h** | **60h** | **120h** |

---

## 十一、每周集成目标

两人项目最怕最后一周才集成，因此每周都需要有可演示目标。

| 周次 | 必须可演示内容 | 验收方式 |
|---|---|---|
| 第 2 周 | Web / CLI 可读取 mock manifest | 本地 JSON 或 mock API 展示包列表和详情 |
| 第 3 周 | Web 能调用真实包列表 API | 首页列表从后端读取数据 |
| 第 4 周 | 提交后能生成扫描报告 | 上传 / 登记示例包后生成 scan_report |
| 第 5 周 | 详情页能展示真实评分解释 | B 评分模型读取 A 扫描报告并生成解释 |
| 第 6 周 | CLI 能安装一个已发布示例包 | `npx trusted-agent-hub install <name>` 写入本地目录 |
| 第 7 周 | Docker 一键启动完整链路 | `docker compose up` 后可完成提交、审核、安装 |
| 第 8 周 | 完整验收演示彩排 | 按任务书展示流程完整走通 |

---

## 十二、示例包建设计划

示例包不要等到第 7 周才开始，应从第 2 周开始逐步建设。

| 阶段 | 示例包目标 | A 负责 | B 负责 |
|---|---|---|---|
| 第 2 周 | 先做 3 个最小样例 | 1 个风险样例 | 2 个高可信样例 |
| 第 4 周 | 扩展到 6 个，用于审核流测试 | 3 个风险 / 待确认样例 | 3 个正常样例 |
| 第 6 周 | 扩展到 10 个，用于 CLI 安装测试 | 至少 3 个风险样例 | 至少 7 个可安装样例 |
| 第 7 周 | 补充文档、风险说明和演示数据 | 风险说明和扫描命中说明 | 安装说明和用户手册 |

建议不少于 10 个：

| 类型 | 数量 | 主负责人 | 说明 |
|---|---:|---|---|
| 高可信 Skill | 4 | B | 文档总结、代码审查、测试生成、API 文档生成 |
| MCP Server | 3 | B 主，A 配合风险声明 | 文件只读、数据库只读、GitHub 查询 |
| Plugin / Command / Prompt | 1-2 | B | 用于展示多类型能力包 |
| 风险样例 | 3 | A | 危险 shell、读取凭据、提示注入 |

---

## 十三、副 Owner 机制

为避免某个人卡住后另一个人完全接不上，每个模块都设置副 owner。

| 模块 | 主 owner | 副 owner | 副 owner 职责 |
|---|---|---|---|
| 元数据规范 | A | B | 验证安装字段、CLI 所需字段是否足够 |
| 扫描报告 Schema | A | B | 验证评分模型能否消费 |
| 信任评分模型 | B | A | 验证扫描 findings 到评分扣分的映射 |
| 供给侧 API | A | B | 验证 Web 门户和 CLI 是否能读取状态 |
| 分发侧 API | B | A | 验证发布状态、审核信息、权限字段是否准确 |
| Web 提交 / 审核页 | A | B | 验证评分和用户展示一致性 |
| Web 首页 / 详情页 | B | A | 验证风险展示和扫描证据准确性 |
| CLI | B | A | 验证安装包结构、权限提示、审核状态 |
| 扫描规则 | A | B | 验证用户可理解的风险摘要 |
| 示例包 | A + B | 互为副 owner | 互相审核样例质量和可安装性 |
| 部署 | A + B | 互为副 owner | 双方都必须能按 README 启动项目 |

副 owner 不一定写核心代码，但必须能看懂、测试并提出问题。

---

## 十四、MVP 红线与可延后项

### 14.1 必须完成

```txt
Web 浏览、搜索、详情、提交、审核、下架
后端 API、数据库、认证授权
统一元数据 Schema
自动扫描报告
信任评分和解释
CLI 搜索、详情、安装、更新、卸载、校验
不少于 10 个示范能力包
Docker 本地部署
需求、规范、接口、部署、测试、安全、用户文档
完整验收演示
```

### 14.2 可以延后

```txt
微信小程序
Redis 三主三从真实部署
真实软件签名系统
复杂 SBOM
AI 自动审核总结
云端生产级高可用
多租户企业权限体系
企业级私有 Marketplace 权限隔离
完整包签名与透明日志系统
```

最高优先级验收链路：

```txt
提交 → 扫描 → 审核 → 发布 → Web 查看 → CLI 安装 → verify 校验
```

只要这条链路稳定，项目就具备验收说服力。

---

## 十五、最终交付物

### 15.1 代码交付

```txt
后端 API
Web 前端
CLI 工具
元数据 Schema
扫描规则
信任评分模块
示例能力包
Docker 部署配置
```

### 15.2 文档交付

```txt
需求分析文档
元数据规范
接口文档 / OpenAPI
部署文档
用户使用手册
CLI 使用文档
测试报告
安全设计说明
课题总结 PPT 或技术博客
```

### 15.3 演示交付

```txt
提交一个 Skill / MCP 包
→ 自动结构和元数据校验
→ 自动扫描
→ 生成扫描报告
→ 计算信任评分
→ 审核员 Review
→ 审核通过并发布
→ Web 端搜索查看
→ npx CLI 安装
→ verify 校验
→ 管理员查看审计日志或下架
```

---

## 十六、最终建议

这版分工的核心是：

- **A 负责 Producer 闭环**：元数据规范、提交校验、供给侧 API、风险扫描、审核页面、可信证据链。
- **B 负责 Consumer 闭环**：分发侧 API、信任评分、Web 门户、CLI 安装、安装记录、用户文档。

两个人通过以下单一事实来源连接：

```txt
agent-package.schema.json
OpenAPI
数据库 ER 图
扫描报告 JSON Schema
信任评分 JSON Schema
审核状态枚举
安装 manifest 格式
```

只要第 2 周前冻结这些契约，A 和 B 就可以基于 mock 数据并行开发，后续逐步替换为真实 API 和真实扫描结果。最终验收时，可以清晰说明：A 保证“能力包可信入库”，B 保证“能力包安全出库”，共同完成一个可治理、可追溯、可落地的 Trusted Agent Hub。

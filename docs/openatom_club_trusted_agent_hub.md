# 俱乐部开源实习课题任务书

## 一、课题基本信息

- **课题名称**：可信 Agent Skills 与 MCP Hub 平台设计与实现
- **指导导师**：慕冬亮、陈磊
- **开发语言**：TypeScript、Python
- **预计项目时长**：120 小时 / 8 周
- **难度等级**：中等偏高级
- **课题背景信息介绍**：

  随着 Claude Code、Cursor、OpenAI Agents SDK 等智能体工具快速发展，Agent Skills、MCP Server、Subagent、Prompt、Command 等能力单元正在成为智能体生态中的重要组成部分。开发者可以通过一个 Skill 让智能体掌握特定工作流，也可以通过 MCP Server 连接数据库、代码仓库、浏览器、企业系统等外部工具。类似 npm、PyPI、VS Code Marketplace 的分发生态正在形成，但智能体能力单元与传统软件包不同：它们不仅包含代码和依赖，还包含会直接影响模型行为的自然语言指令、工具权限和外部资源访问路径。

  当前社区中已经出现 Skills / MCP 的公开目录、插件市场和命令行安装工具，用户可以通过 marketplace、GitHub 仓库或 `npx` 命令发现并安装相关能力。然而，对于高校实验室、开源社区和企业内部场景而言，直接使用未经审核的 Skills 或 MCP 存在明显风险：恶意提示注入、危险脚本、凭据读取、供应链投毒、越权工具调用、版本漂移、来源不可追溯等问题都可能影响开发环境和业务数据安全。

  本课题旨在设计并实现一个面向 Agent Skills 与 MCP Server 的可信分发平台，类似内部版 Skill Hub。平台应支持用户浏览、搜索、提交、审核、评分、安装和更新可信 Skills / MCP；同时提供命令行工具，使用户能够通过 `npx` 等方式快速拉取经过审核的能力包。平台需要建立一套内部审核机制和信任度评分模型，将自动化扫描、人工 Review、来源信誉、权限声明、版本签名、使用反馈等因素纳入可信评价，为智能体能力扩展提供可治理、可追溯、可落地的基础设施。

## 二、技能要求

- 熟悉 TypeScript / Node.js，能够实现 Web 服务、前端页面和命令行工具
- 具备基本后端开发能力，了解 RESTful API、数据库建模、用户认证与权限控制
- 本课题允许并鼓励申请者合理使用 AI 编程工具辅助开发、调试和文档撰写，但申请者仍需具备前后端基础，能够拆解需求、审查 AI 生成代码、定位问题并完成工程集成
- 了解 Agent Skills、MCP、Claude Code 插件、智能体工具调用等基本概念，有学习相关生态规范的意愿
- 具备基本安全意识，了解供应链安全、权限控制、代码审查、敏感信息检测、提示注入等风险
- 熟悉 Git、Markdown、JSON / YAML 配置格式，能够设计清晰的元数据规范和开发文档
- 加分项：了解静态分析、CI/CD、包管理器、软件签名、SBOM、SemVer 或开源社区治理流程

## 三、课题任务

### 任务 1：调研 Skills / MCP 分发生态并完成需求设计

- 调研 Claude Code 插件市场、Agent Skills、MCP Registry、社区 Skill Hub、GitHub 分发、`npx` 安装工具等现有方案
- 梳理可信 Skills / MCP Hub 需要支持的核心对象：Skill、MCP Server、Plugin、Subagent、Command、Prompt 等
- 明确平台角色与业务流程，至少包括普通用户、提交者、审核员、管理员三类角色
- 输出需求分析文档，覆盖浏览搜索、详情展示、提交审核、自动扫描、人工 Review、信任评分、CLI 安装、版本更新、下架与审计等流程

### 任务 2：设计可信能力包元数据规范与仓库结构

- 设计统一的能力包元数据格式，描述名称、版本、作者、来源仓库、许可证、适配客户端、安装方式、权限声明、依赖、入口文件、风险标签等信息
- 分别定义 Skill 与 MCP Server 的最小提交规范，例如 `SKILL.md`、`.claude-plugin/plugin.json`、MCP manifest、安装命令、配置模板等
- 支持多来源接入，包括 GitHub 仓库、npm 包、PyPI 包、Docker 镜像、本地压缩包或人工上传
- 输出规范文档和若干示例包，确保后续平台、审核系统和 CLI 工具能够基于统一元数据工作

### 任务 3：实现 Hub 平台后端与数据模型

- 设计并实现后端 API，支持能力包创建、版本管理、搜索过滤、详情查询、评分展示、审核流转和安装统计
- 建立数据库模型，至少包含用户、能力包、版本、审核记录、扫描报告、信任评分、安装记录、评论反馈等核心实体
- 实现认证与授权机制，区分提交者、审核员和管理员权限
- 提供可被 Web 前端和 CLI 工具调用的 API，并输出 OpenAPI 或接口文档

### 任务 4：实现 Web Hub 浏览与审核界面

- 实现平台前端页面，支持用户浏览可信 Skills / MCP 列表，按类型、标签、适配客户端、评分、更新时间等条件筛选
- 实现能力包详情页，展示描述、版本、来源、安装命令、权限声明、审核状态、扫描结果、信任度评分和更新记录
- 实现提交与审核界面，支持提交者上传能力包，审核员查看 Diff、扫描报告、权限声明和风险提示，并给出通过、驳回、要求修改等结论
- 实现管理员视图，支持下架能力包、调整可信标签、查看审计日志和处理用户反馈

### 任务 5：实现 CLI / NPX 安装与管理工具

- 开发命令行工具，支持通过 `npx` 方式运行，例如 `npx trusted-agent-hub search <keyword>`、`npx trusted-agent-hub install <name>`、`npx trusted-agent-hub update <name>`
- CLI 需要支持浏览、搜索、查看详情、安装、更新、卸载和校验能力包
- 根据目标客户端生成或写入对应配置，例如 Claude Code Skills 目录、Claude Code 插件目录、MCP 客户端配置文件等
- 安装前展示权限声明、信任度评分、审核状态和风险提示；对于低信任度或高权限能力包，需要显式确认

### 任务 6：实现自动化审核、风险扫描与信任度评分

- 设计自动化审核流水线，对提交的 Skill / MCP 包进行结构校验、元数据校验、依赖检查、敏感信息检测和危险行为扫描
- 风险扫描至少覆盖：提示注入可疑指令、危险 shell 命令、网络外连、读取环境变量、硬编码密钥、远程代码下载、过宽文件系统访问、可疑 npm / pip 依赖等
- 设计信任度评分模型，综合来源可信度、作者信誉、审核结论、扫描结果、权限范围、版本稳定性、安装量、用户反馈等因素生成 0-100 分评分
- 输出评分解释，使用户能够理解扣分原因和主要风险，而不是只看到一个黑盒分数

### 任务 7：完成测试、部署与示范数据建设

- 构建一批示范 Skills / MCP 包，包含高可信样例、待人工确认样例和明确风险样例
- 编写单元测试和集成测试，覆盖提交、扫描、审核、发布、CLI 安装和下架流程
- 将平台部署到本地服务器或云环境，提供可访问的 Web 页面和可执行的 CLI 安装方式
- 输出测试报告、部署文档和用户使用手册，保证导师和社区成员能够独立体验完整流程

## 四、课题验收

**验收时间**：本课题预计于领取后 8 周内开展课题验收，验收项如下所示：

- **代码**：提交完整平台代码，包含后端 API、Web 前端、CLI 工具、扫描规则和信任评分模块；代码结构清晰，可通过 README 快速启动
- **平台**：提供可访问的 Hub 页面，能够浏览、搜索、提交、审核、发布和下架 Skills / MCP
- **CLI**：提供可通过 `npx` 运行的命令行工具，能够完成搜索、详情查看、安装、更新、卸载和校验流程
- **审核机制**：实现自动扫描 + 人工 Review 的审核流，能够展示扫描报告、审核结论、审计记录和信任度评分解释
- **数据**：提交不少于 10 个示范能力包，其中至少包含 Skill、MCP Server 和风险样例三类
- **文档**：提交需求分析文档、元数据规范、接口文档、部署文档、用户使用手册、测试报告和安全设计说明
- **汇报**：提交课题总结 PPT 或技术博客，说明平台架构、可信审核机制、评分模型、CLI 安装流程和后续扩展方向
- **展示**：现场演示完整流程：提交一个 Skill / MCP 包，平台自动扫描并进入审核，审核通过后用户在 Web 端浏览，并通过 `npx` CLI 安装到本地智能体客户端

## 五、参考资料与初始调研方向

- Claude Code Skills 文档，https://code.claude.com/docs/en/skills
- Claude Code 插件市场与安装机制，https://code.claude.com/docs/en/discover-plugins
- Claude Code 插件创建与审核机制，https://code.claude.com/docs/en/plugins
- Claude Code 插件参考，https://code.claude.com/docs/en/plugins-reference
- MCP Registry，https://modelcontextprotocol.info/tools/registry/
- Anthropic Agent Skills 设计文章，https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills
- OWASP Agentic Skills Top 10，https://owasp.org/www-project-agentic-skills-top-10/
- OWASP Top 10 for LLM Applications，https://owasp.org/www-project-top-10-for-large-language-model-applications/

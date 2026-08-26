# TrustedAgentHub — 可信 Agent Skills 与 MCP Hub 平台

面向智能体生态的可信能力分发平台。支持 Agent Skills、MCP Server、Plugin、Subagent 等能力单元的浏览、搜索、提交、安全扫描、人工审核、信任评分和 CLI 安装。

---

## 项目架构

```
TrustedAgentHub/
├── apps/
│   ├── api/              FastAPI 后端 (Python 3.12, 端口 8000)
│   ├── cli/              CLI 安装工具 (TypeScript/Node.js, Commander.js)
│   └── web/              Web 前端 (Next.js 14 App Router + React 18)
├── scanners/
│   └── risk_scanner/     安全扫描器 — 19 条规则 + LLM 审查
├── packages/
│   ├── schema/           统一数据契约 (JSON Schema) + 元数据提取器
│   └── trust-score/      信任评分引擎 — 3 层 9 步漏斗模型
├── examples/             示范能力包 + 真实能力包 (Skill/MCP/Plugin/风险样例)
├── scripts/              数据库种子脚本
├── deploy/               部署配置
├── docker-compose.yml
```

---

## 核心功能

### Hub 平台 (Web + API)

- **包浏览与搜索**：按类型、分类、评分、更新时间筛选
- **提交与扫描**：输入 GitHub URL → 自动 git clone → 19 条规则安全扫描 → 信任评分 → 提交审核
- **审核流程**：审核员查看 Diff、扫描报告、风险提示 → 通过/驳回/要求修改
- **管理面板**：下架、手动评级覆盖、审计日志查询
- **中英双语**：i18next 国际化，导航栏 + 所有管理页面全覆盖

### 安全扫描器 (19 条规则 + LLM 审查)

| 规则 ID | 检测内容 |
|---------|----------|
| SR-001 | 提示注入 + 反拒绝机制 |
| SR-002 | 危险 Shell 命令 |
| SR-003 | 凭据访问 (SSH/AWS/浏览器) |
| SR-004 | 硬编码密钥 |
| SR-005 | 远程代码执行 (正则 + AST 双引擎) |
| SR-006 | 过度权限 + 自主决策 |
| SR-007 | 网络访问无白名单 |
| SR-008 | 供应链风险 (Typosquatting + CVE) |
| SR-009 | 来源完整性 |
| SR-010 | 元数据质量 |
| SR-011 | 输出处理风险 |
| SR-012 | 系统提示泄漏 |
| SR-013 | 记忆投毒 |
| SR-014 | SSRF (含防御上下文过滤) |
| SR-015 | Agent 窥探 |
| SR-016 | 工具滥用 |
| SR-017 | MCP 安全 (隐藏工具 + HTTP 明文 + 工具描述投毒/语义漂移) |
| SR-018 | Plugin 安全 (内联 MCP + Hook 注入) |
| SR-019 | Subagent 安全 (自主模式 + 危险工具) |

另有本地语义检测（`mcp_security.py` + fastembed 嵌入模型）：SR-017 对 MCP 工具描述与权限声明做语义对比，检测"描述投毒"；未安装模型时自动降级为纯规则模式。

### 信任评分引擎

3 层 9 步漏斗模型，输出 0–100 分 + A–E 等级：

| Grade | 分数 | 安装建议 |
|-------|------|----------|
| A | ≥80 | 自动安装 |
| B | ≥60 | 展示权限声明后安装 |
| C | ≥40 | 展示扫描摘要 + 确认 |
| D | ≥20 | 强烈不建议，双重确认 |
| E | <20 | 禁止安装 |

9 个评分维度：来源可信度、作者信誉、元数据完整性、权限最小化、扫描结果、人工审核、版本稳定性、用户反馈、签名可验证性。

### CLI 安装工具

```bash
npx tah search <keyword>
npx tah install <name>
npx tah update <name>
npx tah verify <name>
```

支持 Claude Code / Cursor / VS Code 等多种客户端，安装前展示权限声明和信任评分。

插件类能力包安装到 `~/.claude/skills/<name>/`（与技能共用目录）。只要包内含
`.claude-plugin/plugin.json`，Claude Code 就会自动加载为
`<name>@skills-dir` 插件，无需手工注册 marketplace；安装后新开会话即可在
`/plugin` 中看到并启用。

---

## 快速开始

### 环境要求

- Python 3.12+
- Node.js 18+
- PostgreSQL 16+
- Git

### 安装与配置

```bash
# 克隆仓库
git clone <repo-url>
cd TrustedAgentHub

# Python 依赖 (pyproject.toml 位于 apps/api)
cd apps/api
pip install -e ".[dev]"
cd ../..

# 配置数据库连接 (apps/api/.env)
    echo "DATABASE_URL=postgresql://postgres:password@127.0.0.1:5432/trusted_agent_hub" > apps/api/.env

# 数据库迁移
cd apps/api
alembic upgrade head

# 导入种子数据
python -m src.scripts.seed_producer
```

### 数据库迁移策略

项目当前仍处于预发布阶段，数据库迁移已整理为单一初始 schema。新建数据库执行：

```bash
alembic upgrade head
```

本次整理不兼容此前的旧 revision 链。已有本地数据库如无需要保留的数据，建议删除后
重新创建；如果包含重要数据，应先备份，再按当前 schema 迁移数据。不要仅使用
`alembic stamp` 跳过 schema 创建，除非数据库结构已经与当前初始 schema 完全一致。

评分模型版本升级后，应在发布新 API 镜像时执行一次幂等回填：

```bash
cd apps/api
python -m src.scripts.backfill_trust_scores --batch-size 100 --max-attempts 3
```

命令会跳过已使用当前模型的版本，逐批记录扫描、更新、跳过和失败数量；
单个版本失败会自动重试，最终仍有失败时以非零状态退出。修复故障后可直接重跑，
已完成版本不会重复计算。

### 启动服务

```bash
# 启动后端 (端口 8000)
cd apps/api
python run.py

# 启动前端 (端口 3000)
cd apps/web
npm install && npm run dev

# Docker Compose 一键启动
docker compose up -d
```

启动后访问：
- **Web 前端**：http://localhost:3000
- **Swagger API 文档**：http://127.0.0.1:8000/docs

## 真实能力包

`examples/real-world/` 内置了来自开源社区的**真实能力包**（Apache-2.0）：

| 包名 | 类型 | 上游来源 |
|---|---|---|
| `anthropic-skill-creator` | Skill | [anthropics/skills](https://github.com/anthropics/skills) |
| `anthropic-mcp-builder` | Skill | [anthropics/skills](https://github.com/anthropics/skills) |
| `anthropic-algorithmic-art` | Skill | [anthropics/skills](https://github.com/anthropics/skills) |
| `anthropic-brand-guidelines` | Skill | [anthropics/skills](https://github.com/anthropics/skills) |
| `anthropic-webapp-testing` | Skill | [anthropics/skills](https://github.com/anthropics/skills) |
| `anthropic-theme-factory` | Skill | [anthropics/skills](https://github.com/anthropics/skills) |
| `anthropic-frontend-design` | Skill | [anthropics/skills](https://github.com/anthropics/skills) |
| `mcp-server-filesystem` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) |
| `mcp-server-memory` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) |
| `mcp-server-sequential-thinking` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) |
| `mcp-server-everything` | MCP Server | [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) |
| `anthropic-skills-plugin` | Plugin | [anthropics/skills](https://github.com/anthropics/skills) |
| `anthropic-web-skills-plugin` | Plugin | [anthropics/skills](https://github.com/anthropics/skills) |
| `superpowers` | Plugin | [obra/superpowers](https://github.com/obra/superpowers) |

每个包都带有符合 `agent-package.schema.json` 的 `manifest.json`、来源 commit 和许可证说明，可直接提交、扫描、审核、发布和安装。详见 `examples/real-world/README.md`。

---

## 运行测试

```bash
# 全量测试
cd apps/api
python -m pytest tests/ -v

# 扫描器规则测试 (100 tests)
python -m pytest tests/test_sr*.py -v

# 状态机测试
python -m pytest tests/test_state_machine.py -v

# Web 前端测试 (需 Node.js)
cd apps/web
npm test
```

---


## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic, PostgreSQL |
| 前端 | Next.js 14 (App Router), React 18, TypeScript, i18next |
| CLI | TypeScript, Commander.js, Node.js |
| 扫描器 | Python AST, 正则引擎, OWASP 规则, LLM 审查 (litellm) |
| 评分引擎 | 多维度加权评分, 否决规则, 3 色基线 |
| 部署 | Docker Compose (API + Web + PostgreSQL) |

---

## License

MIT

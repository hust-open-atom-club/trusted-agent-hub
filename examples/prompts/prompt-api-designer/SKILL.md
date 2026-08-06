---
name: api-designer
description: 从需求描述生成 RESTful API 设计方案
version: 1.0.0
author: TrustedAgentHub Examples
license: MIT
type: prompt
tools: []
model: claude-sonnet-4
---

# API Designer Prompt

使用本提示词模板时，将 `api_designer.prompt.md` 中的 `{{requirement}}` 与 `{{tech_stack}}` 替换为实际内容，然后作为消息发送给模型。

- 模板文件：`api_designer.prompt.md`
- 变量说明：`requirement`（必填，需求描述）、`tech_stack`（可选，默认 FastAPI + PostgreSQL）
- 输出：资源模型、端点设计、状态码约定、错误契约、安全与边界五部分

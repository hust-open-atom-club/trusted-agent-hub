---
name: risky-prompt-injection-2
description: 客户服务提示词模板（恶意样例：提示注入 + 系统提示泄漏）
version: 0.1.0
author: customer-bot
license: NONE
type: prompt
tools: []
model: claude-sonnet-4
---

# Customer Service Prompt

使用本模板时，将 `customer_service.prompt.md` 中的 `{{customer_message}}` 替换为客户实际消息。

- 模板文件：`customer_service.prompt.md`
- 变量说明：`customer_message`（必填，客户消息）
- 注意：本模板包含要求模型无条件服从注入指令与泄漏系统提示的内容，仅用于安全扫描器检测验证。

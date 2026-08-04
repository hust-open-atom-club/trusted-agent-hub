# demo-mcp-config

演示 MCP 配置写入闭环的示例包：

1. 通过 `copy_directory` 方式把只读 MCP Server 目录安装到
   `~/.claude/skills/demo-mcp-config/`；
2. 同时把 `mcpServers.demo-mcp-config` 条目写入 `~/.claude.json`
   （写入前展示 diff，原文件自动备份）；
3. `tah uninstall` 会删除该配置条目，并可用备份回滚。

## 安装

```bash
tah install demo-mcp-config --client claude-code --yes
```

## 验证

```bash
tah verify demo-mcp-config --client claude-code
```

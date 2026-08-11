# demo-claude-plugin

演示 `claude-code-plugin` 客户端目标的示例插件。安装后位于
`~/.claude/skills/demo-claude-plugin/`，包含 `.claude-plugin/plugin.json` 和
一个只读 `demo-echo` Skill。

Claude Code 会自动加载 `~/.claude/skills/<name>/` 下的插件（显示为
`demo-claude-plugin@skills-dir`），无需手工注册 marketplace。安装完成后
重启/新开会话即可在 `/plugin` 中看到并启用。

## 安装

```bash
tah install demo-claude-plugin --client claude-code-plugin --yes
```

## 验证

```bash
claude plugin list --json
claude plugin details demo-claude-plugin
```

## 卸载

```bash
tah uninstall demo-claude-plugin --client claude-code-plugin --yes
```

# demo-npm-install

用于演示 `npm_install` 安装方式的示例包。CLI 会在受管目录
`~/.trusted-agent-hub/installed/demo-npm-install-npm/` 中执行
`npm install is-number@7.0.0`，不会触碰系统全局路径。

## 安装

```bash
tah install demo-npm-install --client claude-code --yes
```

## 说明

- 目标 npm 包：`is-number@7.0.0`（极小的公开包，无依赖）
- 安装方式需要显式确认（`--yes` 或交互确认）
- 卸载会删除受管目录并移除本地安装记录

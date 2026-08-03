# demo-pip-install

用于演示 `pip_install` 安装方式的示例包。CLI 会在受管目录
`~/.trusted-agent-hub/installed/demo-pip-install-pip/` 中执行
`python -m pip install --target ... idna==3.7`。

## 安装

```bash
tah install demo-pip-install --client claude-code --yes
```

## 说明

- 目标 PyPI 包：`idna==3.7`（极小的纯 Python 包）
- 安装方式需要显式确认（`--yes` 或交互确认）
- 卸载会删除受管目录并移除本地安装记录

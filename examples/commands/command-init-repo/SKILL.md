---
name: init-repo
description: 创建规范的 Git 仓库初始文件（README、.gitignore、LICENSE、CHANGELOG）
version: 1.0.0
author: TrustedAgentHub Examples
license: MIT
type: command
tools:
  - Write
model: claude-sonnet-4
---

# Init Repo Command

用户输入 `/init-repo <name> [language]` 时，在当前项目目录生成一套规范的 Git 仓库初始文件。

## 执行步骤

1. **README.md** — 使用仓库名称生成标题，写项目简介占位、快速开始、License 说明三节。
2. **.gitignore** — 根据 language 参数选择模板：
   - `python`：`.venv/`、`__pycache__/`、`*.pyc`、`.pytest_cache/`
   - `node`：`node_modules/`、`dist/`、`.next/`
   - 其他：通用忽略项（`.DS_Store`、`*.log`）
3. **LICENSE** — 写入 MIT 许可证模板，版权年份为当前年份。
4. **CHANGELOG.md** — 创建 `## [Unreleased]` 占位章节。

## 约束

- 仅创建上述四个文件，不修改已有文件。
- 若目标文件已存在，跳过并在结果中提示用户。
- 不执行任何 git 命令（init/commit 由用户手动执行）。

## 输出

完成时列出创建的文件清单，提示用户下一步（如 `git init`）。

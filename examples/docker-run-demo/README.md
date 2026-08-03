# demo-docker-run

用于演示 `docker_run` 安装方式的示例包。CLI 会执行 `docker pull nginx:alpine`，
然后在受管目录 `~/.trusted-agent-hub/installed/demo-docker-run-docker/` 写入
`docker-run.json` 和 `run-command.txt`。

## 安装

```bash
tah install demo-docker-run --client claude-code --yes
```

## 安全说明

- 只拉取镜像并生成配置，**不会自动启动容器**
- 启动命令由用户审阅后自行执行
- 卸载会删除受管目录（镜像本身保留在本地 Docker 中）

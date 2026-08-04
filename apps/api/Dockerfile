# TrustedAgentHub — API 后端 Dockerfile
# 构建上下文 = 项目根目录: docker compose build api
FROM python:3.11-slim

WORKDIR /app

# 替换为国内镜像源（解决 deb.debian.org 502 问题）
RUN sed -i 's|http://deb.debian.org|https://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's|http://security.debian.org|https://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc git \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖（使用阿里云 pypi 镜像）
COPY apps/api/pyproject.toml .
RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ -e ".[dev]" && \
    pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ alembic && \
    pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ psycopg2-binary jsonschema numpy

# 复制源码和共享包
COPY apps/api/alembic.ini .
COPY apps/api/src/ src/
COPY apps/api/tests/ tests/
COPY packages/ /packages/
COPY scanners/ /scanners/

# 将共享包加入 Python 路径（/scanners/、/packages/ 作为顶层包可 import）
ENV PYTHONPATH=/packages:/

# 暴露端口
EXPOSE 8000

# 启动：先跑数据库迁移，再启动 uvicorn
CMD ["sh", "-c", "alembic upgrade head && uvicorn src.main:app --host 0.0.0.0 --port 8000"]

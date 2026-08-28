# TrustedAgentHub — API 后端 Dockerfile
# 构建上下文 = 项目根目录: docker compose build api
FROM python:3.12-slim

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

# 可选：本地语义模型（SR-017 fastembed + MiniLM-L12 嵌入模型）
# 启用方式：docker compose build --build-arg ENABLE_SEMANTIC_MODEL=true
#   或用 deploy/build.ps1 交互式选择
# 启用后：构建时预下载模型 (~241MB) 到镜像内缓存，镜像约增大 300MB，语义检测完全离线可用
# 未启用：镜像更小，SR-017 语义检测自动降级为纯规则模式（默认）
ARG ENABLE_SEMANTIC_MODEL=false
RUN if [ "$ENABLE_SEMANTIC_MODEL" = "true" ]; then \
        apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/* && \
        pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ fastembed && \
        HF_ENDPOINT=https://hf-mirror.com python -c "from fastembed import TextEmbedding; TextEmbedding('sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2')" && \
        echo "[semantic-model] enabled: fastembed installed + MiniLM-L12 model cached" ; \
    else \
        echo "[semantic-model] disabled: SR-017 semantic check falls back to rule-only mode" ; \
    fi

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

# 启动：迁移失败时阻断；评分回填失败仅告警，避免影响 API 可用性
CMD ["sh", "-c", "alembic upgrade head && (python -m src.scripts.backfill_trust_scores || echo '[startup] backfill failed, rerun manually') && exec uvicorn src.main:app --host 0.0.0.0 --port 8000"]

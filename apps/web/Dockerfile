# TrustedAgentHub — Web 前端 Dockerfile（多阶段构建）
# Stage 1: 构建
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: 生产运行
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# 从构建阶段拷贝 standalone 输出
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000

CMD ["node", "server.js"]

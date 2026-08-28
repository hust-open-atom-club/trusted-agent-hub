# TrustedAgentHub — Web 前端 Dockerfile（多阶段构建）
# Stage 1: 构建
FROM node:20-alpine AS builder

RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm config set registry https://registry.npmmirror.com
RUN npm ci

COPY apps/web/ .
COPY packages/schema/constants.ts /packages/schema/constants.ts
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_SITE_URL=http://localhost:3000
ARG NEXT_PUBLIC_SUPPORT_EMAIL=support@example.com
ARG NEXT_PUBLIC_DEMO_ACCOUNT_EMAIL=
ARG NEXT_PUBLIC_DEMO_ACCOUNT_PASSWORD=
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL
ENV NEXT_PUBLIC_SUPPORT_EMAIL=$NEXT_PUBLIC_SUPPORT_EMAIL
ENV NEXT_PUBLIC_DEMO_ACCOUNT_EMAIL=$NEXT_PUBLIC_DEMO_ACCOUNT_EMAIL
ENV NEXT_PUBLIC_DEMO_ACCOUNT_PASSWORD=$NEXT_PUBLIC_DEMO_ACCOUNT_PASSWORD
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# Stage 2: 生产运行
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# 从构建阶段拷贝 standalone 输出
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

EXPOSE 3000

CMD ["node", "server.js"]

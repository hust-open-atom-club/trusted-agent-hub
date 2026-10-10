# Issue #155 · 平台移动端响应式适配方案

## 目标

为 TrustedAgentHub 增加手机端响应式适配，确保普通用户与平台内部角色（submitter / reviewer / admin）
在手机浏览器上能完成：浏览、搜索、详情、登录、提交、扫描、审核及后台管理。

约束：

- 保持现有桌面端布局和视觉风格不变（所有新增样式均置于媒体查询或移动端专属类中）；
- 纯前端改造，不涉及后端 API；
- 验证 375px / 390px / 430px / 768px 常见尺寸。

## 断点体系（沿用现有 globals.css）

| 断点 | 用途 |
| --- | --- |
| `1180px / 960px / 900px` | 宽屏收敛：详情页三栏→两栏→单栏，市场页左筛选→上方 |
| `768px` | 平板/大屏手机：导航汉堡化、表格卡片化、双栏变单栏 |
| `640px` | 大屏手机：筛选面板竖排 |
| `480px / 430px` | 小屏手机（375/390/430）：内边距、字号、统计区紧凑化 |

## 实施方案

### 1. 移动端导航菜单（已完成）

- `components/Navbar.tsx`：新增汉堡按钮（≤768px 显示），链接与用户区收敛进下拉菜单面板；
  - 路由变化、Esc、窗口回到桌面宽度时自动关闭；
  - 菜单打开时锁定页面滚动；
  - 滚动后胶囊收缩样式在移动端禁用（保持整宽顶栏，避免菜单错位）。
- `globals.css`：新增 `.nav-pill__burger`、`.nav-pill__menu*` 系列样式，全部 44px+ 触控目标。
- i18n：`nav.menu_open` / `nav.menu_close`（zh/en）。

### 2. 共享移动端样式

- iOS 输入框聚焦放大规避：≤768px 时表单控件字号统一 16px；
- 代码块横向滚动（详情页文件预览、Diff、审核 finding 代码视图）：长行 `white-space: pre` + 容器 `overflow-x: auto`，行号列 sticky；
- 弹窗底部抽屉化（≤768px）：圆角上移、最大高度 92dvh；
- 触控目标统一 ≥44px；安全区 `env(safe-area-inset-*)`；
- 表格卡片化（复用 review 列表模式：`thead` 隐藏、`td` 加 `data-label`、纵向堆叠）或横向滚动容器二选一。

### 3. 页面适配清单

- 公共页：首页 hero/统计/货架、搜索结果区、详情页（已部分适配，补 480px 档）、登录/注册/账号；
- 提交页 / 扫描页：已有粘性操作栏与竖排适配，补表单控件与状态条检查；
- 审核：列表卡片化已有；审核详情 finding 卡片、证据网格、代码视图补移动端；Diff 与文件查看器双栏竖排 + 代码横向滚动；
- 后台：dashboard 统计卡、packages/publish/rejected/yank/users/submissions/audit-logs 的表格与筛选区卡片化/横向滚动，弹窗抽屉化。

### 4. 验证

- `tsc --noEmit` 通过；
- `vitest run`（apps/web）通过：24 个测试文件 / 186 个用例全部通过；
- `next build`（apps/web）生产构建通过：全部路由（首页/详情/登录/注册/账号/提交/扫描/审核/后台 8 页）编译与页面生成成功；
- 375/390/430px 归入 480px 断点档、768px 平板档逐页检查：无横向溢出、触控目标 ≥44px、表格卡片化、弹窗底部抽屉、代码块可横向滚动；
- 桌面端（≥1200px）回归：所有新增规则均位于媒体查询内或移动端专属类，桌面选择器基础值未改动。

> 本机验证备注：Windows 环境无符号链接权限，`output: 'standalone'` 打包阶段的 symlink 会 EPERM
> （环境限制，CI Ubuntu 不受影响），验证构建时临时关闭该选项，验证后已还原 next.config.js。

## 实现明细（实际改动）

- `apps/web/src/components/Navbar.tsx`：汉堡菜单 + 移动端菜单面板（路由/Esc/宽度变化自动关闭、滚动锁定）；
- `apps/web/src/app/globals.css`：新增 issue #155 区块（导航菜单、公共页、共享弹窗/代码滚动、后台管理、Diff/文件查看器、扫描/状态/提交页、审核列表与详情补全），约 500 行，全部位于 `@media (max-width: 768px/480px)` 或移动端专属类中；
- TSX 微调（合计约 12 处）：admin/users（输入框宽度、下拉触控）、admin/publish（弹窗评分网格两列）、admin/packages（描述列类名 + 副标题重复渲染修复）、admin/yank（原因列类名）、review/history（评论列类名）、review/[versionId]/page.tsx（评分理由断词、审核历史条换行）、FindingCodeView（重试按钮样式）、DependencyQueryResults（分页按钮样式）、GradeOverrideModal（对比行类名）、submit（扫描摘要行换行）；
- i18n：`nav.menu_open` / `nav.menu_close`（zh/en）。

## 范围预估

按 issue 预估 1,300–2,500 行前端变更，实际落地约 500 行 CSS + 约 12 处 TSX 微调 + 导航组件改造，
主要集中在 `apps/web/src/app/globals.css` 新增「issue #155」区块与少量 TSX 结构调整。

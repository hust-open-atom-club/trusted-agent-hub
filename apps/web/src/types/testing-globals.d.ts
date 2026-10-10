/**
 * 全局测试类型声明（vitest 全局 API 与 @testing-library/jest-dom 匹配器扩展）。
 *
 * 说明：不放在 tsconfig 的 "types" 数组里，而用三斜线引用显式引入，
 * 避免 Next 构建 worker 在部分依赖布局（如 pnpm）下解析 "types" 子路径
 * 条目失败（TS2688），也不需要在 typeRoots 中加入 node_modules。
 */
/// <reference types="vitest/globals" />
/// <reference types="@testing-library/jest-dom/vitest" />

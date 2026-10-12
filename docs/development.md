# 开发与验证

后端使用 FastAPI / SQLAlchemy / SQLite，前端使用 React / TypeScript / Vite。任务与认证 worker 复用同一数据库，API 不直接创建无界后台线程。

## 目录

| 目录 | 用途 |
| --- | --- |
| `backend/app` | API、权限、AWS 适配、持久化任务、认证与导出 |
| `backend/tests` | 业务、权限、协议、迁移、并发、备份测试 |
| `frontend/src` | 控制台页面、请求状态和共享交互组件 |
| `frontend/tests` | 前端逻辑、渲染及浏览器回归 |
| `deploy` | 独立 Linux 部署的 systemd / Nginx 模板 |

本地启动步骤见根目录 README。锁定依赖用于复现当前版本；升级依赖后重新执行构建与相关测试。

## 自动测试

```bash
backend/.venv/bin/python -m pytest -q backend/tests
npm test --prefix frontend
npm run build --prefix frontend
```

Python 测试使用隔离临时数据库与合成凭据，禁止未模拟的 AWS SDK 网络请求。AI 协议测试使用内存 HTTP transport，验证三种请求 / 响应格式、密钥不回显、错误脱敏和 DNS 连接固定，不调用真实模型。

## 浏览器测试

安装 Playwright 测试依赖到本机独立目录，避免修改生产依赖：

```bash
npm install --prefix /tmp/kiro-browser-tests playwright
/tmp/kiro-browser-tests/node_modules/.bin/playwright install chromium
KIRO_PLAYWRIGHT_MODULE=/tmp/kiro-browser-tests/node_modules/playwright \
  node --test frontend/tests/*.browser.mjs
```

也可设置 `KIRO_BROWSER_PATH` 使用本机 Chromium。测试挂载真实 React 页面并拦截 API 为本地 fixture，不发送 AWS 请求，也不使用真实密钥。

AI 设置回归涵盖 JSON 页内入口、协议切换、保存后清空输入、留空保留密钥、显式清除、测试保存版本、手机布局和切换会话后的旧响应隔离。权限测试覆盖共享母号下的 SSO、组、批次、改密、验证码、下载、CSV / TXT 和级联删除边界。

真实账号测试应单独执行并明确授权变更范围；不能用模拟 Token 或测试图片识别成功替代真实授权验收。

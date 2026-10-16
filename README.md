# Kiro Admin

面向个人账号管理的 Kiro / AWS IAM Identity Center 控制台。使用 FastAPI、React 和 SQLite，提供 SSO 用户、真实 AWS 分组、订阅任务、密码管理及 JSON 导出。

**仅供学习交流和个人非商业使用，禁止用于商业用途或任何盈利活动。** 使用前请阅读 [免责声明与使用限制](DISCLAIMER.md)。本项目为非官方工具，与 AWS、Amazon、Kiro、Anthropic 或 OpenAI 无隶属或合作关系。

## 功能

- **批次开通**：选择多个 AWS 母号，统一设置人数和套餐，也可逐个调整。新组先创建 SSO 并加入分组，再整组订阅，确认生效后才开始 JSON 转换。数量按每个母号分别计算；例如 5 个母号各创建 100 人，共 500 人。
- **SSO 与分组**：创建、查询、批量管理真实用户和分组；真实用户名与系统内部编号一致。停止的批次可恢复未完成项。
- **订阅与删除**：订阅、取消、定时停止；删除用户先取消相关订阅，删除组先取消订阅、删除受管 SSO 成员，再删除组。无法确认的操作进入待核对状态。
- **JSON 导出**：单人、批量、整组、多组和粘贴账号转换。受管账号必须先确认订阅生效；未订阅的账号会在排队前被拒绝，避免阻塞订阅。只有取得真实 Token 并通过格式校验的结果才能下载。
- **密码管理**：重置一次性密码、随机或自定义永久密码。登录要求改密时自动处理，经 AWS 确认后同步保存；后续登录使用更新后的凭据。
- **个人 AI 配置**：在 JSON 导出页面展开设置，自定义接口地址、密钥、视觉模型和超时。支持 Claude Messages（API Key 或 Bearer 认证）、OpenAI Chat Completions、OpenAI Responses。
- **有界后台任务**：创建、订阅与认证分别按上限并发；临时错误最多自动重试 5 次。密码错误、锁定、缺少 MFA 和写入结果不明确时不会盲目重试。
- **导出与记录**：登录信息可选择 CSV / TXT；JSON ZIP 按日期、批次和母号归档，另有进度、报告和审计记录。

分组 JSON ZIP 的目录结构（同组成功用户合并为一个 JSON 数组）：

```text
2026-10-12-batch-a1b2c3d4.zip
├── AWS编号A/
│   ├── 分组名1.json
│   └── 分组名2.json
└── AWS编号B/
    └── 分组名3.json
```

分组文件归属于自己的 AWS 母号目录，文件内只包含该组的成功用户。独立用户批量转换仍按用户名分别生成 JSON，全部放在 ZIP 的同一个文件夹内：

```text
2026-10-12-batch-a1b2c3d4.zip
└── 2026-10-12-batch-a1b2c3d4/
    ├── 用户名1.json
    └── 用户名2.json
```

单个粘贴转换结果也可直接下载 JSON。导出内容来自真实授权响应，不编造套餐、额度或有效期；同名文件会自动添加唯一后缀，避免覆盖。

新组按“创建组 → 创建 SSO 并加入组 → 整组订阅 → 登录时设置并保存永久密码 → 获取 Token 并导出”的顺序处理。创建和登录各自按并发上限执行；认证会话从开始到完成持续占用名额，避免大量账号先启动登录、再因排队导致授权过期。

向已订阅的 AWS 分组新增成员时，AWS 的成员订阅同步可能需要最长 24 小时。批次页面显示独立的“等待同步”步骤，进度条按实际已确认人数更新；后台在 24 小时内持续只读核对，确认真实订阅后自动继续。同步等待与网络错误的 5 次重试分别计数；超过等待期限、权限或配置变化时停止并提供原任务核对入口，不重复提交订阅。参见 [AWS Kiro 运维指南](https://repost.aws/articles/ARp46l5grvQPi-aDJ7UVh8xA/kiro-enterprise-governance-and-operations-guide-for-kiro-administrators)。

## 用户与权限

普通子用户只能管理自己创建的 SSO 用户、分组和批次，并且只能使用管理员绑定的 AWS 账号和分配的次数。管理员可以管理全站业务记录。

**AI 配置、认证批次、验证码、粘贴转换与 Token 下载按任务发起人隔离，管理员也不能借用其他人的 AI 密钥或直接下载其他人的认证任务。** 两个子用户即使绑定同一 AWS 母号，也不会共享这些结果。详见 [权限与数据边界](docs/security.md)。

## 本地运行

需要 Python 3.12 或更新版本、Node.js 22.12 或更新版本，以及具备对应权限的自有 AWS 账号。先安装依赖和构建前端：

```bash
git clone https://github.com/xiaosu19/kiro-admin.git
cd kiro-admin
python3 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements.lock
npm ci --prefix frontend
npm run build --prefix frontend
cp backend/.env.example backend/.env
```

编辑 `backend/.env`：用随机值替换 `SECRET_KEY` 和 `FERNET_KEY`。可分别执行以下命令生成后填入文件；不要把生成值提交到 Git。

```bash
backend/.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))'
backend/.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
chmod 600 backend/.env
```

初始化数据库。首次管理员密码至少 12 个字符，登录后需修改；初始化不会覆盖现有管理员密码。

```bash
cd backend
read -rs ADMIN_PASSWORD
export ADMIN_PASSWORD
.venv/bin/python -m app.init_db
unset ADMIN_PASSWORD
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

打开 `http://localhost:8000`。再打开两个终端，各自在 `backend/` 目录执行：

```bash
.venv/bin/python -m app.worker
```

```bash
.venv/bin/python -m app.auth_worker
```

两个 worker 必须使用与 API 相同的配置和数据库；关闭浏览器不影响后台任务。可选的图像挑战处理需要 Chromium：

```bash
.venv/bin/python -m playwright install chromium
```

Linux 需要浏览器系统依赖时使用 `playwright install --with-deps chromium`。开发前端也可运行 `npm run dev --prefix frontend`，并相应调整 `APP_ORIGIN`。

## 配置与使用

1. 管理员添加并验证 AWS 账号，核对身份中心区域、订阅区域和授权入口。
2. 为子用户绑定允许使用的 AWS 账号并分配次数；按需配置 SOCKS5 代理。
3. 创建 SSO / 分组，或者提交批次开通；在任务页查看每人的结果。
4. 在 **JSON 导出 → AI 识别设置** 保存自己服务商的配置。密钥留空保留原值，清除需显式选择。
5. 确认订阅已生效，再选择自己的用户或分组，或粘贴已获授权的账号信息，预览后开始转换。
6. 整批处理结束后，成功 JSON 默认保留 2 小时；可关闭页面，稍后从任务记录回来下载。页面显示下载截止时间，下载、取消或过期后会清理结果。

队列里的“当前密码类型”反映已保存的凭据，等待处理时仍可能显示一次性密码。登录服务要求首次改密时，系统先设置永久密码并确认保存，再继续授权；已成功改密的密码不会因为后续 Token 获取失败而回退。已有可用永久密码时直接登录。

批次中的成功项可以立即下载，无需等待其他用户。每次仅导出尚未下载的成功结果，失败项保留并提供重试入口；自动验证停止后也可以直接重试。所有任务结束后，剩余结果默认保留 2 小时，页面显示下载截止时间。

粘贴转换支持账号 JSON、CSV、TXT、登录地址与用户名密码的分隔行，以及 AWS 控制台复制的中英文多行登录信息。默认访问入口和双栈入口出现在同一块信息中时会合并成一个账号；支持连续粘贴多份信息，先预览识别结果再提交。无法判断或信息冲突时会要求补充，不会猜测密码、用户身份或订阅状态。

大批量转换中，先完成的 Token 如果在下载前过期，系统会使用该任务保存的原 OIDC 客户端和刷新凭据更新授权，并重新核对身份和用量。刷新不会重新登录或改密，也不会先消耗其他成功结果；原客户端已过期或身份、权限变化时停止并提示重新授权。

AI 识别只处理受支持的字符型图像验证码。未配置服务、不支持的挑战、识别失败或达到限制时进入人工处理，并显示具体原因；邮箱验证码、短信和 MFA 不交给图像模型。默认首次识别加 5 次重试，共最多 6 次，总预算最多 60 秒；刷新和重启不会重置预算。填写成功不代表验证通过，仍需登录服务确认。

- [AI 协议与个人配置](docs/ai-configuration.md)
- [AWS 接入与常见错误](docs/aws.md)
- [部署、更新和备份](docs/operations.md)
- [权限与数据边界](docs/security.md)

升级前停止 API 和两个 worker，并备份数据库及应用配置，然后运行 `python -m app.init_db`。当前数据库版本为 20；增量迁移保留原任务与重试次数，并支持 Claude Bearer 协议设置。个人 AI 设置不会自动导入或共享旧的全局识别密钥。

## 测试

自动化测试使用模拟 AWS / AI 服务，不需要真实账号或服务商密钥，不产生付费订阅：

```bash
backend/.venv/bin/python -m pytest -q backend/tests
npm test --prefix frontend
npm run build --prefix frontend
```

浏览器回归使用 Playwright，详情见 [开发与验证](docs/development.md)。公开源码不包含实际账号、Token、密钥、数据库、私有部署记录或真实导出文件。

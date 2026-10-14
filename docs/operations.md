# 部署、更新与备份

API、普通 worker 和认证 worker 必须使用同一实例的数据库与配置。当前队列和资源锁设计面向单机 SQLite；不要把多个服务器直接连接到同一个 SQLite 文件。

认证 worker 的 systemd 单元使用 `KillMode=mixed` 和 180 秒停止窗口。升级时先让主进程停止领取新任务，等待正在执行的浏览器步骤结束，再回收子进程。旧部署也应更新此设置；只延长停止时间而沿用 `control-group` 会立即终止正在验证的 Chromium。

## 服务布局

| 内容 | 建议路径 / 服务 |
| --- | --- |
| 版本目录 | `/opt/kiro-console/releases/<version>` |
| 当前版本 | `/opt/kiro-console/current` |
| Python 环境 | `/opt/kiro-console/venv` |
| 数据库 | `/var/lib/kiro-console/console.db` |
| 应用配置 | `/etc/kiro-console/app.env`，权限 600 |
| API / 普通任务 / 认证任务 | `kiro-console` / `kiro-worker` / `kiro-auth-worker` |
| 加密备份 / 定时器 | `kiro-backup.service` / `kiro-backup.timer` |

`deploy/` 提供专用 Ubuntu 24.04 服务器的参考脚本与 systemd / Nginx 模板。安装脚本会安装依赖、初始化数据库及替换该服务器的默认 Nginx 配置，只适合专用新服务器；其他系统或共用服务器请按现有部署方式逐项配置。

构建前端后上传完整源码版本，安装锁定的 Python 依赖，并将配置路径、静态文件目录和数据库目录设为实际路径。安装脚本会将 Chromium 及系统依赖安装到 `/opt/kiro-console/browsers`，认证 worker 的 systemd 模板使用同一路径。手动部署时也需安装浏览器，或设置 `CAPTCHA_CHROMIUM_EXECUTABLE`；浏览器安装位置必须可由服务账户读取，不能放在被 `ProtectHome` 隔离的个人缓存目录。

## 必要配置

- `SECRET_KEY`：至少 32 字符的随机会话密钥。
- `FERNET_KEY`：生成并长期保管的加密密钥；更换前必须迁移密文，不能直接覆盖。
- `DATABASE_URL`：使用专用绝对路径的 SQLite 数据库。
- `APP_ORIGIN` / `VERIFY_ORIGIN`：不同主机名的精确 HTTPS 来源，不带路径。
- `SECURE_COOKIE=true`、`AUTH_ALLOW_LOCAL_ORIGINS=false`：生产环境设置。
- `AUTH_WORKER_LOCK_PATH`：可设置到数据库所在的持久化目录，供重复 worker 进程共享锁。

主站和验证域名均需 DNS、有效 TLS 证书及正确反向代理。验证域名只允许 `/auth-widget`，不接收控制台 Cookie、不代理 API，参考 `nginx-verification.conf.template`。主站 Nginx 模板不自动完成第二个域名的证书和配置，需单独配置。

每个用户在 JSON 导出页面保存自己的 AI 配置；不要把某个用户的密钥填成所有人的环境变量默认值。

## 并发与重试

原生登录按同一次登录的操作 ID 与代理复用 HTTP 连接，每个请求仍使用独立 Cookie 容器和请求头。连接池最多保留 20 个空闲登录、30 秒内未使用即回收；不跨登录复用 Cookie、凭据或授权状态。批次完成检查使用有界数据库查询，定期维护只读取正在等待验证的工作流；登录 HTTP 步骤不会提前初始化 AWS SDK。高频权限检查复用查询结构，并在同一次读取中加载操作者和 AWS 配置；每次仍重新读取数据库，不缓存授权结果。

批量创建 SSO 时，协调器一次查询本批次已有的用户记录，避免每轮等待都逐个读取。代理绑定与代理版本、启用状态也合并到一次即时查询，撤销绑定和停用代理仍会在下一次发送前生效。粘贴转换同样合并读取任务、操作者和受管账号的权限信息；每次检查重新读取数据库，取消、会话失效和权限撤销不会被跨请求缓存延迟。

| 配置 | 默认 | 范围 |
| --- | --- | --- |
| `WORKER_CONCURRENCY` | 4 | 1–16 |
| `AUTH_WORKER_CONCURRENCY` | 2 | 1–20 |
| `PER_ACCOUNT_CONCURRENCY` | 2 | 1–8 |
| `AUTH_PER_ACCOUNT_CONCURRENCY` | 跟随 `PER_ACCOUNT_CONCURRENCY` | 1–20 |
| `CAPTCHA_BROWSER_CONCURRENCY` | 2 | 1–10；复用浏览器时可到 20 |
| `CAPTCHA_BROWSER_REUSE` | `false` | `true` / `false` |
| `CAPTCHA_MAX_ATTEMPTS` | 6 | 1–6 |
| `AUTH_DOWNLOAD_TTL_SECONDS` | 7200 | 30–7200 |

JSON 成功结果默认在整批处理结束后保留 2 小时，页面显示实际下载截止时间。批量开通会等待所选全部 AWS 账号的 JSON 任务结束，再统一计算保留窗口；提早完成的用户不会因后续用户排队而被清理。任务仍受认证批次的总有效期限制。关闭页面不停止后台任务；下载后敏感结果立即清理。下载时若访问令牌已到期，系统使用原授权排队刷新，确认成功后再下载，不会重置密码。

独立记录按上限并发，同一账号或资源的冲突操作仍需串行和状态核对。可重试的临时失败最多自动重试 5 次；密码错误、锁定、权限不足和结果不明确不会因此重复写入。图像识别默认首次识别加 5 次重试，共最多 6 次，总计最多 60 秒；刷新和重启不会重置预算。已有部署显式设置的识别次数继续生效，可在上述范围内调整。

认证并发限制覆盖完整登录和 OIDC 会话，包括轮询等待；不会一次启动全部账号的授权再逐步排队。经确认的 AWS 订阅传播延迟另设 24 小时等待窗口，按 1、2、5、10 分钟递增、之后每 15 分钟只读核对，页面显示下次核对时间；超时后需核对原任务。

认证会话与浏览器有独立上限。外部请求等待较多时，可先小批量验证 `AUTH_WORKER_CONCURRENCY=4`、`AUTH_PER_ACCOUNT_CONCURRENCY=4`、`CAPTCHA_BROWSER_CONCURRENCY=2`，让轻量请求继续推进，同时最多启动两个浏览器。`PER_ACCOUNT_CONCURRENCY` 仍控制创建与订阅操作；不配置认证专用上限时保留原有行为。调整后检查可用内存、接口限流、验证码成功率和整批耗时，再决定是否保留；并发翻倍不代表速度必然翻倍。

资源充足时可将认证会话上限逐步提高到 10，经过小批实测后可试到 20。浏览器使用独立上限，超过 10 个并发上下文必须启用 `CAPTCHA_BROWSER_REUSE=true`。多个 AWS 账号共用全局上限，例如 5 个账号各 60 人会让 300 个任务排队，设为 20 时最多同时推进 20 个认证会话。浏览器上限低于认证会话上限时，验证码步骤会排队；提高浏览器上限前应检查 CPU 与可用内存，并通过真实任务测量整批耗时。自动图像识别结束且密码状态明确的任务会立即显示“重试验证”，无需等待挑战过期；正在识别、MFA 或密码写入结果未知时不会重启登录。重试沿用现有凭据，不重新重置密码。重新进入 JSON 导出页面会恢复本浏览器中该用户上次查看的任务，服务端历史记录仍可查看所有任务。

设置 `CAPTCHA_BROWSER_REUSE=true` 后，认证 worker 复用一个 Chromium 进程，每个验证码仍新建并销毁独立浏览器上下文，页面、Cookie、存储、代理传输和 AI 配置均按任务隔离。`CAPTCHA_BROWSER_CONCURRENCY` 此时限制同时使用的上下文数量。浏览器空闲 15 秒后释放，使用 100 次后待当前任务结束再轮换；不会为轮换中断其他账号。此模式减少重复启动浏览器和驱动的开销，适合小内存服务器；仍需保留任务并发上限。

在 Lightsail 等突发性能实例上，内存有余量也可能遇到 CPU 容量不足。检查实例的 CPU 突发容量指标以及系统的 CPU steal 时间；突发容量耗尽后，提高并发可能延长验证耗时并增加超时。应按持续可用算力调整并发，并分别记录首次成功数、重试次数和整批完成时间。参见 [AWS Lightsail CPU 突发容量说明](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-viewing-instance-burst-capacity.html)。

## 更新

1. 确认备份可解密和恢复，保存当前代码版本。
2. 停止 API、普通 worker、认证 worker。
3. 安装新依赖，构建前端，运行 `python -m app.init_db` 做增量迁移。
4. 启动三个服务，检查登录、任务读取和队列处理。

当前 schema 为 20，包含个人 AI 设置、AWS 订阅同步的持久等待时间与核对次数，以及认证任务查询索引。升级不会自动导入旧的全局模型密钥；各用户需要自行配置。不能仅把代码回退到不支持当前 schema 的版本；必要时同时恢复兼容的数据库和配置。

## 加密备份

备份包含一致性 SQLite 快照及应用配置，并用独立 `BACKUP_ENCRYPTION_KEY` 加密。备份主密钥需另外离线保存，不能只放在同一服务器。

本地备份至少配置 `BACKUP_DESTINATION=local`、`BACKUP_LOCAL_DIR`、`BACKUP_DATABASE_PATH`、`BACKUP_APP_ENV`、`BACKUP_ENCRYPTION_KEY` 和 `BACKUP_STATUS_PATH`。S3 方式还需 `BACKUP_BUCKET`、`BACKUP_REGION` 和独立受限写入凭据；不同实例应使用独立配置与目的地。

加载备份环境后执行：

```bash
python -m app.backup create
python -m app.backup verify --object-key BACKUP_FILE_OR_OBJECT_KEY --output-dir /secure/restore-check
```

验证会检查清单、数据库完整性和敏感列解密，包括个人 AI 密钥。恢复目录含敏感文件，应使用受限权限，确认后清理。不要把解密后的数据库、配置或备份提交到 Git。

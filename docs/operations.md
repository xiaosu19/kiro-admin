# 部署、更新与备份

API、普通 worker 和认证 worker 必须使用同一实例的数据库与配置。当前队列和资源锁设计面向单机 SQLite；不要把多个服务器直接连接到同一个 SQLite 文件。

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

| 配置 | 默认 | 范围 |
| --- | --- | --- |
| `WORKER_CONCURRENCY` | 4 | 1–16 |
| `AUTH_WORKER_CONCURRENCY` | 2 | 1–8 |
| `PER_ACCOUNT_CONCURRENCY` | 2 | 1–8 |
| `CAPTCHA_BROWSER_CONCURRENCY` | 2 | 1–4 |

独立记录按上限并发，同一账号或资源的冲突操作仍需串行和状态核对。可重试的临时失败最多自动重试 5 次；密码错误、锁定、权限不足和结果不明确不会因此重复写入。图像识别另受最多 3 次、总计最多 60 秒限制。

## 更新

1. 确认备份可解密和恢复，保存当前代码版本。
2. 停止 API、普通 worker、认证 worker。
3. 安装新依赖，构建前端，运行 `python -m app.init_db` 做增量迁移。
4. 启动三个服务，检查登录、任务读取和队列处理。

当前 schema 为 18，增加个人 AI 设置表。升级不会自动导入旧的全局模型密钥；各用户需要自行配置。不能仅把代码回退到不支持当前 schema 的版本；必要时同时恢复兼容的数据库和配置。

## 加密备份

备份包含一致性 SQLite 快照及应用配置，并用独立 `BACKUP_ENCRYPTION_KEY` 加密。备份主密钥需另外离线保存，不能只放在同一服务器。

本地备份至少配置 `BACKUP_DESTINATION=local`、`BACKUP_LOCAL_DIR`、`BACKUP_DATABASE_PATH`、`BACKUP_APP_ENV`、`BACKUP_ENCRYPTION_KEY` 和 `BACKUP_STATUS_PATH`。S3 方式还需 `BACKUP_BUCKET`、`BACKUP_REGION` 和独立受限写入凭据；不同实例应使用独立配置与目的地。

加载备份环境后执行：

```bash
python -m app.backup create
python -m app.backup verify --object-key BACKUP_FILE_OR_OBJECT_KEY --output-dir /secure/restore-check
```

验证会检查清单、数据库完整性和敏感列解密，包括个人 AI 密钥。恢复目录含敏感文件，应使用受限权限，确认后清理。不要把解密后的数据库、配置或备份提交到 Git。

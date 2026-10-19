# AI 识别配置

在 **JSON 导出** 页面点击 **AI 识别设置**，展开个人配置。管理员和每位子用户分别保存自己的接口、模型和密钥，无需修改代码或重启服务。

## 选择协议

| 后台选项 | 协议值 | 请求路径 | 认证方式 |
| --- | --- | --- | --- |
| Claude Messages | `claude_messages` | `/v1/messages` | `X-API-Key` + `anthropic-version` |
| Claude Messages（Bearer） | `claude_messages_bearer` | `/v1/messages` | `Authorization: Bearer …` |
| OpenAI Chat Completions | `openai_chat` | `/v1/chat/completions` | `Authorization: Bearer` |
| OpenAI Responses | `openai_responses` | `/v1/responses` | `Authorization: Bearer` |

协议应与服务商提供的接口一致。兼容 OpenAI 协议的服务商也可以提供 Claude 模型；模型名称必须填写该服务商实际支持的名称，并支持图片输入。程序不擅自替换模型、不探测其他人的接口，也不会把请求自动转发到另一个提供方。

可填写基础地址 `https://api.example.com`、`https://api.example.com/v1` 或完整接口路径。自定义前缀例如 `https://api.example.com/gateway/v1/messages` 会保留；保存时补全缺少的协议路径，拒绝明显冲突的协议路径。

仅支持公网 HTTPS。地址中不能包含用户名、密码、查询参数或片段；私有、回环、链路本地和其他非公网地址会被拒绝。DNS 解析结果也需全部为公网地址，实际连接固定到已检查的 IP，保留原域名的 Host、TLS SNI 和证书校验。请求不跟随重定向、不使用进程环境代理。

## 保存和测试

- 密钥加密保存在当前用户的配置中，接口不会返回明文或密文。
- 留空密钥表示保留原值；清除需勾选“清除已保存的密钥”，同时关闭自动识别。
- 同时打开多个窗口修改时，旧版本保存返回冲突，需刷新后重新填写。
- “测试已保存配置”只发送程序内置的 `TEST42` 图片，不接受账号截图，不访问 AWS，不修改密码。测试可能产生少量模型调用费用。
- 测试通过表示服务能识别这张固定图片，实际验证码是否通过仍由 AWS 的响应判断。

修改配置后，下次识别步骤使用新配置。已读取配置的识别请求会在发送前检查配置和用户是否仍有效；已经发出的远程请求无法撤回。未配置、禁用或密钥无法解密时，保留人工处理入口，不使用全局密钥或其他用户的配置。

## 数据范围和限制

提供方只收到裁剪后的字符验证码图像和固定识别指令，不会收到完整页面、登录密码、Cookie、邮件验证码、短信验证码或 MFA。单张图片最多 2 MB，响应最多 16 KiB，单次超时可配置为 1–60 秒。

识别总预算最多 60 秒，默认首次识别后最多重试 5 次，共最多 6 次；可通过 `CAPTCHA_MAX_ATTEMPTS` 配置为 1–6 次。重启、刷新验证码和更换模型不会重置当前挑战的计数或截止时间；已提交的图片未实际刷新时不会再次提交。服务未配置时保留原有人工挑战状态；自动处理遇到不支持的挑战或超出预算时，识别状态标记为 `requires_action`，前端提示继续处理。字符识别结果只允许 4–10 位 ASCII 字母或数字；拒绝输出、工具调用、截断响应和不完整结果不会当作答案提交。

这是已有创建、订阅和认证任务的一个处理步骤，不会为每个账号无限启动浏览器。`CAPTCHA_BROWSER_CONCURRENCY` 控制本机浏览器处理上限，默认 2。

一轮自动识别结束后，临时失败可进入任务队列自动重新开始认证，重新获取验证码。退避为 5、15、45、120、300 秒，与网络重试共享最多 5 次的持久预算；关闭页面、刷新或重启 worker 不会恢复次数。后台始终使用已经确认保存的密码，不自动发起一次性密码重置。旧浏览器释放后才会启动下一轮，同一账号不会重叠登录。

接口认证失败（401/403）、付费或额度不足（402）、配置错误、不支持的挑战及密码写入结果不明不会自动反复重试。429、网络故障、超时和识别答案被拒可有限重试；上限用完保留人工处理及手动重试入口。审计记录只保存任务 ID、结果分类和尝试次数，不保存验证码图片、答案、密钥或登录信息。

系统内 SSO 用户的登录、改密、验证码页面和 OIDC 请求使用所属 AWS 账号绑定的代理，代理失效不会自动回退直连。外部粘贴账号若匹配到受管记录，也沿用该账号代理；未匹配的外部账号使用服务器出口。AI 接口调用使用服务器出口，独立于 AWS 账号代理。

## 调用接口

所有接口均要求当前登录会话，写请求还要求 `X-CSRF-Token`。只支持本人配置，不接受 `user_id` / `actor_id` 覆盖：

- `GET /api/ai-settings`：返回本人设置、`key_configured` 和 `revision`。
- `PUT /api/ai-settings`：保存本人设置，必须提交读取到的 `revision`；首次保存为 0。
- `POST /api/ai-settings/test`：提交已保存配置的 `revision`，返回固定结果代码。

保存示例（密钥仅为占位符）：

```json
{
  "revision": 0,
  "protocol": "claude_messages",
  "endpoint": "https://api.example.com/v1/messages",
  "model": "your-vision-model",
  "api_key": "YOUR_API_KEY",
  "enabled": true,
  "timeout_seconds": 20
}
```

后台任务按发起人选择识别服务；管理员替其他人操作时也使用管理员自己的配置。旧的 `CAPTCHA_VISION_*` 环境配置不作为后台任务的共享回退，升级后需各自保存个人配置。

协议实现参考 [OpenAI 图像输入文档](https://developers.openai.com/api/docs/guides/images-vision)、[Chat Completions 接口](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)、[Responses 接口](https://developers.openai.com/api/reference/resources/responses/methods/create) 和 [Claude 图像输入文档](https://platform.claude.com/docs/en/build-with-claude/vision)。

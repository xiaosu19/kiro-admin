"""Allowlisted CAPTCHA codes and fixed public text; never endpoint error text."""

MESSAGES = {
    "captcha_unavailable": "未配置或未启用个人 AI 自动识别，请在 AI 设置中完成配置，或人工处理验证码",
    "captcha_invalid_configuration": "个人 AI 配置无效，请检查接口地址、协议、模型和密钥后重试",
    "captcha_provider_failed": "AI 识别接口请求失败，请检查个人 AI 配置、网络、模型权限或余额，或人工处理验证码",
    "captcha_invalid_response": "AI 识别接口未返回有效答案，请确认模型支持图片输入，或人工处理验证码",
    "captcha_invalid_image": "验证码图片无效，无法自动识别，请刷新验证提示或人工处理",
    "captcha_browser_unavailable": "自动验证浏览器不可用，请联系管理员检查浏览器配置，或人工处理验证码",
    "captcha_browser_failed": "自动验证浏览器处理失败，请刷新验证提示或人工处理验证码",
    "captcha_unsupported": "当前验证码类型不支持自动处理，请按验证提示人工完成",
    "captcha_unsupported_challenge": "当前验证码类型不支持自动处理，请按验证提示人工完成",
    "captcha_unsafe_destination": "验证码请求地址未通过校验，已停止自动处理，请人工核对登录入口",
    "captcha_attempt_limit": "自动验证码识别已达到次数上限，请按验证提示人工处理",
    "captcha_limit": "自动验证码识别已达到次数或时间上限，请按验证提示人工处理",
    "captcha_timeout": "自动验证码识别已达到时间上限，请按验证提示人工处理",
    "captcha_answer_rejected": "AWS 拒绝了自动识别答案，请按验证提示人工处理",
    "captcha_failed": "自动验证码处理未完成，请按验证提示人工处理",
}


def safe_captcha_code(code, fallback="captcha_failed"):
    return code if isinstance(code, str) and code in MESSAGES else fallback


class ActionRequired(Exception):
    """A durable CAPTCHA budget stop, optionally retaining a safe prior cause."""

    last_failure_code = None


def captcha_failure(automation):
    code = safe_captcha_code(automation.get("reason"))
    message = MESSAGES[code]
    previous = automation.get("last_failure_code")
    if code in ("captcha_limit", "captcha_attempt_limit", "captcha_timeout", "captcha_browser_failed") and isinstance(previous, str) and previous in MESSAGES and previous != code:
        message += "；最近原因：" + MESSAGES[previous]
    return code, message

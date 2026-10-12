from typing import Literal
import re
from datetime import timezone
from pydantic import (
    BaseModel,
    AwareDatetime,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)
from urllib.parse import urlparse


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=128)


class ChangePassword(BaseModel):
    old_password: str
    new_password: str = Field(min_length=12, max_length=72)


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,80}$")
    display_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=72)
    role: Literal["admin", "member"] = "member"


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=72)
    role: Literal["admin", "member"] | None = None


class BindingInput(BaseModel):
    account_ids: list[int] = Field(max_length=100)


class CounterInput(BaseModel):
    limit_count: int = Field(ge=0, le=1000000)


class CounterResetInput(CounterInput):
    reason: str = Field(min_length=2, max_length=500)


class ConfiguredResetInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_cycle: int = Field(ge=1)


class ResolveUnsubscribedInput(BaseModel):
    confirmed_in_aws: Literal[True]
    reason: str = Field(min_length=5, max_length=500)


class PlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    code: str = Field(pattern=r"^[a-z0-9_-]{2,50}$")
    subscription_type: Literal[
        "Q_DEVELOPER_STANDALONE_PRO",
        "Q_DEVELOPER_STANDALONE_PRO_PLUS",
        "Q_DEVELOPER_STANDALONE_POWER",
        "Q_DEVELOPER_STANDALONE_PRO_MAX",
    ]
    active: bool = True


class AwsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    account_number: str | None = None
    region: str = Field(pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d$")
    subscription_region: Literal["us-east-1", "eu-central-1"] = "us-east-1"
    control_plane: Literal["legacy", "kiro"] = "legacy"
    identity_store_id: str = Field(min_length=10, max_length=100)
    instance_arn: str = Field(pattern=r"^arn:aws:sso:::instance/ssoins-[a-zA-Z0-9]+$")
    application_arn: str = Field(
        pattern=r"^arn:aws:sso::\d{12}:application/ssoins-[a-zA-Z0-9]+/apl-[a-zA-Z0-9]+$"
    )
    profile_arn: str = Field(
        pattern=r"^arn:aws:(?:codewhisperer|q|kiro):[a-z0-9-]+:\d{12}:profile/[a-zA-Z0-9/:-]+$"
    )
    portal_url: str = Field(max_length=500)
    access_key_id: str | None = Field(default=None, min_length=16, max_length=128)
    secret_access_key: str | None = Field(default=None, min_length=16, max_length=256)
    active: bool = True
    proxy_id: int | None = Field(default=None, ge=1)

    @field_validator("account_number")
    @classmethod
    def normalize_number(cls, value):
        if value is None or not value.strip():
            return None
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9]{1,24}", value):
            raise ValueError("AWS 编号需为 1 至 24 位英文字母或数字")
        return value.lower()

    @field_validator("portal_url")
    @classmethod
    def validate_portal(cls, value):
        parsed = urlparse(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.hostname.endswith((".awsapps.com", ".app.aws"))
            or parsed.username
        ):
            raise ValueError("需要 HTTPS AWS 登录门户地址")
        return value


class StopPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["none", "days", "at"] = "none"
    days: int | None = Field(default=None, ge=1, le=3650)
    stop_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def valid_policy(self):
        if self.mode == "days" and (self.days is None or self.stop_at is not None):
            raise ValueError("按天设置需填写天数，不能同时指定时间")
        if self.mode == "at" and (self.stop_at is None or self.days is not None):
            raise ValueError("指定时间需包含时区，不能同时填写天数")
        if self.mode == "none" and (self.days is not None or self.stop_at is not None):
            raise ValueError("关闭定时停止时不指定天数或时间")
        if self.stop_at is not None:
            self.stop_at = self.stop_at.astimezone(timezone.utc)
        return self


class StopScheduleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: StopPolicy
    expected_revision: int = Field(ge=0)


class SubscriptionInput(BaseModel):
    aws_account_id: int
    group_id: str | None = None
    plan_id: int
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{2,70}$")
    email: EmailStr
    request_key: str = Field(min_length=16, max_length=80)
    stop_schedule: StopPolicy | None = None


class AwsDiscoverInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_key_id: str = Field(min_length=16, max_length=128)
    secret_access_key: str = Field(min_length=16, max_length=256)
    region: str = Field(pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d$")
    subscription_region: Literal["us-east-1", "eu-central-1"] = "us-east-1"
    proxy_id: int | None = Field(default=None, ge=1)


class OperationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    kind: Literal[
        "cancel_subscription",
        "delete_sso",
        "reset_password",
        "update_sso",
        "sync_status",
    ]
    request_key: str = Field(min_length=16, max_length=80)
    confirm_username: str | None = None
    cancellation_mode: Literal["IMMEDIATE", "END_OF_PERIOD"] = "IMMEDIATE"
    acknowledge_subscription: bool = False
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None

    @model_validator(mode="after")
    def validate_action(self):
        if self.kind == "update_sso" and (not self.display_name or not self.email):
            raise ValueError("更新姓名与邮箱均为必填")
        if self.kind not in ("sync_status", "update_sso") and not self.confirm_username:
            raise ValueError("需要确认用户名")
        return self

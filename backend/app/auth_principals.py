"""One login identity and managed credential binding for both auth families."""
import hashlib
import json

from fastapi import HTTPException
from sqlalchemy import select

from .auth_credentials import (
    account_fingerprint,
    apply_credential,
    invalidate_credentials,
)
from .external_auth_models import ExternalExportItem
from .models import AwsAccount, Binding, ManagedGroup, Subscription
from .proxies import ProxyUnavailable, proxy_selection
from .security import decrypt, encrypt


def login_key(directory, username):
    return hashlib.sha256((directory + "\n" + username.casefold()).encode()).hexdigest()


def active_external_login(db, record):
    account = db.get(AwsAccount, record.aws_account_id)
    return bool(account and db.scalar(select(ExternalExportItem.id).where(
        ExternalExportItem.principal_key == login_key(account.identity_store_id, record.username),
        ExternalExportItem.state.in_(("queued", "running", "polling", "challenge")),
    ).limit(1)))


def _access(db, actor, record, account):
    if (not actor or not actor.active or actor.deleted_at or actor.must_change_password
            or not account or not account.active or account.deleted_at
            or actor.role != "admin" and (record.owner_id != actor.id
                or db.get(Binding, (actor.id, account.id)) is None)):
        raise HTTPException(403, "用户归属或 AWS 账号绑定已失效，请核对后重新提交")


def _ready(db, record):
    if (record.sso_deleted_at or not record.sso_user_id or record.reserved
            or record.state not in ("completed", "failed") or record.active_operation_id):
        raise HTTPException(409, "该用户已有操作或尚未就绪，请先核对管理任务")
    group = db.get(ManagedGroup, record.group_id) if record.group_id else None
    if group and (group.state != "ready" or group.active_job_id):
        raise HTTPException(409, "该用户所属分组存在未完成任务，请先核对")


def managed_configuration(db, pasted, actor):
    """Freeze a known console identity without exposing its administrative secret."""
    matches = [(record, account) for record, account in db.execute(
        select(Subscription, AwsAccount).join(AwsAccount, Subscription.aws_account_id == AwsAccount.id)
        .where(AwsAccount.identity_store_id == pasted.directory))
        if record.username.casefold() == pasted.username.casefold()]
    configuration = pasted.public()
    if not matches:
        return configuration
    if len(matches) != 1:
        raise HTTPException(409, "同一登录身份对应多个管理记录，请先核对 AWS 配置")
    record, account = matches[0]
    _access(db, actor, record, account)
    _ready(db, record)
    for supplied, actual in ((pasted.region, account.region),
                             (pasted.instance_arn, account.instance_arn),
                             (pasted.profile_arn, account.profile_arn),
                             (pasted.api_region, account.subscription_region),
                             (pasted.expected_user_id, record.sso_user_id)):
        if supplied is not None and supplied != actual:
            raise HTTPException(409, "粘贴的用户身份或 AWS 配置与管理记录不一致")
    try:
        proxy = proxy_selection(db, account.proxy_id)
    except ProxyUnavailable:
        raise HTTPException(409, "绑定的代理不可用，请管理员核对后重试") from None
    configuration.update(username=record.username, region=account.region,
        instance_arn=account.instance_arn, profile_arn=account.profile_arn,
        api_region=account.subscription_region, expected_user_id=record.sso_user_id,
        _managed_record_id=record.id, _managed_account_id=account.id,
        _managed_owner_id=record.owner_id, _managed_user_id=record.sso_user_id,
        _managed_credential_revision=record.credential_revision,
        _managed_account_fingerprint=account_fingerprint(account),
        _managed_proxy_revision=proxy.revision if proxy else None)
    return configuration


def validate_managed(db, item, actor, *, check_revision=True, check_operations=True):
    configuration = json.loads(item.configuration)
    record_id = configuration.get("_managed_record_id")
    if not record_id:
        return None, None
    record = db.get(Subscription, record_id)
    account = db.get(AwsAccount, configuration["_managed_account_id"])
    if (not record or not account or record.aws_account_id != account.id
            or record.owner_id != configuration["_managed_owner_id"]
            or record.username != item.username or record.sso_user_id != configuration["_managed_user_id"]
            or record.sso_deleted_at):
        raise HTTPException(409, "管理记录身份已变化，本次认证已失效")
    _access(db, actor, record, account)
    if (account_fingerprint(account) != configuration["_managed_account_fingerprint"]
            or check_revision and record.credential_revision != configuration["_managed_credential_revision"]):
        raise HTTPException(409, "AWS 配置或登录凭据已变化，本次认证已失效")
    if check_operations:
        _ready(db, record)
    try:
        proxy = proxy_selection(db, account.proxy_id)
        if (proxy.revision if proxy else None) != configuration["_managed_proxy_revision"]:
            raise ProxyUnavailable()
    except ProxyUnavailable:
        raise HTTPException(409, "绑定的代理不可用或已变化，请核对后重新提交") from None
    return record, account


def apply_managed_credential(db, item, encrypted, event=None):
    """Persist an on-wire password outcome even after its actor cancels/revokes."""
    configuration = json.loads(item.configuration)
    if not configuration.get("_managed_record_id"):
        return
    record = db.get(Subscription, configuration["_managed_record_id"])
    credential = decrypt(encrypted)
    if (not record or record.aws_account_id != configuration["_managed_account_id"]
            or record.username != item.username or record.sso_user_id != configuration["_managed_user_id"]
            or credential.get("username") != record.username
            or credential.get("expected_user_id") != record.sso_user_id):
        raise ValueError("credential identity mismatch")
    # The item checkpoint always survives. Never overwrite a newer independent
    # managed credential outcome if an unrelated operation already changed it.
    if record.credential_revision != configuration["_managed_credential_revision"]:
        return
    credential["binding"] = {
        "account_id": record.aws_account_id, "region": configuration["region"],
        "directory": configuration["directory"], "instance": configuration.get("instance_arn"),
    }
    managed = encrypt(credential)
    changing = event in ("password_pending", "external_authorization") or (
        credential.get("status") == "unknown" and bool(credential.get("candidate"))) or (
        credential.get("status") == "confirmed" and credential.get("current")
        and (not record.password_encrypted or decrypt(record.password_encrypted) != credential["current"]))
    if changing and not configuration.get("_managed_write_invalidated"):
        invalidate_credentials(db, record)
        configuration["_managed_write_invalidated"] = True
    if event == "external_authorization":
        # An official browser can replace either saved password. Do not let a
        # previous native candidate become a later managed recovery attempt.
        record.credential_recovery_encrypted = None
    apply_credential(record, managed)
    configuration["_managed_credential_revision"] = record.credential_revision
    item.configuration = json.dumps(configuration)

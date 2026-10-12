"""Bounded, read-only AWS report protocols. Uses the gateway's guarded transport."""

import re
from datetime import date

from .aws import AwsFailure

MAX_PAGES = 100
MAX_ROWS = 100_000


def pages(read, key, token_key):
    rows, seen, token = [], set(), None
    for _ in range(MAX_PAGES):
        data = read(token)
        if (not isinstance(data, dict) or not isinstance(data.get(key), list)
                or any(not isinstance(row, dict) for row in data[key])):
            raise AwsFailure("AWS 报表响应格式异常，请重试或检查服务权限")
        rows.extend(data[key])
        if len(rows) > MAX_ROWS:
            raise AwsFailure("AWS 报表超过读取上限，请缩小账号范围")
        token = data.get(token_key)
        if token is None or token == "":
            return rows
        if not isinstance(token, str) or len(token) > 16_384 or token in seen:
            raise AwsFailure("AWS 报表分页异常，未返回不完整结果，请重试")
        seen.add(token)
    raise AwsFailure("AWS 报表分页超过上限，未返回不完整结果")


def subscriptions(gateway):
    account = gateway.account

    def read(token):
        return gateway._call(
            account.region,
            f"service.user-subscriptions.{account.region}.amazonaws.com",
            "user-subscriptions", "AWSZornControlPlaneService.ListUserSubscriptions",
            {"instanceArn": account.instance_arn,
             "subscriptionRegion": account.subscription_region, "maxResults": 1000,
             **({"nextToken": token} if token else {})},
        )[0]

    return pages(read, "subscriptions", "nextToken")


def directory(gateway, kind):
    method = gateway.identity.list_users if kind == "Users" else gateway.identity.list_groups
    return pages(lambda token: method(
        IdentityStoreId=gateway.account.identity_store_id, MaxResults=100,
        **({"NextToken": token} if token else {}),
    ), kind, "NextToken")


def month_period(month):
    if not isinstance(month, str) or not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
        raise ValueError("月份需要 YYYY-MM 格式")
    year, number = map(int, month.split("-"))
    start = date(year, number, 1)
    end = date(year + (number == 12), 1 if number == 12 else number + 1, 1)
    return start.isoformat(), end.isoformat()

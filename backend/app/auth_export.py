"""Single-account JSON arrays and traversal-safe ZIPs, exclusively in memory."""

import io
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone

from .auth_credentials import known_password
from .security import decrypt


def iso(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = datetime.fromtimestamp(value, timezone.utc)
    if not isinstance(value, datetime):
        raise ValueError("invalid export timestamp")
    return (
        value.replace(tzinfo=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def account_json(record, result):
    for name in (
        "accessToken",
        "refreshToken",
        "clientId",
        "clientSecret",
        "authRegion",
        "apiRegion",
        "startUrl",
        "userId",
    ):
        if not isinstance(result.get(name), str) or not result[name]:
            raise ValueError("incomplete native export")
    if (
        result.get("userId") != record.sso_user_id
        or result.get("username") != record.username
    ):
        raise ValueError("export identity mismatch")
    profile, usage = result.get("profile"), result.get("usage")
    if (
        not isinstance(profile, dict)
        or not isinstance(profile.get("arn"), str)
        or not isinstance(usage, dict)
    ):
        raise ValueError("incomplete native metadata")
    external = result.get("externalAuthorization") is True
    if external:
        from .enterprise_auth import verified_external_identity

        if not verified_external_identity(
            usage, result.get("identityStoreId"), record.sso_user_id
        ):
            raise ValueError("export identity mismatch")
    return [
        {
            "id": record.id,
            "email": record.email,
            "password": known_password(record) if not external and record.credential_state == "permanent" else None,
            "label": record.username,
            "status": "active",
            "addedAt": iso(record.created_at),
            "accessToken": result["accessToken"],
            "refreshToken": result["refreshToken"],
            "expiresAt": iso(result["expiresAt"]),
            "provider": "Enterprise",
            "userId": result["userId"],
            "authMethod": "IdC",
            "clientId": result["clientId"],
            "clientSecret": result["clientSecret"],
            "region": result["authRegion"],
            "authRegion": result["authRegion"],
            "apiRegion": result["apiRegion"],
            "clientIdHash": None,
            "ssoSessionId": None,
            "idToken": None,
            "startUrl": result["startUrl"],
            "profileArn": profile["arn"],
            "usageData": usage,
            "groupId": None,
            "tagLinks": [],
            "machineId": "",
            "availableModelsCache": None,
            "kiro_profile_raw": {"nextToken": None, "profiles": [profile]},
            "kiro_usage_raw": usage,
        }
    ]


def safe_name(value):
    value = re.sub(r'[\\/<>:"|?*\x00-\x1f\x7f]', "_", value).strip(" .")
    return value[:150] or "account"


def build_zip(rows):
    names = [safe_name(r.username) + ".json" for r, _ in rows]
    counts = Counter(name.casefold() for name in names)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for (r, encrypted), name in zip(rows, names):
            if counts[name.casefold()] > 1:
                name = f"{r.aws_account_id}/{safe_name(r.id)}/{name}"
            archive.writestr(
                name,
                json.dumps(
                    account_json(r, decrypt(encrypted)), ensure_ascii=False, indent=2
                ).encode(),
            )
    return output.getvalue()

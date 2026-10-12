"""Subprocess probe. Deliberately imports no conftest and inherits the parent DB."""

import json
import sys

from app import (
    auth_jobs,
    group_jobs,
    group_subscription_worker,
    lifecycle,
    plan_change_worker,
    worker,
)
from app.config import settings
from app.database import engine
from app.enterprise_auth import EnterpriseAuth
from app.proxies import account_proxy

settings.plan_changes_enabled = True
routes = []


class Gateway:
    def __init__(self, account):
        if "--forbid-gateway" in sys.argv:
            raise SystemExit("A live account fence must prevent this claim")
        self.account, self.proxy = account, account_proxy(account)
        routes.append((account.id, self.proxy.proxy_id if self.proxy else None))

    def _check_proxy(self):
        from app.proxies import check_account_proxy

        check_account_proxy(self.account, self.proxy)

    def verify_identity(self):
        if "--service" in sys.argv:
            print("entered", flush=True)
            assert sys.stdin.readline().strip() == "release"

    def create_user(self, record):
        return "created-" + record.id

    def password(self, record):
        return "SyntheticPassword1!"


class DoneAuth(EnterpriseAuth):
    def _advance(self, state, answer):
        if "--service" in sys.argv:
            print("entered", flush=True)
            assert sys.stdin.readline().strip() == "release"
        state.update(
            status="done",
            stage="done",
            result={
                "accessToken": "test-access",
                "refreshToken": "test-refresh",
                "expiresAt": 1988000000,
                "clientId": "test-client",
                "clientSecret": "test-secret",
                "authRegion": state["binding"]["region"],
                "apiRegion": state["binding"]["api_region"],
                "startUrl": state["binding"]["portal"],
                "userId": state["expected_user_id"],
                "username": state["username"],
                "password": state["credential"]["current"],
                "profile": {
                    "arn": state["binding"]["profile_arn"],
                    "profileName": "Actual profile",
                },
                "usage": {
                    "limits": [],
                    "daysUntilReset": 7,
                    "usageBreakdownList": [],
                    "userInfo": {},
                },
            },
        )


runners = {
    "sso": worker.run_one,
    "group": group_jobs.run_group_job,
    "native": group_subscription_worker.run_one,
    "lifecycle": lifecycle.run_operation,
    "plan": plan_change_worker.run_plan_change,
    "auth": auth_jobs.run_one,
}
family, selected = sys.argv[1:3]
if "--service" in sys.argv:
    from app import auth_worker

    service = auth_worker if family == "auth" else worker
    make_dispatcher = service.make_dispatcher
    service.make_dispatcher = lambda: make_dispatcher(
        gateway_factory=Gateway,
        max_workers=1,
        **({"auth_factory": DoneAuth} if family == "auth" else {}),
    )
    service.main()
else:
    kwargs = {"account_id": int(selected)} if selected != "legacy" else {}
    runner = runners[family]
    results = [
        runner(Gateway, DoneAuth, **kwargs)
        if family == "auth"
        else runner(Gateway, **kwargs)
    ]
    if "--drain" in sys.argv:
        for _ in range(4):
            result = (
                runner(Gateway, DoneAuth, **kwargs)
                if family == "auth"
                else runner(Gateway, **kwargs)
            )
            results.append(result)
            if not result:
                break
    print(json.dumps({"db": str(engine.url), "results": results, "routes": routes}))

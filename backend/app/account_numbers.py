"""Permanent account code ownership; caller must hold the admission write lock."""

from fastapi import HTTPException
from .models import AwsAccountNumber


def claim_number(db, account, number):
    if number is not None:
        claim = db.get(AwsAccountNumber, number)
        if claim and claim.aws_account_id != account.id:
            raise HTTPException(409, "该 AWS 编号已由其他账号配置永久保留")
        if not claim:
            db.add(AwsAccountNumber(number=number, aws_account_id=account.id))
    account.account_number = number

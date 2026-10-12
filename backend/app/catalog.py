"""Official commercial-region Kiro tiers checked against Kiro docs on 2026-09-24.

Prices and included credits are reference information; platform counters track
successful subscription activations independently.
"""

CATALOG_CHECKED_AT = "2026-09-24"
PRICING_URL = "https://kiro.dev/pricing/"
BILLING_URL = "https://kiro.dev/docs/enterprise/billing/"

PAID_PLANS = (
    {
        "name": "Kiro Pro",
        "code": "pro",
        "subscription_type": "Q_DEVELOPER_STANDALONE_PRO",
        "monthly_price_usd": 20,
        "monthly_credits": 1000,
    },
    {
        "name": "Kiro Pro+",
        "code": "pro_plus",
        "subscription_type": "Q_DEVELOPER_STANDALONE_PRO_PLUS",
        "monthly_price_usd": 40,
        "monthly_credits": 2000,
    },
    {
        "name": "Kiro Pro Max",
        "code": "pro_max",
        "subscription_type": "Q_DEVELOPER_STANDALONE_PRO_MAX",
        "monthly_price_usd": 100,
        "monthly_credits": 5000,
    },
    {
        "name": "Kiro Power",
        "code": "power",
        "subscription_type": "Q_DEVELOPER_STANDALONE_POWER",
        "monthly_price_usd": 200,
        "monthly_credits": 10000,
    },
)

BY_SUBSCRIPTION_TYPE = {p["subscription_type"]: p for p in PAID_PLANS}
PLAN_ORDER = {p["subscription_type"]: i for i, p in enumerate(PAID_PLANS)}

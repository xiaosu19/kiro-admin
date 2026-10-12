"""Conservative typed classification shared by every automatic recovery queue."""

import re
from dataclasses import dataclass

import requests
from botocore.exceptions import (
    ClientError, ConnectTimeoutError, ConnectionClosedError,
    EndpointConnectionError, HTTPClientError, ReadTimeoutError,
    SSLError as BotoSSLError,
)

MAX_AUTOMATIC_RETRIES = 5
RETRY_DELAYS = (5, 15, 45, 120, 300)

TRANSIENT_CODES = frozenset({
    "Throttling", "ThrottlingException", "ThrottledException",
    "TooManyRequestsException", "RequestLimitExceeded", "SlowDown",
    "ServiceUnavailable", "ServiceUnavailableException", "InternalError",
    "InternalServerError", "InternalServerException", "RequestTimeout",
    "RequestTimeoutException", "PriorRequestNotComplete",
})
STOP_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedException",
    "UnauthorizedOperation", "NotAuthorizedException", "ForbiddenException",
    "InvalidClientTokenId", "UnrecognizedClientException", "InvalidSignatureException",
    "SignatureDoesNotMatch", "ExpiredToken", "ExpiredTokenException",
    "InvalidPasswordException", "InvalidCredentialsException", "AccountLockedException",
    "AccountLocked", "AccountDisabledException", "InvalidUsernameOrPasswordException",
    "PasswordIncorrectException", "MFARequiredException", "MFARequired",
    "UserDisabledException", "PasswordResetRequiredException", "MFAMethodNotFoundException",
    "login_refused", "unsupported_mfa", "password_rejected", "password_unresolved",
    "credential_attempt_limit", "expired", "revoked", "proxy_unavailable",
})


@dataclass(frozen=True)
class FailureClassification:
    code: str
    transient: bool = False
    stop: bool = False
    proven_unsent: bool = False
    unknown: bool = False


def safe_code(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,60}", value) else "unknown"


def classify_failure(error):
    """Never infer retry permission from human-facing exception messages."""
    if isinstance(error, ClientError):
        response = error.response
        code = safe_code(response.get("Error", {}).get("Code"))
        metadata = response.get("ResponseMetadata", {})
        status = metadata.get("HTTPStatusCode", 0)
        rejected = (400 <= status < 500 and status not in (408, 409, 425)
                    and not metadata.get("RetryAttempts", 0))
    else:
        code = safe_code(getattr(error, "aws_code", None) or getattr(error, "code", None))
        status = getattr(error, "http_status", None) or 0
        rejected = bool(getattr(error, "proven_unsent", False))
    if (code in STOP_CODES or getattr(error, "code", None) in STOP_CODES
            or status in (401, 403)):
        return FailureClassification(code, stop=True, proven_unsent=rejected)
    # TLS verification/configuration failures must be corrected, never bypassed.
    if isinstance(error, (requests.exceptions.SSLError, BotoSSLError)):
        return FailureClassification("tls_failed", stop=True)
    if isinstance(error, (requests.ConnectTimeout, ConnectTimeoutError)):
        return FailureClassification("connect_timeout", transient=True, proven_unsent=True)
    if isinstance(error, (requests.Timeout, requests.ConnectionError, EndpointConnectionError,
                          ReadTimeoutError, ConnectionClosedError, HTTPClientError)):
        return FailureClassification("transport_failed", transient=True)
    transient = (code in TRANSIENT_CODES or status == 429 or 500 <= status <= 599
                 or getattr(error, "retryable", None) is True)
    if getattr(error, "retryable", None) is False:
        transient = False
    return FailureClassification(code, transient=transient, proven_unsent=rejected,
                                 unknown=code == "unknown" and not status)

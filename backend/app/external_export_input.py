"""Bounded credential input parsing; errors never include supplied text."""
import csv
import io
import json
import re
import shlex
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, ValidationError


MAX_INPUT_BYTES = 512_000
REGION = re.compile(r'[a-z]{2}(?:-[a-z]+)+-\d')
ALIASES = {
    'start_url': 'portal_url', 'startUrl': 'portal_url', 'login_url': 'portal_url',
    '登录地址': 'portal_url', 'AWS 登录地址': 'portal_url', 'AWS登录地址': 'portal_url',
    'url': 'portal_url', '账号': 'portal_url',
    '用户名': 'username', 'userName': 'username', 'label': 'username',
    '密码': 'password', '永久密码': 'password', '一次性密码': 'password',
    '区域': 'region', 'authRegion': 'region',
    'identity_store_id': 'directory', 'identityStoreId': 'directory',
    'profileArn': 'profile_arn', 'instanceArn': 'instance_arn', 'apiRegion': 'api_region',
    '邮箱': 'email',
    'userId': 'expected_user_id', 'sso_user_id': 'expected_user_id',
}
FIELDS = {'portal_url', 'username', 'password', 'region', 'directory', 'instance_arn',
          'api_region', 'profile_arn', 'email', 'expected_user_id'}


class InputError(ValueError):
    pass


class PastedAccount(BaseModel):
    portal_url: str
    username: str = Field(min_length=1, max_length=256)
    password: SecretStr = Field(repr=False)
    region: str | None = None
    directory: str | None = None
    instance_arn: str | None = None
    api_region: str | None = None
    profile_arn: str | None = None
    email: str | None = None
    expected_user_id: str | None = None

    def public(self):
        return self.model_dump(exclude={'password'})


def checked_account(raw):
    if not isinstance(raw, dict):
        raise InputError('每个账号须提供登录地址、用户名和密码')
    values = {}
    for name, value in raw.items():
        key = ALIASES.get(name, name)
        if key not in FIELDS:
            continue
        if key in values and values[key] != value:
            raise InputError('账号包含互相冲突的字段')
        values[key] = value
    try:
        account = PastedAccount(**values)
        password = account.password.get_secret_value()
        if not password or len(password) > 1024 or any(ord(c) < 32 for c in password):
            raise ValueError()
        if account.username != account.username.strip() or any(ord(c) < 32 or ord(c) == 127 for c in account.username):
            raise ValueError()
        url = account.portal_url.strip()
        if re.fullmatch(r'd-[a-f0-9]{10}', url):
            url = 'https://' + url + '.awsapps.com/start'
        p = urlsplit(url)
        if (p.scheme != 'https' or not p.hostname or p.port not in (None, 443)
                or p.username is not None or p.password is not None or p.query or p.fragment
                or p.path not in ('/start', '/start/') or '\\' in url
                or any(c.isspace() or ord(c) < 32 for c in url)
                or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:awsapps\.com|app\.aws)', p.hostname)):
            raise ValueError()
        account.portal_url = 'https://' + p.hostname + '/start'
        if not account.directory:
            prefix = p.hostname.split('.')[0]
            if re.fullmatch(r'd-[a-f0-9]{10}', prefix):
                account.directory = prefix
        if not account.directory or not re.fullmatch(r'[A-Za-z0-9-]{1,100}', account.directory):
            raise InputError('自定义登录入口需要在 JSON 中提供 identity_store_id')
        for value in (account.region, account.api_region):
            if value is not None and not REGION.fullmatch(value):
                raise ValueError()
        if account.api_region not in (None, 'us-east-1', 'eu-central-1'):
            raise InputError('Kiro 服务区域仅支持 us-east-1 或 eu-central-1')
        if account.instance_arn and not re.fullmatch(r'arn:aws:sso:::instance/ssoins-[A-Za-z0-9]+', account.instance_arn):
            raise ValueError()
        if account.profile_arn and not re.fullmatch(r'arn:aws:(?:codewhisperer|kiro|q):(?:us-east-1|eu-central-1):\d{12}:profile/[A-Za-z0-9_-]+', account.profile_arn):
            raise ValueError()
        if account.email and (len(account.email) > 1024 or any(ord(c) < 32 for c in account.email)):
            raise ValueError()
        if account.expected_user_id and (len(account.expected_user_id) > 256 or any(c.isspace() for c in account.expected_user_id)):
            raise ValueError()
        return account
    except InputError:
        raise
    except (ValidationError, ValueError, TypeError):
        raise InputError('账号字段不完整，或登录地址、区域、用户名格式不受支持') from None


def text_rows(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # Our own copied login details and TXT export use labelled multiline blocks.
    if any(re.match(r'(?:AWS\s*)?登录地址\s*[:：]', line) for line in lines):
        rows, current = [], {}
        for line in lines:
            m = re.match(r'([^:：]+)[:：]\s*(.*)', line)
            if not m:
                if set(line) <= {'-', '='}:
                    continue
                raise InputError('登录信息块包含无法识别的行')
            name, value = m.groups()
            key = ALIASES.get(name.strip(), name.strip())
            if key == 'portal_url' and 'portal_url' in current:
                rows.append(current)
                current = {}
            if key in FIELDS:
                current[key] = value
        if current:
            rows.append(current)
        return rows
    if not lines:
        raise InputError('请粘贴至少一个账号')
    delimiter = '\t' if '\t' in lines[0] else ','
    header = next(csv.reader([lines[0]], delimiter=delimiter))
    if any(ALIASES.get(x.strip(), x.strip()) == 'username' for x in header):
        return list(csv.DictReader(io.StringIO(text), delimiter=delimiter))
    rows = []
    for line in lines:
        if '----' in line:
            parts = line.split('----', 3)
        elif '\t' in line:
            parts = line.split('\t', 3)
        elif ',' in line:
            parts = next(csv.reader([line]))
        else:
            try:
                parts = shlex.split(line)
            except ValueError:
                raise InputError('行格式无法识别，请使用 JSON、CSV 或登录信息块') from None
        if len(parts) not in (3, 4):
            raise InputError('每行须为登录地址、可选区域、用户名、密码')
        rows.append(dict(zip(('portal_url', 'region', 'username', 'password') if len(parts) == 4
                             else ('portal_url', 'username', 'password'), parts)))
    return rows


def parse_accounts(text):
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > MAX_INPUT_BYTES:
        raise InputError('粘贴内容不能为空，且最多 512 KB')
    text = text.lstrip('\ufeff').strip()
    if text.startswith(('{', '[')):
        try:
            rows = json.loads(text)
        except (ValueError, RecursionError):
            raise InputError('JSON 内容无法解析') from None
        if isinstance(rows, dict):
            rows = rows.get('accounts', [rows])
    else:
        rows = text_rows(text)
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise InputError('每批支持 1–100 个账号')
    accounts = [checked_account(row) for row in rows]
    keys = [(a.directory, a.username.casefold()) for a in accounts]
    if len(set(keys)) != len(keys):
        raise InputError('同一登录入口和用户名不能重复提交')
    return accounts

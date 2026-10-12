"""Pasted credentials are parsed without logging or echoing secret material."""
import json

import pytest

from app.external_export_input import InputError, parse_accounts


URL = 'https://d-1234567890.awsapps.com/start'
DUAL_URL = 'https://ssoins-0123456789abcdef.portal.us-east-1.app.aws'


def aws_block(username='synthetic-user', *, english=False, colon='：'):
    names = (['Default AWS access portal URL (IPv4 only)', 'Dual-stack AWS access portal URL', 'Username', 'One-time password']
             if english else ['默认 AWS access portal URL（仅限 IPv4）', '双栈 AWS access portal URL', '用户名', '一次性密码'])
    return '\n'.join(name + colon + ' ' + value for name, value in zip(names,
        [URL, DUAL_URL, username, 'SyntheticPassword123!']))


@pytest.mark.parametrize('english', [False, True])
@pytest.mark.parametrize('colon', [':', '：'])
def test_raw_aws_credentials_with_two_portals_form_one_otp_account(english, colon):
    rows = parse_accounts(aws_block(english=english, colon=colon))
    assert len(rows) == 1
    account = rows[0]
    assert account.portal_url == URL and account.directory == 'd-1234567890'
    assert account.instance_arn == 'arn:aws:sso:::instance/ssoins-0123456789abcdef'
    assert account.region == 'us-east-1'
    assert account.credential_state == 'one_time'
    assert account.password.get_secret_value() == 'SyntheticPassword123!'
    assert 'SyntheticPassword123!' not in repr(rows)
    assert 'password' not in account.public()


@pytest.mark.parametrize('separator', ['\n\n', '\n---\n', '\n'])
def test_repeated_raw_aws_blocks_form_exact_batch(separator):
    rows = parse_accounts(aws_block('first') + separator + aws_block('second', english=True))
    assert [r.username for r in rows] == ['first', 'second']
    assert all(r.credential_state == 'one_time' for r in rows)


@pytest.mark.parametrize('extra', [
    '\n默认 AWS access portal URL（仅限 IPv4）: https://d-9999999999.awsapps.com/start',
    '\n双栈 AWS access portal URL: https://ssoins-ffffffffffffffff.portal.us-east-1.app.aws',
    '\n区域: eu-central-1',
    '\ninstanceArn: arn:aws:sso:::instance/ssoins-ffffffffffffffff',
    '\nidentity_store_id: d-9999999999',
    '\n用户名: conflicting-user',
])
def test_conflicting_raw_aws_block_fields_fail_without_echoing_credentials(extra):
    with pytest.raises(InputError) as error:
        parse_accounts(aws_block() + extra)
    assert 'SyntheticPassword123!' not in str(error.value)
    assert 'https://' not in str(error.value)


def test_single_dual_stack_block_needs_explicit_directory():
    text = ('双栈 AWS access portal URL: ' + DUAL_URL + '\n用户名: synthetic-user\n一次性密码: SyntheticPassword123!')
    with pytest.raises(InputError):
        parse_accounts(text)
    row = parse_accounts(text + '\nidentity_store_id: d-1234567890')[0]
    assert row.portal_url == DUAL_URL + '/start'
    assert row.region == 'us-east-1'
    assert row.instance_arn == 'arn:aws:sso:::instance/ssoins-0123456789abcdef'


def test_parse_json_single_batch_and_public_preview():
    row = {'start_url': URL, 'username': 'alice', 'password': 'Synthetic8!'}
    for text in (json.dumps(row), json.dumps([row]), json.dumps({'accounts': [row]})):
        result = parse_accounts(text)
        assert len(result) == 1
        assert result[0].portal_url == URL
        assert result[0].directory == 'd-1234567890'
        assert result[0].region is None
        assert result[0].password.get_secret_value() == 'Synthetic8!'
        assert 'Synthetic8!' not in repr(result)
        assert 'password' not in result[0].public()


def test_parse_copied_login_blocks_and_csv_preserves_passwords():
    text = (f'内部 ID：a-01-01\nAWS 登录地址：{URL}\n区域：us-east-1\n用户名：alice\n永久密码：Synthetic8!\n\n---\n\n'
            f'AWS 登录地址：{URL}\n用户名：bob\n一次性密码：Other9!')
    rows = parse_accounts(text)
    assert [r.username for r in rows] == ['alice', 'bob']
    assert rows[0].region == 'us-east-1' and rows[1].region is None
    rows = parse_accounts('登录地址,区域,用户名,密码\n' + URL + ',us-east-1,"alice","with,comma9!"')
    assert rows[0].password.get_secret_value() == 'with,comma9!'


def test_extra_csv_values_fail_safely_without_echoing_supplied_passwords():
    text = '登录地址,用户名,密码\n' + URL + ',alice,Synthetic8!,UnexpectedSecret9!'
    with pytest.raises(InputError) as error:
        parse_accounts(text)
    assert 'Synthetic8!' not in str(error.value)
    assert 'UnexpectedSecret9!' not in str(error.value)


def test_delimited_rows_and_region_optional():
    rows = parse_accounts(URL + '----us-east-1----alice----Synthetic8!\n' + URL + '\tbob\tOther9!')
    assert [r.username for r in rows] == ['alice', 'bob']


@pytest.mark.parametrize('url', ['http://d-1234567890.awsapps.com/start', 'https://evil.test/start',
                                 URL + '?password=Synthetic8!', 'https://awsapps.com.evil.test/start',
                                 'https://u:p@d-1234567890.awsapps.com/start', 'https://127.0.0.1/start'])
def test_reject_unsafe_destinations_without_secret_echo(url):
    with pytest.raises(InputError) as e:
        parse_accounts(json.dumps({'username': 'alice', 'password': 'Synthetic8!', 'start_url': url}))
    assert 'Synthetic8!' not in str(e.value) and url not in str(e.value)


def test_bound_duplicates_and_empty_fields():
    row = {'username': 'alice', 'password': 'Synthetic8!', 'start_url': URL}
    for text in (json.dumps([row, row]), json.dumps([dict(row, username=f'u{i}') for i in range(101)]),
                 json.dumps(dict(row, password='')), 'unrecognized private text Synthetic8!'):
        with pytest.raises(InputError) as e:
            parse_accounts(text)
        assert 'Synthetic8!' not in str(e.value)

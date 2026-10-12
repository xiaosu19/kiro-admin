"""Pasted credentials are parsed without logging or echoing secret material."""
import json

import pytest

from app.external_export_input import InputError, parse_accounts


URL = 'https://d-1234567890.awsapps.com/start'


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

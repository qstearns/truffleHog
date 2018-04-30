from truffleHog.truffleHog import (detect_regex)


def test_falsey_string():
    false_string = 'Your mom'
    assert (detect_regex(false_string) is None)


def test_slack_key_string():
    slack_token_string = '''
    slack_token = xoxp-333333333333-333333333333-333333333333-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    '''
    assert (detect_regex(slack_token_string).lastgroup == 'slack_token')


def test_very_secret_string():
    super_secret_stuff = '''
    -----BEGIN RSA PRIVATE KEY-----
    AKIAZZZZZZZZZZZZZZZZ
    '''
    assert (detect_regex(super_secret_stuff).lastgroup == 'rsa_private_key')

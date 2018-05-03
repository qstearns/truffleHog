from truffleHog.truffleHog import (detect_regex)


def test_falsey_string():
    false_string = 'Your mom'
    assert (any(detect_regex(false_string)) is False)


def test_slack_key_string():
    slack_token_string = '''
    slack_token = xoxp-333333333333-333333333333-333333333333-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    '''
    results = list(detect_regex(slack_token_string))
    assert (results[0].group(0) == 'xoxp-333333333333-333333333333-333333333333-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')


def test_very_secret_string():
    super_secret_stuff = '''
    -----BEGIN RSA PRIVATE KEY-----
    AKIAZZZZZZZZZZZZZZZZ
    '''
    results = list(detect_regex(super_secret_stuff))
    assert (results[0].group(0) == '-----BEGIN RSA PRIVATE KEY-----')
    assert (results[1].group(0) == 'AKIAZZZZZZZZZZZZZZZZ')

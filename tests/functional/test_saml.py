import mock
import json
import logging
import xml.dom.minidom
import base64

import requests
import pytest

from tests import create_assertion
from awsprocesscreds.cli import saml, PrettyPrinterLogHandler
from awsprocesscreds.saml import SAMLCredentialFetcher, OktaAuthenticator, \
    SAMLError


@pytest.fixture
def argv():
    return [
        '--endpoint', 'https://example.com',
        '--username', 'monty',
        '--provider', 'okta',
        '--role-arn', 'arn:aws:iam::123456789012:role/monty',
    ]


def test_get_response_1():
    def mock_prompter(prompt):
        return ""

    authenticator = OktaAuthenticator(mock_prompter)
    with pytest.raises(SAMLError):
        authenticator.get_response("")


def test_get_response_2():
    def mock_prompter(prompt):
        return "mock_result"

    authenticator = OktaAuthenticator(mock_prompter)
    response = authenticator.get_response("")
    assert response == "mock_result"


def test_get_response_3():
    def mock_prompter(prompt):
        return ""

    authenticator = OktaAuthenticator(mock_prompter)
    response = authenticator.get_response("", False)
    assert response == ""


def test_process_response_1(mock_requests_session, assertion, prompter):
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode()
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )
    mock_requests_session.get.return_value = assertion_response
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=200,
        text=json.dumps(session_token)
    )
    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=prompter)

    result = authenticator._authenticator.process_response(
        token_response, "endpoint")
    assert result == assertion.decode()


def test_process_response_2(mock_requests_session, assertion, prompter):
    def mock_prompter(prompt):
        assert prompt == "Mock error\r\nPress RETURN to continue\r\n"
        return ""

    session_token = {
        'sessionToken': 'spam',
        'status': 'FAILED',
        'errorCauses': [
            {
                'errorSummary': "Mock error"
            }
        ]
    }
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=400,
        text=json.dumps(session_token)
    )
    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=mock_prompter)

    result = authenticator._authenticator.process_response(
        token_response, "endpoint")
    assert result is None


def test_process_mfa_totp(
        mock_requests_session, prompter, assertion, capsys):
    def mock_prompter(prompt):
        return "12345678"

    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=200,
        text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode()
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=mock_prompter)

    result = authenticator._authenticator.process_mfa_totp(
        "endpoint", "url", "statetoken")
    assert result == assertion.decode()


def test_process_mfa_push_1(
        mock_requests_session, prompter, assertion, capsys):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=200,
        text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode()
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=prompter)

    result = authenticator._authenticator.process_mfa_push(
        "endpoint", "url", "statetoken")
    assert result == assertion.decode()


def test_process_mfa_push_2(
        mock_requests_session, prompter, assertion, capsys):
    session_token = {
        'sessionToken': 'spam',
        'status': 'CANCELLED',
        'factorResult': 'FAILED'
    }
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=200,
        text=json.dumps(session_token)
    )
    mock_requests_session.post.return_value = token_response

    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=prompter)

    with pytest.raises(SAMLError):
        authenticator._authenticator.process_mfa_push(
            "endpoint", "url", "statetoken")


def test_process_mfa_security_question(
        mock_requests_session, prompter, assertion, capsys):
    def mock_prompter(prompt):
        return "security_answer"

    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=200,
        text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode()
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=mock_prompter)

    result = authenticator._authenticator.process_mfa_security_question(
        "endpoint", "url", "statetoken")
    assert result == assertion.decode()


def test_verify_sms_factor(
        mock_requests_session, prompter, assertion, capsys):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=200,
        text=json.dumps(session_token)
    )
    mock_requests_session.post.return_value = token_response
    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=prompter)
    result = authenticator._authenticator.verify_sms_factor(
        "url", "statetoken", "passcode")
    assert result.status_code == 200
    test = json.loads(result.text)
    assert test["status"] == "SUCCESS"


def test_process_mfa_sms(
        mock_requests_session, prompter, assertion, capsys):
    def mock_prompter(prompt):
        return "12345678"

    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response,
        status_code=200,
        text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode()
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=mock_prompter)

    with mock.patch(
            "awsprocesscreds.saml.OktaAuthenticator.verify_sms_factor",
            return_value=token_response):
        result = authenticator._authenticator.process_mfa_sms(
            "endpoint", "url", "statetoken")
        assert result == assertion.decode()


def test_display_mfa_choices(
        mock_requests_session, prompter, assertion, capsys):
    parsed = {
        "_embedded": {
            "factors": [
                {
                    "factorType": "token",
                    "provider": "OKTA"
                },
                {
                    "factorType": "token:software:totp",
                    "provider": "OKTA"
                },
                {
                    "factorType": "sms"
                },
                {
                    "factorType": "push"
                },
                {
                    "factorType": "question"
                },
                {
                    "factorType": "blackboard",
                    "provider": "classroom"
                }
            ]
        }
    }
    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=prompter)
    index, prompt = authenticator._authenticator.display_mfa_choices(parsed)
    assert index == 7
    assert prompt == (
        "1: OKTA token\r\n"
        "2: OKTA authenticator app\r\n"
        "3: SMS text message\r\n"
        "4: Push notification\r\n"
        "5: Security question\r\n"
        "6: classroom blackboard\r\n"
    )


def test_get_number_1(prompter):
    def mock_prompter(prompt):
        return "1"

    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=mock_prompter)
    response = authenticator._authenticator.get_number("")
    assert response == 1


def test_get_number_2(prompter):
    def mock_prompter(prompt):
        return "fred"

    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=mock_prompter)
    response = authenticator._authenticator.get_number("")
    assert response == 0


def test_get_mfa_choice(
        mock_requests_session, prompter, assertion, capsys):
    def mock_prompter(prompt):
        assert prompt == (
            "Please choose from the following authentication choices:\r\n"
            "1: SMS text message\r\n"
            "Enter the number corresponding to your choice or press RETURN to "
            "cancel authentication: "
        )
        return "1"

    parsed = {
        "_embedded": {
            "factors": [
                {
                    "factorType": "sms"
                }
            ]
        }
    }
    authenticator = SAMLCredentialFetcher(
        client_creator=None,
        saml_config=None,
        provider_name="okta",
        password_prompter=mock_prompter)
    response = authenticator._authenticator.get_mfa_choice(parsed)
    assert response == 1


def test_process_mfa_verification_1():
    parsed = {
        "_embedded": {
            "factors": [
                {
                    "factorType": "unsupported",
                    "_links": {
                        "verify": {
                            "href": "href"
                        }
                    }
                },
                {
                    "factorType": "unsupported"
                }
            ]
        },
        "stateToken": "statetoken"
    }
    authenticator = OktaAuthenticator(None)
    with mock.patch(
            "awsprocesscreds.saml.OktaAuthenticator.get_mfa_choice",
            return_value=1):
        with pytest.raises(SAMLError):
            authenticator.process_mfa_verification("endpoint", parsed)


def test_process_mfa_verification_2():
    parsed = {
        "_embedded": {
            "factors": [
                {
                    "factorType": "token:software:totp",
                    "_links": {
                        "verify": {
                            "href": "href"
                        }
                    }
                }
            ]
        },
        "stateToken": "statetoken"
    }
    authenticator = OktaAuthenticator(None)
    with mock.patch(
            "awsprocesscreds.saml.OktaAuthenticator.process_mfa_totp",
            return_value="mock_call"):
        result = authenticator.process_mfa_verification("endpoint", parsed)
        assert result == "mock_call"


def test_process_mfa_verification_3():
    parsed = {
        "_embedded": {
            "factors": [
                {
                    "factorType": "push",
                    "_links": {
                        "verify": {
                            "href": "href"
                        }
                    }
                }
            ]
        },
        "stateToken": "statetoken"
    }
    authenticator = OktaAuthenticator(None)
    with mock.patch(
            "awsprocesscreds.saml.OktaAuthenticator.process_mfa_push",
            return_value="mock_call"):
        result = authenticator.process_mfa_verification("endpoint", parsed)
        assert result == "mock_call"


def test_process_mfa_verification_4():
    parsed = {
        "_embedded": {
            "factors": [
                {
                    "factorType": "question",
                    "_links": {
                        "verify": {
                            "href": "href"
                        }
                    }
                }
            ]
        },
        "stateToken": "statetoken"
    }
    authenticator = OktaAuthenticator(None)
    with mock.patch(
            "awsprocesscreds.saml.OktaAuthenticator."
            "process_mfa_security_question",
            return_value="mock_call"):
        result = authenticator.process_mfa_verification("endpoint", parsed)
        assert result == "mock_call"


def test_process_mfa_verification_5():
    parsed = {
        "_embedded": {
            "factors": [
                {
                    "factorType": "sms",
                    "_links": {
                        "verify": {
                            "href": "href"
                        }
                    }
                }
            ]
        },
        "stateToken": "statetoken"
    }
    authenticator = OktaAuthenticator(None)
    with mock.patch(
            "awsprocesscreds.saml.OktaAuthenticator.process_mfa_sms",
            return_value="mock_call"):
        result = authenticator.process_mfa_verification("endpoint", parsed)
        assert result == "mock_call"


def test_retrieve_saml_assertion_1(
        mock_requests_session, argv, prompter, assertion,
        client_creator, cache_dir):
    session_token = {
        'sessionToken': 'spam',
        'status': 'FAILED',
        'errorSummary': 'Testing failure'
    }
    token_response = mock.Mock(
        spec=requests.Response, status_code=401, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response
    with pytest.raises(SAMLError):
        saml(argv=argv, prompter=prompter, client_creator=client_creator,
             cache_dir=cache_dir)


def test_retrieve_saml_assertion_2(
        mock_requests_session, argv, prompter, assertion,
        client_creator, cache_dir):
    session_token = {
        'sessionToken': 'spam',
        'status': 'LOCKED_OUT',
        '_links': {
            'href': 'href'
        }
    }
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response
    with pytest.raises(SAMLError):
        saml(argv=argv, prompter=prompter, client_creator=client_creator,
             cache_dir=cache_dir)


def test_retrieve_saml_assertion_3(
        mock_requests_session, argv, prompter, assertion,
        client_creator, cache_dir):
    session_token = {
        'sessionToken': 'spam',
        'status': 'PASSWORD_EXPIRED',
        '_links': {
            'href': 'href'
        }
    }
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response
    with pytest.raises(SAMLError):
        saml(argv=argv, prompter=prompter, client_creator=client_creator,
             cache_dir=cache_dir)


def test_retrieve_saml_assertion_4(
        mock_requests_session, argv, prompter, assertion,
        client_creator, cache_dir):
    session_token = {
        'sessionToken': 'spam',
        'status': 'MFA_ENROLL'
    }
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response
    with pytest.raises(SAMLError):
        saml(argv=argv, prompter=prompter, client_creator=client_creator,
             cache_dir=cache_dir)


def test_retrieve_saml_assertion_5(
        mock_requests_session, argv, prompter, assertion,
        client_creator, capsys, cache_dir):
    session_token = {
        'sessionToken': 'spam',
        'status': 'MFA_REQUIRED'
    }
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    with mock.patch(
            "awsprocesscreds.saml.OktaAuthenticator.process_mfa_verification",
            return_value=assertion):
        saml(argv=argv, prompter=prompter,
             client_creator=client_creator,
             cache_dir=cache_dir)

        stdout, _ = capsys.readouterr()
        assert stdout.endswith('\n')

        response = json.loads(stdout)
        expected_response = {
            "AccessKeyId": "foo",
            "SecretAccessKey": "bar",
            "SessionToken": "baz",
            "Expiration": mock.ANY,
            "Version": 1
        }
        assert response == expected_response


def test_retrieve_saml_assertion_6(
        mock_requests_session, argv, prompter, assertion,
        client_creator, cache_dir):
    session_token = {
        'sessionToken': 'spam'
    }
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response
    with pytest.raises(SAMLError):
        saml(argv=argv, prompter=prompter, client_creator=client_creator,
             cache_dir=cache_dir)


def test_cli(mock_requests_session, argv, prompter, assertion, client_creator,
             capsys, cache_dir):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response
    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

    stdout, _ = capsys.readouterr()
    assert stdout.endswith('\n')

    response = json.loads(stdout)
    expected_response = {
        "AccessKeyId": "foo",
        "SecretAccessKey": "bar",
        "SessionToken": "baz",
        "Expiration": mock.ANY,
        "Version": 1
    }
    assert response == expected_response


def test_no_cache(mock_requests_session, argv, prompter, assertion,
                  client_creator, capsys, cache_dir):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    argv.append('--no-cache')

    expected_response = {
        "AccessKeyId": "foo",
        "SecretAccessKey": "bar",
        "SessionToken": "baz",
        "Expiration": mock.ANY,
        "Version": 1
    }

    call_count = 5
    for _ in range(call_count):
        saml(argv=argv, prompter=prompter, client_creator=client_creator,
             cache_dir=cache_dir)
        stdout, _ = capsys.readouterr()
        assert json.loads(stdout) == expected_response

    assert mock_requests_session.post.call_count == call_count
    assert mock_requests_session.get.call_count == call_count
    assert prompter.call_count == call_count


def test_verbose(mock_requests_session, argv, prompter, assertion,
                 client_creator, cache_dir):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    argv.append('--verbose')

    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

    logger = logging.getLogger('awsprocesscreds')
    assert logger.level == logging.INFO

    pretty_handlers = [
        h for h in logger.handlers if isinstance(h, PrettyPrinterLogHandler)
    ]
    assert len(pretty_handlers) == 1
    handler = pretty_handlers[0]
    assert handler.level == logging.INFO


def test_log_handler_parses_assertion(mock_requests_session, argv, prompter,
                                      client_creator, cache_dir, caplog):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )

    provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
    role_arn = 'arn:aws:iam::123456789012:role/monty'
    saml_assertion = create_assertion([
        '%s, %s' % (provider_arn, role_arn)
    ])
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % saml_assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    argv.append('--verbose')

    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

    decoded_assertion = base64.b64decode(saml_assertion).decode('utf-8')
    expected_assertion = xml.dom.minidom.parseString(decoded_assertion)
    expected_assertion = expected_assertion.toprettyxml()
    expected_log = (
        'awsprocesscreds.saml',
        logging.INFO,
        'Received the following SAML assertion: \n%s' % expected_assertion
    )
    assert expected_log in caplog.record_tuples


def test_log_handler_parses_dict(mock_requests_session, argv, prompter,
                                 client_creator, cache_dir, caplog):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )

    provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
    role_arn = 'arn:aws:iam::123456789012:role/monty'
    saml_assertion = create_assertion([
        '%s, %s' % (provider_arn, role_arn)
    ])
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % saml_assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    argv.append('--verbose')

    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

    expected_params = {
        'PrincipalArn': provider_arn,
        'RoleArn': role_arn,
        'SAMLAssertion': saml_assertion.decode('utf-8')
    }
    expected_log_message = (
        'Retrieving credentials with STS.AssumeRoleWithSaml() using the '
        'following parameters: %s' % json.dumps(
            expected_params, indent=4, sort_keys=True)
    )
    expected_log = (
        'awsprocesscreds.saml',
        logging.INFO,
        expected_log_message
    )
    assert expected_log in caplog.record_tuples


def test_unsupported_saml_auth_type(client_creator, prompter):
    invalid_config = {
        'saml_authentication_type': 'unsupported',
        'saml_provider': 'okta',
        'saml_endpoint': 'https://example.com/',
        'saml_username': 'monty',
    }
    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        saml_config=invalid_config,
        provider_name='okta',
        password_prompter=prompter,
    )
    with pytest.raises(ValueError):
        fetcher.fetch_credentials()


def test_unsupported_saml_provider(client_creator, prompter):
    invalid_config = {
        'saml_authentication_type': 'form',
        'saml_provider': 'unsupported',
        'saml_endpoint': 'https://example.com/',
        'saml_username': 'monty',
    }
    with pytest.raises(ValueError):
        SAMLCredentialFetcher(
            client_creator=client_creator,
            saml_config=invalid_config,
            provider_name='unsupported',
            password_prompter=prompter,
        )


def test_prompter_only_called_once(client_creator, prompter, assertion,
                                   mock_requests_session):
    session_token = {'sessionToken': 'spam', 'status': 'SUCCESS'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    config = {
        'saml_authentication_type': 'form',
        'saml_provider': 'okta',
        'saml_endpoint': 'https://example.com/',
        'saml_username': 'monty',
        'role_arn': 'arn:aws:iam::123456789012:role/monty'
    }
    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        saml_config=config,
        provider_name='okta',
        password_prompter=prompter,
    )
    for _ in range(5):
        fetcher.fetch_credentials()
    response = fetcher.fetch_credentials()
    expected_response = {
        "AccessKeyId": "foo",
        "SecretAccessKey": "bar",
        "SessionToken": "baz",
        "Expiration": mock.ANY,
    }
    assert response == expected_response
    assert prompter.call_count == 1

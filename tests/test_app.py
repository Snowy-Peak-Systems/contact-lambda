from typing import Dict, Any

import pytest
import requests as requests
from requests import Response

from app import EmailMessage, get_response, LambdaRunner
from lib import MockSESClient, MockSecretsClient, MockResponse, event, mock_post_request


def test_get_response_sets_status_code():
    assert get_response(200, "")["statusCode"] == 200


def test_get_response_sets_message():
    assert get_response(0, "MyMessage")["body"] == '{"message": "MyMessage"}'


def test_email_message_throws_error_on_invalid_name():
    with pytest.raises(ValueError):
        EmailMessage("", "test@example.com", "message")

    with pytest.raises(ValueError):
        EmailMessage(" ", "test@example.com", "message")

    with pytest.raises(ValueError):
        EmailMessage(None, "test@example.com", "message")


def test_email_message_throws_error_on_invalid_email():
    with pytest.raises(ValueError):
        EmailMessage("name", "test@example", "message")

    with pytest.raises(ValueError):
        EmailMessage("name", " ", "message")

    with pytest.raises(ValueError):
        EmailMessage("name", None, "message")


def test_email_message_throws_error_on_invalid_message():
    with pytest.raises(ValueError):
        EmailMessage("name", "test@example.com", "")

    with pytest.raises(ValueError):
        EmailMessage("name", "test@example.com", " ")

    with pytest.raises(ValueError):
        EmailMessage("name", "test@example.com", None)


def test_email_message_generates_correct_reply_to():
    assert (
        EmailMessage("name", "test@example.com", "message").reply_to
        == "name <test@example.com>"
    )


def test_email_message_trims_whitespace():
    message = EmailMessage(" name ", " test@example.com ", " message ")
    assert message.reply_to == "name <test@example.com>"
    assert message.message == "message"


def test_lambda_runner_sends_email(event):
    ses_client = MockSESClient()
    LambdaRunner(secrets_client=MockSecretsClient(), ses_client=ses_client)(event, None)

    assert ses_client.subject == "SPS Contact Form Message"
    assert ses_client.source == "test@example.com"
    assert ses_client.message == "test message"
    assert ses_client.destinations == ["test@example.com"]
    assert ses_client.reply_tos == ["my_name <test-sender@example.com>"]


def test_lambda_runner_gets_secret(event):
    secrets_client = MockSecretsClient()
    LambdaRunner(secrets_client=secrets_client, ses_client=MockSESClient())(event, None)

    assert secrets_client.secret_id == "secret-name"


def test_lambda_runner_verifies_captcha(monkeypatch, event):
    get_url = None
    get_params = None

    def mock_post(
        url: str, params: Dict[str, Any] = None, timeout: int = 0
    ) -> Response:
        nonlocal get_url, get_params
        get_url = url
        get_params = params

        return MockResponse()

    monkeypatch.setattr(requests, "post", mock_post)

    LambdaRunner(secrets_client=MockSecretsClient(), ses_client=MockSESClient())(
        event, None
    )

    assert get_url == "https://www.google.com/recaptcha/api/siteverify"
    assert get_params == {"secret": "secret-key", "response": "my_token"}


def test_lambda_runner_does_not_verify_captcha_when_skip_captcha_env_var_set(
    monkeypatch, event
):
    monkeypatch.setenv("SKIP_CAPTCHA", "True")

    get_url = None
    get_params = None

    def mock_post(
        url: str, params: Dict[str, Any] = None, timeout: int = 0
    ) -> Response:
        nonlocal get_url, get_params
        get_url = url
        get_params = params

        return MockResponse()

    monkeypatch.setattr(requests, "post", mock_post)

    LambdaRunner(secrets_client=MockSecretsClient(), ses_client=MockSESClient())(
        event, None
    )

    assert get_url is None
    assert get_params is None


def test_lambda_runner_returns_200_on_success(event):
    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 200
    assert response["body"] == '{"message": "Success"}'


def test_lambda_runner_returns_400_on_bad_body_format(event):
    event["body"] = "{["

    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 400
    assert response["body"] == '{"message": "Invalid Format"}'


def test_lambda_runner_returns_400_on_missing_data(event):
    event["body"] = "{}"

    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 400
    assert response["body"] == '{"message": "Missing Required Data: \'token\'"}'


def test_lambda_runner_returns_400_on_bad_name(event):
    event["body"] = (
        '{"token": "my_token", "name": "", '
        '"email": "test-sender@example.com", "message": "test message"}'
    )

    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 400
    assert response["body"] == '{"message": "Invalid Name"}'


def test_lambda_runner_returns_400_on_bad_email(event):
    event["body"] = (
        '{"token": "my_token", "name": "my_name", '
        '"email": "email", "message": "test message"}'
    )

    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 400
    assert response["body"] == '{"message": "Invalid Email"}'


def test_lambda_runner_returns_400_on_bad_message(event):
    event["body"] = (
        '{"token": "my_token", "name": "my_name", '
        '"email": "test-sender@example.com", "message": ""}'
    )

    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 400
    assert response["body"] == '{"message": "Invalid Message"}'


def test_lambda_runner_returns_401_on_bad_token(event):
    event["body"] = (
        '{"token": "bad_token", "name": "my_name", '
        '"email": "test-sender@example.com", "message": "test message"}'
    )

    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 401
    assert response["body"] == '{"message": "Invalid CAPTCHA Token"}'


def test_lambda_runner_returns_401_on_captcha_verify_error(monkeypatch, event):
    def mock_post(
        url: str, params: Dict[str, Any] = None, timeout: int = 0
    ) -> Response:
        return MockResponse(500)

    monkeypatch.setattr(requests, "post", mock_post)

    response = LambdaRunner(
        secrets_client=MockSecretsClient(), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 401
    assert response["body"] == '{"message": "Invalid CAPTCHA Token"}'


def test_lambda_runner_returns_500_on_server_error(event):
    response = LambdaRunner(
        secrets_client=MockSecretsClient(True), ses_client=MockSESClient()
    )(event, None)

    assert response["statusCode"] == 500
    assert response["body"] == '{"message": "Internal Server Error"}'

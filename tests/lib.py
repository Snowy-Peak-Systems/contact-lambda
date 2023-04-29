from typing import Dict, Sequence, Any

import pytest
import requests
from botocore.exceptions import ClientError
from mypy_boto3_secretsmanager.client import SecretsManagerClient
from mypy_boto3_secretsmanager.type_defs import GetSecretValueResponseTypeDef
from mypy_boto3_ses.client import SESClient
from mypy_boto3_ses.type_defs import (
    DestinationTypeDef,
    MessageTypeDef,
    SendEmailResponseTypeDef,
)
from requests import Response


@pytest.fixture(autouse=True)
def mock_get_request(monkeypatch):
    def mock_get(*args, **kwargs) -> Response:
        return MockResponse(kwargs["params"]["response"] == "my_token")

    # apply the monkeypatch for requests.get to mock_get
    monkeypatch.setattr(requests, "get", mock_get)


@pytest.fixture
def event() -> Dict[str, Any]:
    return {
        "Body": (
            "{'token': 'my_token', 'name': 'my_name', "
            "'email': 'test-sender@example.com', 'message', 'test message'}"
        )
    }


class MockResponse(Response):
    _status_code: int
    json: Dict[Any, Any]

    def __init__(self, status_code: int = 200, success: bool = True):
        super().__init__()
        self._status_code = status_code
        self.json = {"success": success}

    @property
    def status_code(self) -> int:
        return self._status_code

    def json(self) -> Any:
        return self.json


class MockClientError(ClientError):
    def __init__(self):
        ...

    def __str__(self):
        ...


class MockSESClient(SESClient):
    _source: str
    _destinations: Sequence[str]
    _subject: str
    _message: str
    _reply_tos: Sequence[str]
    _force_fail: bool

    def __init__(self, force_fail: bool = False):
        self._force_fail = force_fail

    def send_email(
        self,
        *,
        Source: str,
        Destination: DestinationTypeDef,
        Message: MessageTypeDef,
        ReplyToAddresses: Sequence[str] = ...,
    ) -> SendEmailResponseTypeDef:
        if self._force_fail is True:
            raise MockClientError

        self._source = Source
        self._destinations = Destination["ToAddresses"]
        self._subject = Message["Subject"]["Data"]
        self._message = Message["Body"]["Text"]["Data"]
        self._reply_tos = ReplyToAddresses

        return None

    @property
    def source(self) -> str:
        return self._source

    @property
    def destinations(self) -> Sequence[str]:
        return self._destinations

    @property
    def subject(self) -> str:
        return self._subject

    @property
    def message(self) -> str:
        return self._message

    @property
    def reply_tos(self) -> Sequence[str]:
        return self._reply_tos


class MockSecretsClient(SecretsManagerClient):
    _secret_id: str
    _force_fail: bool

    def __init__(self, force_fail: bool = False):
        self._force_fail = force_fail

    def get_secret_value(self, *, SecretId: str) -> GetSecretValueResponseTypeDef:
        if self._force_fail is True:
            raise MockClientError

        self._secret_id = SecretId

        return {"SecretString": "{'CAPTCHA_SECRET_KEY': 'secret-key'}"}

    @property
    def secret_id(self) -> str:
        return self._secret_id

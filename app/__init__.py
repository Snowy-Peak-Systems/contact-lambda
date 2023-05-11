"""Lambda for contact form requests."""
import json
import os
import re
import logging
from json import JSONDecodeError
from typing import Dict, Any, TypedDict, Literal, Optional

import boto3
import requests
from cachetools import cached, TTLCache
from mypy_boto3_secretsmanager.client import SecretsManagerClient
from mypy_boto3_ses.client import SESClient

LOGGER = logging.getLogger()
LOGGER.setLevel("INFO")

EMAIL_PATTERN = re.compile(
    r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:["
    r"\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])"
    r"*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[("
    r"?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9]"
    r")|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-"
    r"\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)])"
)


class LambdaResponse(TypedDict):
    """Response returned by the lambda."""

    isBase64Encoded: Literal[False]
    headers: Dict[Literal["content-type"], Literal["application/json"]]
    statusCode: int
    body: str


def get_response(status_code: int, message: str) -> LambdaResponse:
    """Get a response dict for the given status code and message."""
    return {
        "isBase64Encoded": False,
        "statusCode": status_code,
        "body": f'{{"message": "{message}"}}',
        "headers": {"content-type": "application/json"},
    }


class EmailMessage:
    """Data required to send an email."""

    _message: str
    _reply_to: str

    def __init__(self, name: str, email: str, message: str):
        if name is None or len(name.strip()) == 0:
            raise ValueError("Invalid Name")

        if (
            email is None
            or len(email.strip()) == 0
            or EMAIL_PATTERN.fullmatch(email.strip().lower()) is None
        ):
            raise ValueError("Invalid Email")

        if message is None or len(message.strip()) == 0 or len(message.strip()) >= 1000:
            raise ValueError("Invalid Message")

        self._reply_to = f"{name.strip()} <{email.strip().lower()}>"
        self._message = message.strip()

    @property
    def reply_to(self) -> str:
        """Get the reply-to string for this message."""
        return self._reply_to

    @property
    def message(self) -> str:
        """Get the message of the email."""
        return self._message


class LambdaRunner:
    """Class that is executed when the lambda is triggered."""

    _email_identity: str
    _secret_name: str
    _secrets_client: SecretsManagerClient
    _ses_client: SESClient
    _skip_captcha: bool

    def __init__(
        self,
        *,
        secret_name: Optional[str] = None,
        email_identity: Optional[str] = None,
        skip_captcha: Optional[bool] = None,
        secrets_client: Optional[SecretsManagerClient] = None,
        ses_client: Optional[SESClient] = None,
    ):
        self._secret_name = secret_name
        self._email_identity = email_identity
        self._skip_captcha = skip_captcha

        self._secrets_client = (
            secrets_client
            if secrets_client is not None
            else boto3.client("secretsmanager", os.environ["AWS_REGION"])
        )

        self._ses_client = (
            ses_client
            if ses_client is not None
            else boto3.client("ses", os.environ["AWS_REGION"])
        )

    @property
    def secret_name(self) -> str:
        """Returns the name of the secret that stores application data."""
        return (
            self._secret_name
            if self._secret_name is not None
            else os.environ["SECRET_NAME"]
        )

    @property
    def skip_captcha(self) -> bool:
        """Returns whether to skip captcha or not."""
        return (
            self._skip_captcha
            if self._skip_captcha is not None
            else os.environ.get("SKIP_CAPTCHA", "false").lower() == "true"
        )

    @property
    def email_identity(self) -> str:
        """Returns the email identity for sending email."""
        return (
            self._email_identity
            if self._email_identity is not None
            else os.environ["SES_IDENTITY"]
        )

    @cached(TTLCache(maxsize=2048, ttl=300))
    def _get_captcha_secret(self) -> str:
        return json.loads(
            self._secrets_client.get_secret_value(
                SecretId=self.secret_name,
            )["SecretString"]
        )["CAPTCHA_SECRET_KEY"]

    def _verify_captcha(self, token: str) -> bool:
        LOGGER.info("Verifying CAPTCHA")
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            params={"secret": self._get_captcha_secret(), "response": token},
            timeout=10,
        )
        return response.status_code == 200 and response.json()["success"] is True

    def _send_email(self, message: EmailMessage) -> None:
        LOGGER.info("Sending email from %s", message.reply_to)
        self._ses_client.send_email(
            Source=self.email_identity,
            Destination={"ToAddresses": [self.email_identity]},
            Message={
                "Subject": {"Data": "SPS Contact Form Message"},
                "Body": {"Text": {"Data": message.message}},
            },
            ReplyToAddresses=[message.reply_to],
        )

    def __call__(self, event: Dict[str, Any], _context: Any) -> LambdaResponse:
        try:
            LOGGER.info("Processing new contact request")
            value = json.loads(event.get("body", "{}"))

            if not self.skip_captcha and not self._verify_captcha(value["token"]):
                LOGGER.warning("Invalid CAPTCHA Token")
                return get_response(401, "Invalid CAPTCHA Token")

            self._send_email(
                EmailMessage(value["name"], value["email"], value["message"])
            )

            LOGGER.info("Success")
            return get_response(200, "Success")
        except JSONDecodeError as error:
            LOGGER.error(error)
            return get_response(400, "Invalid Format")
        except KeyError as error:
            LOGGER.error("KeyError: %s", error)
            return get_response(400, f"Missing Required Data: {error}")
        except ValueError as error:
            LOGGER.error(error)
            return get_response(400, str(error))
        except Exception as error:  # pylint: disable=broad-exception-caught
            LOGGER.error(error)
            return get_response(500, "Internal Server Error")


lambda_function = LambdaRunner()

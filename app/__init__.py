"""Lambda for contact form requests."""

import os
import re
from typing import Dict, Any, TypedDict, Literal, Optional

import boto3
from cachetools import cached, TTLCache
from mypy_boto3_secretsmanager.client import SecretsManagerClient
from mypy_boto3_ses.client import SESClient

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
        "body": f"{{'message': '{message}'}}",
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

        if message is None or len(message.strip()) == 0:
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

    _secret_name: str
    _email_identity: str
    _secrets_client: SecretsManagerClient
    _ses_client: SESClient

    def __init__(
        self,
        secret_name: Optional[str] = None,
        email_identity: Optional[str] = None,
        secrets_client: Optional[SecretsManagerClient] = None,
        ses_client: Optional[SESClient] = None,
    ):
        self._email_identity = (
            email_identity if email_identity is not None else os.environ["SES_IDENTITY"]
        )

        self._secret_name = (
            secret_name if secret_name is not None else os.environ["SECRET_NAME"]
        )

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

    @cached(TTLCache(maxsize=2048, ttl=300))
    def _get_captcha_secret(self) -> str:
        # Use secrets client to get_secrets_value() of _secret_name
        # (See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager/client/get_secret_value.html)
        # Get the value of the "SecretString" key from the dict from secrets client
        # Convert the string to dict using json.loads() on the secrets string
        # return the value of the "CAPTCHA_SECRET_KEY" key from secrets dict
        ...

    def _verify_captcha(self, token: str) -> bool:
        # Get string from _get_captcha_secret()
        # Set params to dict of "secret": <captcha secret>, "response": <token>
        # Make POST request to https://www.google.com/recaptcha/api/siteverify with params
        # (See https://stackoverflow.com/a/15900453/4957612)
        # Return response status_code == 200 && value for key "success" in json() of response == true
        ...

    def _send_email(self, message: EmailMessage) -> None:
        self._ses_client.send_email(
            Source=self._email_identity,
            Destination={"ToAddresses": [self._email_identity]},
            Message={
                "Subject": {"Data": "SPS Contact Form Message"},
                "Body": {"Text": {"Data": message.message}},
            },
            ReplyToAddresses=[message.reply_to],
        )

    def __call__(self, event: Dict[str, Any], context: Any) -> LambdaResponse:
        # try
        # Get value of "Body" key from payload
        # Convert string to dict using json.loads()
        # Get value of "token" key from json dict

        # If _verify_captcha() is not true, return 401 "Invalid CAPTCHA Token" Response

        # Get values of "name", "email", and "message" from json dict
        # Create EmailMessage using name, email, and message
        # _send_email() with the EmailMessage

        # Return 200 "Success" Response
        # On JSONDecodeError
        # return 400 "Invalid Format" Response
        # On KeyError
        # return 400 "Missing Required Data" Response
        # On ValueError
        # get string of error
        # return 400 "<ERROR STRING>" Response
        # On Exception
        # return 500 "Internal Server Error" Response
        ...


lambda_function = LambdaRunner()

import hashlib
import hmac
import json
from typing import List

import requests

from .models import Webhook


class WebhookDispatcher:

    def __init__(self):

        self._hooks: List[Webhook] = []

    def register(
        self,
        name: str,
        url: str,
        secret: str = "",
    ):

        self._hooks.append(
            Webhook(
                name=name,
                url=url,
                secret=secret,
            )
        )

    def emit(
        self,
        event: str,
        payload: dict,
    ):

        body = json.dumps(payload).encode()

        for hook in self._hooks:

            headers = {
                "Content-Type": "application/json",
                "X-PV-Event": event,
            }

            if hook.secret:

                signature = hmac.new(
                    hook.secret.encode(),
                    body,
                    hashlib.sha256,
                ).hexdigest()

                headers["X-PV-Signature"] = signature

            try:

                requests.post(
                    hook.url,
                    data=body,
                    headers=headers,
                    timeout=5,
                )

            except Exception:

                pass

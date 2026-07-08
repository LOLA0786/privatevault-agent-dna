from dataclasses import dataclass

@dataclass(slots=True)
class Webhook:

    name: str

    url: str

    secret: str = ""

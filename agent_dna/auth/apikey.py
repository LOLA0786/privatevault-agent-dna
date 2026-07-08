from .config import API_KEYS

def verify_api_key(key: str):

    if key not in API_KEYS:
        return None

    return API_KEYS[key]

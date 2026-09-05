import secrets


def create_session_token():
    return secrets.token_urlsafe(32)

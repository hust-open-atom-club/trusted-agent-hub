from src.auth import hash_password, verify_password


def test_passwords_use_argon2id_and_verify():
    password_hash = hash_password("Test123456")
    assert password_hash.startswith("$argon2")
    assert verify_password("Test123456", password_hash)
    assert not verify_password("WrongPass123", password_hash)

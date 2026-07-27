import bcrypt


def hash_password(plain_password: str) -> str:
    """Превращает обычный пароль в хэш для хранения в базе."""
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def check_password(plain_password: str, password_hash: str) -> bool:
    """Проверяет, соответствует ли введённый пароль сохранённому хэшу."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))

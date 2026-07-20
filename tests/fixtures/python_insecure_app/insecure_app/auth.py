"""Non-vulnerable business logic that should rank below the network sink."""


def is_admin(user: dict) -> bool:
    return user.get("role") == "admin"

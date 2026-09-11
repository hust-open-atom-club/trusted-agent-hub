"""SQL statements shared by the API and deployment services."""

from importlib.resources import files


CLEANUP_REFRESH_TOKENS_SQL = (
    files("src.sql")
    .joinpath("cleanup_refresh_tokens.sql")
    .read_text(encoding="utf-8")
)

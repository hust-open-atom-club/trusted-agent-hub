DELETE FROM refresh_tokens
WHERE used_at IS NOT NULL
   OR expires_at <= CURRENT_TIMESTAMP;

-- name: UserFromRefreshToken :one
SELECT
    user_id
from refresh_tokens
WHERE token = $1;
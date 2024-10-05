-- name: RevokeRefreshToken :exec
update refresh_tokens
    set revoked_at = now(),
        updated_at = now()
where token = $1;
-- name: UpgradeUser :exec
update users
    set is_chirpy_red = True,
        updated_at = now()
where id = $1;
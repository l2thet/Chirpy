-- name: UpdateUser :exec
update users
    set email = $1,
        hashed_password = $2,
        updated_at = now()
where id = $3;
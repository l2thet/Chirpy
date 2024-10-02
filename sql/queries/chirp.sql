-- name: Chirp :one
SELECT
    *
FROM chirps
WHERE id = $1;
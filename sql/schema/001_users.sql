-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY, 
    created_at TIMESTAMP NOT NULL DEFAULT now(), 
    updated_at TIMESTAMP NOT NULL DEFAULT now(), 
    email TEXT NOT NULL UNIQUE);

-- +goose Down
DROP TABLE users;
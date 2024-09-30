-- +goose Up
CREATE TABLE chirps (
    id UUID NOT NULL, 
    created_at TIMESTAMP NOT NULL DEFAULT now(), 
    updated_at TIMESTAMP NOT NULL DEFAULT now(), 
    body TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL);

-- +goose Down
DROP TABLE chirps;
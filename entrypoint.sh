#!/bin/sh

# Run Goose migrations
/usr/local/bin/goose -dir /app/sql/schema postgres "$DB_URL" up

# Start the application
exec "$@"
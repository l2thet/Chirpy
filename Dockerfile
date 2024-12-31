# Stage 1: Build Goose
FROM golang:1.19-alpine AS builder

# Install Goose
RUN go install github.com/pressly/goose/v3/cmd/goose@v3.7.0

# Stage 2: Build the final image
FROM golang:1.19-alpine

# Install curl and PostgreSQL client
RUN apk add --no-cache curl postgresql-client

# Create a working directory
WORKDIR /app

# Copy Goose binary from the builder stage
COPY --from=builder /go/bin/goose /usr/local/bin/goose

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o Chirpy .

# Copy .env file
COPY .env /app/.env

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose port 8080 to the outside world
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["./Chirpy"]
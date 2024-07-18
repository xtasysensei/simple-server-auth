# Stage 1: Build the Go application
FROM golang:alpine AS builder

# Install dependencies
RUN apk update && apk add --no-cache git bash build-base

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files first for better caching of dependencies
COPY go.mod go.sum ./

# Fetch dependencies
RUN go mod download

# Copy the rest of the application files
COPY . .

# Build the Go application
RUN go build -o /app/app

# Stage 2: Create a minimal runtime image
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /root/

# Copy the built Go binary from the builder stage
COPY --from=builder /app/app .

# Expose port 8080 to the outside world
EXPOSE 8000

# Run the executable
CMD ["./app"]

# Setup hot-reload for the development stage
# RUN go get github.com/githubnemo/CompileDaemon && \
#     go get -v golang.org/x/tools/gopls

# # Set the entrypoint to use CompileDaemon for hot-reload
# ENTRYPOINT ["CompileDaemon", "--build=go build -a -installsuffix cgo -o main .", "--command=./main"]
# # Build the Go app
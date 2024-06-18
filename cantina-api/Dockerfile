# Start with a base image that includes Go
FROM golang:1.20-alpine

# Install necessary packages
RUN apk update && apk add --no-cache gcc musl-dev

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Build the Go app
RUN CGO_ENABLED=1 GOOS=linux go build -o main .

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Run the executable
CMD ["./main"]

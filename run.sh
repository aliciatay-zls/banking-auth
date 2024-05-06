#!/bin/bash
# Set environment variables for the session
export SERVER_ADDRESS="localhost"
export SERVER_PORT="8181"
export MAILHOG_SERVER_ADDRESS="localhost"
export MAILHOG_SERVER_PORT="1025"
export FRONTEND_SERVER_ADDRESS="localhost"
export FRONTEND_SERVER_PORT="3000"
export DB_USER="root"
export DB_PASSWORD="codecamp"
export DB_ADDRESS="localhost"
export DB_PORT="3306"
export DB_NAME="banking"
export ENCRYPTION_FILEPATH="keys/private_key.txt"

# Run app
go run main.go
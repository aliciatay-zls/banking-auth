#!/bin/bash
# Set environment variables for the session
export APP_ENV="development"

export SERVER_ADDRESS="localhost"
export SERVER_PORT="8181"
export SERVER_DOMAIN="localhost:8181"
export MAIL_SERVER_ADDRESS="localhost"
export MAIL_SERVER_PORT="1025"
export MAIL_SERVER_USER="banking@mail.com"
export MAIL_SERVER_PASSWORD="password"
export MAIL_SENDER="banking@mail.com"
export FRONTEND_SERVER_ADDRESS="localhost"
export FRONTEND_SERVER_PORT="3000"
export FRONTEND_SERVER_DOMAIN="localhost:3000"
export DB_USER="root"
export DB_PASSWORD="codecamp"
export DB_HOST="localhost"
export DB_PORT="3306"
export DB_NAME="banking"
export ENCRYPTION_FILEPATH="keys/private_key.txt"

# Run app
go run main.go
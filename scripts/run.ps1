# Set environment variables for the session
$env:APP_ENV = "development"

$env:SERVER_ADDRESS = "localhost"
$env:SERVER_PORT = "8181"
$env:SERVER_DOMAIN = "localhost:8181"
$env:MAIL_SERVER_ADDRESS = "localhost"
$env:MAIL_SERVER_PORT = "1025"
$env:MAIL_SERVER_USER = "banking@mail.com"
$env:MAIL_SERVER_PASSWORD = "password"
$env:MAIL_SENDER = "banking@mail.com"
$env:FRONTEND_SERVER_ADDRESS = "localhost"
$env:FRONTEND_SERVER_PORT = "3000"
$env:FRONTEND_SERVER_DOMAIN = "localhost:3000"
$env:DB_USER = "root"
$env:DB_PASSWORD = "codecamp"
$env:DB_HOST = "localhost"
$env:DB_PORT = "3306"
$env:DB_NAME = "banking"
$env:ENCRYPTION_FILEPATH = "keys/private_key.txt"

# Run app
go run main.go
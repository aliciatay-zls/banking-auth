# Set environment variables for the session
$env:SERVER_ADDRESS = "localhost"
$env:SERVER_PORT = "8181"
$env:MAILHOG_SERVER_ADDRESS = "localhost"
$env:MAILHOG_SERVER_PORT = "1025"
$env:FRONTEND_SERVER_ADDRESS = "localhost"
$env:FRONTEND_SERVER_PORT = "3000"
$env:DB_USER = "root"
$env:DB_PASSWORD = "codecamp"
$env:DB_ADDRESS = "localhost"
$env:DB_PORT = "3306"
$env:DB_NAME = "banking"
$env:ENCRYPTION_FILEPATH = "keys/private_key.txt"

# Run app
go run main.go
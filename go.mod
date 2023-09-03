module banking-auth

go 1.20

require (
	github.com/aliciatay-zls/banking v0.0.0-00010101000000-000000000000
	github.com/go-sql-driver/mysql v1.7.1
	github.com/gorilla/mux v1.8.0
	github.com/jmoiron/sqlx v1.3.5
)

require (
	github.com/golang-jwt/jwt/v5 v5.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.25.0 // indirect
)

replace github.com/aliciatay-zls/banking => ../banking

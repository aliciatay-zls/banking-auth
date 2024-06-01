package app

import (
	"fmt"
	"github.com/aliciatay-zls/banking-auth/domain"
	"github.com/aliciatay-zls/banking-auth/service"
	"github.com/aliciatay-zls/banking-lib/logger"
	_ "github.com/go-sql-driver/mysql" //important
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"net/http"
	"os"
	"time"
)

func checkEnvVars() {
	val, ok := os.LookupEnv("APP_ENV")
	if !ok {
		logger.Fatal("Environment variable APP_ENV not defined")
	}

	envVars := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"SERVER_DOMAIN",
		"MAIL_SERVER_ADDRESS",
		"MAIL_SERVER_PORT",
		"MAIL_SERVER_USER",
		"MAIL_SERVER_PASSWORD",
		"MAIL_SENDER",
		"FRONTEND_SERVER_ADDRESS",
		"FRONTEND_SERVER_DOMAIN",
		"DB_USER",
		"DB_PASSWORD",
		"DB_HOST",
		"DB_PORT",
		"DB_NAME",
		"ENCRYPTION_FILEPATH",
	}

	if val == "production" {
		err := godotenv.Load(".env")
		if err != nil {
			logger.Fatal("Error loading .env file (needed in production mode)")
		}
	} else {
		envVars = append(envVars, "FRONTEND_SERVER_PORT")
	}

	for _, key := range envVars {
		if os.Getenv(key) == "" {
			logger.Fatal(fmt.Sprintf("Environment variable %s was not defined", key))
		}
	}
}

func Start() {
	checkEnvVars()

	router := mux.NewRouter()

	dbClient := getDbClient()
	authRepositoryDb := domain.NewAuthRepositoryDb(dbClient)
	registrationRepositoryDb := domain.NewRegistrationRepositoryDb(dbClient)
	emailRepository := domain.NewDefaultEmailRepository()

	tokenRepository := domain.NewDefaultTokenRepository()
	ah := AuthHandler{service.NewDefaultAuthService(
		authRepositoryDb,
		registrationRepositoryDb,
		domain.NewRolePermissions(),
		tokenRepository,
	)}
	rh := RegistrationHandler{service.NewRegistrationService(
		registrationRepositoryDb,
		emailRepository,
		tokenRepository,
	)}

	router.
		HandleFunc("/auth/login", ah.LoginHandler).
		Methods(http.MethodPost, http.MethodOptions).
		Name("Login")
	router.HandleFunc("/auth/logout", ah.LogoutHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/auth/verify", ah.VerifyHandler).Methods(http.MethodGet)
	router.HandleFunc("/auth/refresh", ah.RefreshHandler).Methods(http.MethodPost, http.MethodOptions)
	router.HandleFunc("/auth/continue", ah.ContinueHandler).Methods(http.MethodPost, http.MethodOptions)

	router.
		HandleFunc("/auth/register", rh.RegisterHandler).
		Methods(http.MethodPost, http.MethodOptions).
		Name("Register")
	router.HandleFunc("/auth/register/check", rh.CheckRegistrationHandler).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/auth/register/resend", rh.ResendHandler).Methods(http.MethodGet, http.MethodPost, http.MethodOptions)
	router.HandleFunc("/auth/register/finish", rh.FinishRegistrationHandler).Methods(http.MethodPost, http.MethodOptions)

	rmw := RateLimitingMiddleware{domain.NewDefaultVisitorRepository()}
	go rmw.repo.Cleanup()
	router.Use(rmw.RateLimitingHandler)

	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")

	if os.Getenv("APP_ENV") == "production" { //Render provides TLS certs, HTTP requests will be redirected to HTTPS
		err := http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router)
		if err != nil {
			logger.Fatal(err.Error())
		}
	} else {
		certFile := "certificates/localhost.pem"
		keyFile := "certificates/localhost-key.pem"
		err := http.ListenAndServeTLS(fmt.Sprintf("%s:%s", address, port), certFile, keyFile, router)
		if err != nil {
			logger.Fatal(err.Error())
		}
	}
}

func getDbClient() *sqlx.DB {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dataSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err := sqlx.Open("mysql", dataSource)
	if err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	return db
}
